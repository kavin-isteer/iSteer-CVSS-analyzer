package com.isteer.cvssapplication.datastore.service.impl;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.isteer.cvssapplication.datastore.dao.ApplicationDao;
import com.isteer.cvssapplication.datastore.dao.ComputerApplicationDao;
import com.isteer.cvssapplication.datastore.dao.ComputerDao;
import com.isteer.cvssapplication.datastore.dao.VulnerabilityDao;
import com.isteer.cvssapplication.datastore.dto.ComputerApplicationDTO;
import com.isteer.cvssapplication.datastore.dto.ComputerDetailsResponseDTO;
import com.isteer.cvssapplication.datastore.dto.ComputerPayloadDTO;
import com.isteer.cvssapplication.datastore.dto.SoftwareDTO;
import com.isteer.cvssapplication.datastore.entity.Application;
import com.isteer.cvssapplication.datastore.entity.Computer;
import com.isteer.cvssapplication.datastore.entity.ComputerApplication;
import com.isteer.cvssapplication.datastore.enums.CVSSEnum;
import com.isteer.cvssapplication.datastore.exception.BussinessException;
import com.isteer.cvssapplication.datastore.service.ApplicationService;
import com.isteer.cvssapplication.datastore.service.ComputerService;
import com.isteer.cvssapplication.datastore.util.UUIDUtil;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;

@Service
public class ComputerServiceImpl implements ComputerService {
	private static final Logger logger = LoggerFactory.getLogger(ComputerServiceImpl.class);

	@Autowired
	private ComputerDao computerRepository;

	@Autowired
	private ApplicationDao applicationRepository;

	@Autowired
	private ApplicationService applicationService;

	@Autowired
	private ComputerApplicationDao computerApplicationRepository;

	@Autowired
	private VulnerabilityDao vulnerabilityRepository;

	@Autowired
	private Validator validator;

	@Transactional
	@Override
	public int createComputer(ComputerPayloadDTO payload) {
		logger.debug("Processing computer with deviceId: {}", payload.getDeviceId());
		Set<ConstraintViolation<ComputerPayloadDTO>> violations = validator.validate(payload);
		if (!violations.isEmpty()) {
			logger.warn("Validation errors: {}",
					violations.stream().map(ConstraintViolation::getMessage).collect(Collectors.joining("; ")));
			return -1; // Invalid payload
		}

		Optional<Computer> existingComputer = computerRepository.findByDeviceIdAndIsDeletedFalse(payload.getDeviceId());
		boolean isComputerUpdated = false;
		boolean isApplicationsUpdated = false;
		Computer computer;
		boolean isUpdate = existingComputer.isPresent();

		if (isUpdate) {
			computer = existingComputer.get();
			logger.info("Checking for updates to computer with UUID: {}", computer.getUuid());
			if (isComputerUnchanged(computer, payload)) {
				logger.debug("No changes to computer details for UUID: {}", computer.getUuid());
			} else {
				updateComputerDetails(computer, payload);
				if (computerRepository.update(computer) != 1) {
					logger.error("Failed to update computer with UUID: {}", computer.getUuid());
					return -1; // Internal error
				}
				isComputerUpdated = true;
				logger.info("Updated computer with UUID: {}", computer.getUuid());
			}
			// Soft-delete outdated mappings
//	            List<ComputerApplicationDTO> currentMappings = computerApplicationRepository.findByComputerUuid(computer.getUuid());
//	            Set<String> newAppKeys = payload.getInstalledSoftware().stream()
//	                    .map(s -> s.getName() + ":" + (s.getVendorName() == null ? "" : s.getVendorName()) + ":" + (s.getVersion() == null ? "" : s.getVersion()))
//	                    .collect(Collectors.toSet());
//	            for (ComputerApplication mapping : currentMappings) {
//	                Application app = applicationRepository.findByUuidAndIsDeletedFalse(mapping.getApplicationUuid()).orElse(null);
//	                if (app != null) {
//	                    String appKey = app.getName() + ":" + (app.getVendorName() == null ? "" : app.getVendorName()) + ":" + (app.getVersion() == null ? "" : app.getVersion());
//	                    if (!newAppKeys.contains(appKey)) {
//	                        computerApplicationRepository.softDeleteComputerApplicationUuid(mapping);
//	                        logger.debug("Soft deleted mapping for application UUID: {}", app.getUuid());
//	                    }
//	                }
//	            }
		} else {
			computer = new Computer();
			computer.setUuid(UUIDUtil.generateUUID());
			computer.setDeviceId(payload.getDeviceId());
			computer.setMachineName(payload.getMachineName());
			computer.setIpAddress(payload.getIpAddress());
			computer.setOsVersion(payload.getOsVersion());
			computer.setAntivirusStatus(payload.getAntivirusStatus());
			computer.setFirewallStatus(payload.getFirewallStatus());
			computer.setLoggedInUser(payload.getLoggedInUser());
			computer.setLastUpdateCheck(payload.getLastUpdateCheck());
			computer.setTimestamp(payload.getTimestamp());
			computer.setActive(true);
			computer.setDeleted(false);
			computer.setCreatedAt(LocalDateTime.now());

			if (computerRepository.save(computer) != 1) {
				logger.error("Failed to save new computer with UUID: {}", computer.getUuid());
				return -1; // Internal error
			}
			logger.info("Created new computer with UUID: {}", computer.getUuid());
		}

		List<ComputerApplicationDTO> currentMappings = computerApplicationRepository
				.findByComputerUuid(computer.getUuid());

		Set<String> newAppKeys = payload.getInstalledSoftware().stream()
				.map(software -> key(software.getName(), software.getVendorName(), software.getVersion()))
				.collect(Collectors.toSet());
		Set<String> currentAppKeys = currentMappings.stream().map(software -> key(software.getApplicationName(),
				software.getApplicationVendorName(), software.getApplicationVersion())).collect(Collectors.toSet());
		Set<String> deletedAppKeys = currentMappings.stream().filter(mapping -> mapping.isDeleted()) // or
																										// mapping.getIsDeleted()
																										// depending on
																										// method name
				.map(mapping -> key(mapping.getApplicationName(), mapping.getApplicationVendorName(),
						mapping.getApplicationVersion()))
				.collect(Collectors.toSet());

		Set<String> newAppKeysInDeleted = newAppKeys.stream().filter(deletedAppKeys::contains)
				.collect(Collectors.toSet());

		// Remove new apps that are already soft-deleted
		newAppKeys.removeAll(newAppKeysInDeleted);

		// Find new apps not already mapped
		Set<String> onlyInNew = new HashSet<>(newAppKeys);
		onlyInNew.removeAll(currentAppKeys);

		// Find apps that are mapped but no longer present in the payload
		Set<String> onlyInCurrent = new HashSet<>(currentAppKeys);
		onlyInCurrent.removeAll(newAppKeys);

		List<SoftwareDTO> newSoftware = payload.getInstalledSoftware().stream()
				.filter(software -> onlyInNew
						.contains(key(software.getName(), software.getVendorName(), software.getVersion())))
				.collect(Collectors.toList());
		if (!newSoftware.isEmpty()) {
			int newSoftwareStatus = applicationService.createOrUpdateApplication(newSoftware, computer.getUuid());
			isApplicationsUpdated = true;
		}

		List<ComputerApplicationDTO> outdatedMappings = currentMappings.stream()
				.filter(mapping -> onlyInCurrent.contains(key(mapping.getApplicationName(),
						mapping.getApplicationVendorName(), mapping.getApplicationVersion())))
				.collect(Collectors.toList());

		for (ComputerApplicationDTO mapping : outdatedMappings) {
			int outdatedMappingsStatus = computerApplicationRepository
					.softDeleteByComputerAndApplicationUuid(mapping.getUuid());
			if (outdatedMappingsStatus != 1) {
				logger.error("Failed to soft delete mapping for application UUID: {}", mapping.getApplicationUuid());
			} else {
				logger.debug("Soft deleted mapping for application UUID: {}", mapping.getApplicationUuid());
			}
		}

		List<ComputerApplicationDTO> reactivatedMappings = currentMappings.stream()
				.filter(mappings -> newAppKeysInDeleted.contains(key(mappings.getApplicationName(),
						mappings.getApplicationVendorName(), mappings.getApplicationVersion())))
				.collect(Collectors.toList());
		for (ComputerApplicationDTO mapping : reactivatedMappings) {
			int reactivateMappings = computerApplicationRepository
					.reactivateByComputerAndApplicationUuid(mapping.getUuid(), mapping.getInstalledDate());
			if (reactivateMappings != 1) {
				logger.error("Failed to reactivate mapping for application UUID: {}", mapping.getApplicationUuid());
				return -5; // Internal error
			}
			logger.debug("Reactivated mapping for application UUID: {}", mapping.getApplicationUuid());
		}

//	            if (computerRepository.findByDeviceIdAndIsDeletedFalse(payload.getDeviceId()).isPresent()) {
//	                logger.warn("Device ID {} already exists", payload.getDeviceId());
//	                return -3; // Device ID exists
//	            }
//	            
//
//	        // Process all applications in a batch
//	        int appStatus = applicationService.createOrUpdateApplication(payload.getInstalledSoftware(), computer.getUuid());
//	        isApplicationsUpdated = true;
//	        logger.info("Processed applications for computer UUID: {}", computer.getUuid());
//	        if (appStatus == -1) {
//	            logger.error("Error processing applications for computer UUID: {}", computer.getUuid());
//	            return -4; // Error in application processing
//	        }

		if (!existingComputer.isPresent()) {
			return 1; // New computer created successfully
		} else if (isComputerUpdated && isApplicationsUpdated) {
			return 2; // Computer and applications updated successfully
		} else if (isComputerUpdated) {
			return 3; // Only computer updated successfully
		} else if (isApplicationsUpdated) {
			return 4; // Only applications updated successfully
		} else {
			logger.debug("No changes detected for computer with UUID: {}", computer.getUuid());
			return 0; // No changes made
		}
	}

	private boolean isComputerUnchanged(Computer computer, ComputerPayloadDTO payload) {
		return computer.getMachineName().equals(payload.getMachineName())
				&& computer.getIpAddress().equals(payload.getIpAddress())
				&& computer.getOsVersion().equals(payload.getOsVersion())
				&& (computer.getAntivirusStatus() == null ? payload.getAntivirusStatus() == null
						: computer.getAntivirusStatus().equals(payload.getAntivirusStatus()))
				&& (computer.getFirewallStatus() == null ? payload.getFirewallStatus() == null
						: computer.getFirewallStatus().equals(payload.getFirewallStatus()))
				&& (computer.getLoggedInUser() == null ? payload.getLoggedInUser() == null
						: computer.getLoggedInUser().equals(payload.getLoggedInUser()))
				&& computer.getLastUpdateCheck().equals(payload.getLastUpdateCheck())
				&& computer.getTimestamp().equals(payload.getTimestamp());
	}

	private void updateComputerDetails(Computer computer, ComputerPayloadDTO payload) {
		computer.setMachineName(payload.getMachineName());
		computer.setIpAddress(payload.getIpAddress());
		computer.setOsVersion(payload.getOsVersion());
		computer.setAntivirusStatus(payload.getAntivirusStatus());
		computer.setFirewallStatus(payload.getFirewallStatus());
		computer.setLoggedInUser(payload.getLoggedInUser());
		computer.setLastUpdateCheck(payload.getLastUpdateCheck());
		computer.setTimestamp(payload.getTimestamp());
		computer.setUpdatedAt(LocalDateTime.now());
	}

	@Transactional(readOnly = true)
	@Override
	public Computer getComputerByUuid(String uuid) {
		logger.info("Fetching computer with UUID: {}", uuid);
		return computerRepository.findByUuidAndIsDeletedFalse(uuid).orElseThrow(() -> {
			logger.warn("Computer not found for UUID: {}", uuid);
			return new BussinessException(CVSSEnum.COMPUTER_NOT_FOUND);
		});
	}

	@Transactional(readOnly = true)
	@Override
	public List<Computer> getAllComputers() {
		logger.info("Fetching all computers");
		return computerRepository.findAllComputers();
	}

	@Override
	public ComputerDetailsResponseDTO getComputerDetailsByUuid(String uuid) {
		logger.info("Fetching computer details with UUID: {}", uuid);
		Computer computer = getComputerByUuid(uuid);
		List<Application> applications = applicationService.getApplicationsByComputerUuid(uuid);

		for (Application app : applications) {
			app.setVulnerabilities(vulnerabilityRepository.findByApplicationUuid(app.getUuid()));
		}

		ComputerDetailsResponseDTO response = new ComputerDetailsResponseDTO();
		response.setComputer(computer);
		response.setApplications(applications);

		logger.info("Returning computer details with UUID: {} and {} applications", uuid, applications.size());
		return response;
	}

	private String key(String product, String vendor, String version) {
		return product + ":" + (vendor == null ? "" : vendor) + ":" + (version == null ? "" : version);
	}

}