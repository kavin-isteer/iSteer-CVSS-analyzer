package com.isteer.cvssapplication.datastore.service.impl;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Function;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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



@Service
public class ComputerServiceImpl implements ComputerService {
	private static final Logger logger = LoggerFactory.getLogger(ComputerServiceImpl.class);

	@Autowired
	private ComputerDao computerRepository;

	@Autowired
	private ApplicationService applicationService;

	@Autowired
	private ComputerApplicationDao computerApplicationRepository;

	@Autowired
	private VulnerabilityDao vulnerabilityRepository;

//	@Autowired
//	private Validator validator;

	@Transactional
	@Override
	public int createComputer(ComputerPayloadDTO payload) {
		logger.debug("Processing computer with deviceId: {}", payload.getDeviceId());
//		Set<ConstraintViolation<ComputerPayloadDTO>> violations = validator.validate(payload);
//		if (!violations.isEmpty()) {
//			logger.warn("Validation errors: {}",
//					violations.stream().map(ConstraintViolation::getMessage).collect(Collectors.joining("; ")));
//			return -1; // Invalid payload
//		}
		
		// Validate application names in installedSoftware
				for (SoftwareDTO software : payload.getInstalledSoftware()) {
					if (software.getName() == null || software.getName().trim().isEmpty()) {
						logger.warn("Application name is null or blank in payload for deviceId: {}", payload.getDeviceId());
						return -2; // Application name should not be blank
					}
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

		Set<String> currentAppKeys = currentMappings.stream().map(mapping -> key(mapping.getApplicationName(),
				mapping.getApplicationVendorName(), mapping.getApplicationVersion())).collect(Collectors.toSet());

		Set<String> deletedAppKeys = currentMappings
				.stream().filter(ComputerApplicationDTO::isDeleted).map(mapping -> key(mapping.getApplicationName(),
						mapping.getApplicationVendorName(), mapping.getApplicationVersion()))
				.collect(Collectors.toSet());

		// Get all known applications
		List<Application> allApplications = applicationService.getAllApplications();
		Map<String, Application> existingAppMap = allApplications.stream().collect(Collectors
				.toMap(app -> key(app.getName(), app.getVendorName(), app.getVersion()), Function.identity()));

		// Keys for newly reported apps
		Set<String> newAppKeys = payload.getInstalledSoftware().stream()
				.map(software -> key(software.getName(), software.getVendorName(), software.getVersion()))
				.collect(Collectors.toSet());

		// Reactivatable keys
		Set<String> newAppKeysInDeleted = newAppKeys.stream().filter(deletedAppKeys::contains)
				.collect(Collectors.toSet());

		// Determine new keys (not currently mapped and not just deleted)
		Set<String> onlyInNew = new HashSet<>(newAppKeys);
		onlyInNew.removeAll(currentAppKeys);
		onlyInNew.removeAll(newAppKeysInDeleted);

		// Determine which apps are missing globally
		Set<String> missingAppKeys = new HashSet<>(onlyInNew);
		missingAppKeys.removeAll(existingAppMap.keySet());

		List<SoftwareDTO> appsToCreate = payload.getInstalledSoftware().stream()
				.filter(software -> missingAppKeys
						.contains(key(software.getName(), software.getVendorName(), software.getVersion())))
				.collect(Collectors.toList());

		if (!appsToCreate.isEmpty()) {
			int createdStatus = applicationService.createOrUpdateApplication(appsToCreate, computer.getUuid());
			logger.debug("Created {} new applications", appsToCreate.size());
			if (createdStatus != 1) {
				logger.error("Failed to create new applications for computer UUID: {}", computer.getUuid());
				return -1; // Internal error
			}
			isApplicationsUpdated = true;
		}

		// Refresh app list after new app insert
		allApplications = applicationService.getAllApplications();
		existingAppMap = allApplications.stream().collect(Collectors
				.toMap(app -> key(app.getName(), app.getVendorName(), app.getVersion()), Function.identity()));

		Map<String, SoftwareDTO> softwareDTOMap = payload.getInstalledSoftware().stream()
                .collect(Collectors.toMap(
                        software -> key(software.getName(), software.getVendorName(), software.getVersion()),
                        Function.identity()
                ));
		
		// Insert new mappings using your save() method
		for (String appKey : onlyInNew) {
			// Extra safety: skip if already mapped or reactivatable
			if (currentAppKeys.contains(appKey) || newAppKeysInDeleted.contains(appKey)) {
				continue;
			}

			Application app = existingAppMap.get(appKey);
			SoftwareDTO softwareDTO = softwareDTOMap.get(appKey);
			if (app != null) {
				ComputerApplication mapping = new ComputerApplication();
				mapping.setUuid(UUID.randomUUID().toString());
				mapping.setComputerUuid(computer.getUuid());
				mapping.setApplicationUuid(app.getUuid());
				mapping.setInstalledDate(softwareDTO.getInstalledDate()); // Or set from SoftwareDTO if available
				mapping.setDeleted(false);
				mapping.setCreatedAt(LocalDateTime.now());

				try {
					int saveStatus = computerApplicationRepository.save(mapping);
					if (saveStatus != 1) {
						logger.error("Failed to save mapping: Computer UUID [{}], Application UUID [{}]",
								computer.getUuid(), app.getUuid());
					} else {
						isApplicationsUpdated = true;
						logger.debug("Saved mapping: Computer UUID [{}], Application UUID [{}]", computer.getUuid(),
								app.getUuid());
					}
				} catch (DuplicateKeyException e) {
					logger.warn("Duplicate mapping ignored: Computer UUID [{}], Application UUID [{}]",
							computer.getUuid(), app.getUuid());
				}
			} else {
				logger.warn("Application not found for app key: {}", appKey);
			}
		}

		//  Reactivate previously deleted mappings now found in the payload
		List<ComputerApplicationDTO> reactivatedMappings = currentMappings.stream()
				.filter(mapping -> newAppKeysInDeleted.contains(key(mapping.getApplicationName(),
						mapping.getApplicationVendorName(), mapping.getApplicationVersion())))
				.collect(Collectors.toList());

		for (ComputerApplicationDTO mapping : reactivatedMappings) {
			int status = computerApplicationRepository.reactivateByComputerAndApplicationUuid(mapping.getUuid(),
					mapping.getInstalledDate());
			if (status != 1) {
				logger.error("Failed to reactivate mapping for application UUID: {}", mapping.getApplicationUuid());
				return -5;
			}
			logger.debug("Reactivated mapping for application UUID: {}", mapping.getApplicationUuid());
			isApplicationsUpdated = true;
		}

		// 🧹 Soft-delete applications no longer present on this computer
		Set<String> onlyInCurrent = new HashSet<>(currentAppKeys);
		onlyInCurrent.removeAll(newAppKeys);

		List<ComputerApplicationDTO> outdatedMappings = currentMappings.stream()
				.filter(mapping -> onlyInCurrent.contains(key(mapping.getApplicationName(),
						mapping.getApplicationVendorName(), mapping.getApplicationVersion())))
				.collect(Collectors.toList());

		for (ComputerApplicationDTO mapping : outdatedMappings) {
			int deleteStatus = computerApplicationRepository.softDeleteByComputerAndApplicationUuid(mapping.getUuid());
			if (deleteStatus != 1) {
				logger.error("Failed to soft delete mapping for application UUID: {}", mapping.getApplicationUuid());
			} else {
				logger.debug("Soft deleted mapping for application UUID: {}", mapping.getApplicationUuid());
				isApplicationsUpdated = true;
			}
		}


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
		List<Application> applications = applicationService.getApplicationsByComputerUuid(uuid, null);

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