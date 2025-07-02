package com.isteer.cvssapplication.datastore.service.impl;

import java.time.LocalDateTime;
import java.util.HashSet;
import java.util.LinkedHashMap;
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

	@Transactional
	@Override
	public int createComputer(ComputerPayloadDTO payload) {
		logger.debug("Processing computer with deviceId: {}", payload.getDeviceId());
		Computer computer = new Computer();
		// Added: Check for duplicate applications in installedSoftware
		Map<String, SoftwareDTO> softwareDTOMapForValidation = new LinkedHashMap<>();
		for (SoftwareDTO software : payload.getInstalledSoftware()) {
			if (software.getName() == null || software.getName().trim().isEmpty()) {
				logger.warn("Application name is null or blank in payload for deviceId: {}", payload.getDeviceId());
				return -2; // Application name should not be blank
			}
			String key = key(software.getName(), software.getVendorName(), software.getVersion());
			if (softwareDTOMapForValidation.containsKey(key)) {
				logger.warn("Duplicate application found in payload for deviceId: {}, key: {}", payload.getDeviceId(),
						key);
				return -3; // Duplicate application in payload
			}
			softwareDTOMapForValidation.put(key, software);
		}

		Optional<Computer> existingComputer = computerRepository.findByDeviceIdAndIsDeletedFalse(payload.getDeviceId());
		// Added: Check if computer is active

		boolean isComputerUpdated = false;
		boolean isApplicationsUpdated = false;

		boolean isUpdate = existingComputer.isPresent();

		if (isUpdate) {
			computer = existingComputer.get();
			if (computer.isActive()) {
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
				logger.warn("Cannot update soft deleted or deactivated computer with deviceId: {}",
						payload.getDeviceId());
				return -4; // Computer is soft deleted
			}
		} else {
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
						Function.identity()));

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

		for (ComputerApplicationDTO mapping : currentMappings) {
			if (mapping.isDeleted()) {
				continue; // Skip deleted mappings
			}
			String appKey = key(mapping.getApplicationName(), mapping.getApplicationVendorName(),
					mapping.getApplicationVersion());
			SoftwareDTO softwareDTO = softwareDTOMap.get(appKey);
			if (softwareDTO != null) {
				LocalDateTime newInstalledDate = softwareDTO.getInstalledDate();
				LocalDateTime currentInstalledDate = mapping.getInstalledDate();
				if (newInstalledDate != null && !newInstalledDate.equals(currentInstalledDate)) {
					int updateStatus = computerApplicationRepository.updateInstalledDate(mapping.getUuid(),
							newInstalledDate);
					if (updateStatus != 1) {
						logger.error("Failed to update installed_date for mapping UUID: {}", mapping.getUuid());
					} else {
						isApplicationsUpdated = true;
						logger.debug("Updated installed_date for mapping UUID: {}", mapping.getUuid());
					}
				}
			}
		}

		// Reactivate previously deleted mappings now found in the payload
		List<ComputerApplicationDTO> reactivatedMappings = currentMappings.stream()
				.filter(mapping -> newAppKeysInDeleted.contains(key(mapping.getApplicationName(),
						mapping.getApplicationVendorName(), mapping.getApplicationVersion())))
				.collect(Collectors.toList());

		for (ComputerApplicationDTO mapping : reactivatedMappings) {
			// Modified: Update installed_date during reactivation
			SoftwareDTO softwareDTO = softwareDTOMap.get(key(mapping.getApplicationName(),
					mapping.getApplicationVendorName(), mapping.getApplicationVersion()));
			LocalDateTime newInstalledDate = softwareDTO != null ? softwareDTO.getInstalledDate()
					: mapping.getInstalledDate();
			System.out.println("in service " + newInstalledDate);
			int status = computerApplicationRepository.reactivateByComputerAndApplicationUuid(mapping.getUuid(),
					newInstalledDate);
			if (status != 1) {
				logger.error("Failed to reactivate mapping for application UUID: {}", mapping.getApplicationUuid());
				return -5;
			}
			logger.debug("Reactivated mapping for application UUID: {}", mapping.getApplicationUuid());
			isApplicationsUpdated = true;
		}

		// Soft-delete applications no longer present on this computer
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
				&& (computer.getLastUpdateCheck() == null ? payload.getLastUpdateCheck() == null
						: computer.getLastUpdateCheck().equals(payload.getLastUpdateCheck()))
				&& (computer.getTimestamp() == null ? payload.getTimestamp() == null
						: computer.getTimestamp().equals(payload.getTimestamp()));
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
	public List<Computer> getAllPresentComputers() {
		logger.info("Fetching all computers");
		return computerRepository.findAllPresentComputers();
	}

	@Override
	public ComputerDetailsResponseDTO getComputerDetailsByUuid(String uuid) {

		ComputerDetailsResponseDTO computerDetails = computerRepository.findDetailsByUuid(uuid);
		if (computerDetails.getComputer() == null || computerDetails.getComputer().getUuid() == null) {
			logger.warn("Computer not found for UUID: {}", uuid);
			throw new BussinessException(CVSSEnum.COMPUTER_NOT_FOUND);
		}
		logger.info("Returning computer details for UUID: {}", uuid);
		return computerDetails;
	}

	private String key(String product, String vendor, String version) {
		return product + ":" + (vendor == null ? "" : vendor) + ":" + (version == null ? "" : version);
	}

	@Override
	public int softDeleteComputer(String uuid) {
		logger.info("Soft deleting computer with UUID: {}", uuid);
		Optional<Computer> computerOpt = computerRepository.findByUuid(uuid);
		if (!computerOpt.isPresent()) {
			logger.warn("Computer not found for UUID: {}", uuid);
			return -1; // Not found
		}
		Computer computer = computerOpt.get();
		if (computer.isDeleted()) {
			logger.warn("Computer already soft deleted for UUID: {}", uuid);
			return -2; // Already deleted
		}
		computer.setDeleted(true);
		computer.setActive(false); // Deactivate on soft delete
		computer.setUpdatedAt(LocalDateTime.now());
		int status = computerRepository.updateDeletionStatus(computer);
		if (status != 1) {
			logger.error("Failed to soft delete computer with UUID: {}", uuid);
			return -3; // Internal error
		}
		// Soft delete associated computer_applications mappings using JOINs
		int mappingStatus = computerApplicationRepository.softDeleteByComputerUuid(uuid);
		logger.debug("Soft deleted {} mappings for computer UUID: {}", mappingStatus, uuid);
		return 1; // Success}
	}

	// Added: Revert soft delete computer
	@Transactional
	@Override
	public int revertSoftDeleteComputer(String uuid) {
		Optional<Computer> computerOpt = computerRepository.findByUuid(uuid);
		if (!computerOpt.isPresent()) {
			logger.warn("Computer not found for UUID: {}", uuid);
			return -1; // Not found
		}
		Computer computer = computerOpt.get();
		if (!computer.isDeleted()) {
			logger.warn("Computer not soft deleted for UUID: {}", uuid);
			return -2; // Not deleted
		}
		computer.setDeleted(false);
		// Keep is_active = false as per requirement
		computer.setUpdatedAt(LocalDateTime.now());
		int status = computerRepository.updateDeletionStatus(computer);
		if (status != 1) {
			logger.error("Failed to revert soft delete for computer with UUID: {}", uuid);
			return -3; // Internal error
		}
		// Revert soft delete for associated computer_applications mappings
		int mappingStatus = computerApplicationRepository.revertSoftDeleteByComputerUuid(uuid);
		logger.debug("Reverted soft delete for {} mappings for computer UUID: {}", mappingStatus, uuid);
		return 1; // Success
	}

	// Added: Activate computer
	@Transactional
	@Override
	public int activateComputer(String uuid) {
		Optional<Computer> computerOpt = computerRepository.findByUuid(uuid);
		if (!computerOpt.isPresent()) {
			logger.warn("Computer not found for UUID: {}", uuid);
			return -1; // Not found
		}
		Computer computer = computerOpt.get();
		if (computer.isDeleted()) {
			logger.warn("Cannot activate soft deleted computer with UUID: {}", uuid);
			return -3; // Soft deleted
		}
		if (computer.isActive()) {
			logger.warn("Computer already active for UUID: {}", uuid);
			return -2; // Already active
		}
		computer.setActive(true);
		computer.setUpdatedAt(LocalDateTime.now());
		int status = computerRepository.updateActivationStatus(computer);
		if (status != 1) {
			logger.error("Failed to activate computer with UUID: {}", uuid);
			return -5; // Internal error
		}
		return 1; // Success
	}

	// Added: Deactivate computer
	@Transactional
	@Override
	public int deactivateComputer(String uuid) {
		Optional<Computer> computerOpt = computerRepository.findByUuid(uuid);
		if (!computerOpt.isPresent()) {
			logger.warn("Computer not found for UUID: {}", uuid);
			return -1; // Not found
		}
		Computer computer = computerOpt.get();
		if (computer.isDeleted()) {
			logger.warn("Cannot deactivate soft deleted computer with UUID: {}", uuid);
			return -3; // Soft deleted
		}
		if (!computer.isActive()) {
			logger.warn("Computer already deactivated for UUID: {}", uuid);
			return -2; // Already deactivated
		}
		computer.setActive(false);
		computer.setUpdatedAt(LocalDateTime.now());
		int status = computerRepository.updateActivationStatus(computer);
		if (status != 1) {
			logger.error("Failed to deactivate computer with UUID: {}", uuid);
			return -5; // Internal error
		}
		return 1; // Success
	}

	// Added: List computers by deletion status
	@Override
	public List<Computer> getComputersByDeletionStatus(Boolean isDeleted) {
		return computerRepository.findByDeletionStatus(isDeleted);
	}

	// Added: List computers by activation status
	@Override
	public List<Computer> getComputersByActivationStatus(Boolean isActive) {
		return computerRepository.findByActivationStatus(isActive);
	}

	@Override
	public List<Computer> getAllDeletedComputers() {
		logger.info("Fetching all deleted computers");
		List<Computer> deletedComputers = computerRepository.findAllDeletedComputers();
		if (deletedComputers.isEmpty()) {
			logger.warn("No deleted computers found");
		} else {
			logger.info("Found {} deleted computers", deletedComputers.size());
		}
		return deletedComputers;
	}

}