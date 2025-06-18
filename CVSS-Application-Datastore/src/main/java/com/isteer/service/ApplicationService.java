package com.isteer.service;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.isteer.dto.SoftwareDTO;
import com.isteer.entity.Application;
import com.isteer.entity.ComputerApplication;
import com.isteer.enums.CVSSEnum;
import com.isteer.exception.BussinessException;
import com.isteer.repository.dao.ApplicationRepositoryDao;
import com.isteer.repository.dao.ComputerApplicationRepositoryDao;
import com.isteer.service.dao.ApplicationServiceDao;
import com.isteer.service.dao.ComputerApplicationServiceDao;
import com.isteer.util.UUIDUtil;

@Service
public class ApplicationService implements ApplicationServiceDao {
	private static final Logger logger = LoggerFactory.getLogger(ApplicationService.class);

	@Autowired
	private ApplicationRepositoryDao applicationRepository;

	@Autowired
	private ComputerApplicationRepositoryDao computerApplicationRepository;

	@Autowired
	private ComputerApplicationServiceDao computerApplicationService;

	@Transactional
	@Override
	public int createOrUpdateApplication(SoftwareDTO software, String computerUuid) {
		logger.info("Processing application: {} version {} vendor: {} for computer UUID: {}", software.getName(),
				software.getVersion(), software.getVendorName(), computerUuid);
		  // Normalize version: treat null or "null" as empty string
        String version = software.getVersion() == null ? "" : software.getVersion();
        
        String vendorName = software.getVendorName() == null ? "" : software.getVendorName();
		
		// Check for existing application (including soft-deleted mappings)
		Optional<Application> existingApp = applicationRepository.findByNameVersionVendor(software.getName(),
				version, vendorName);
		Application application;

		if (existingApp.isPresent()) {
			application = existingApp.get();
			logger.debug("Reusing existing application with UUID: {}", application.getUuid());

			// Check if there's a mapping for this computer and application
			Optional<ComputerApplication> existingMapping = computerApplicationRepository
					.findByComputerAndApplicationUuid(computerUuid, application.getUuid());
			if (existingMapping.isPresent()) {
				// Reactivate soft-deleted mapping
				if (existingMapping.get().isDeleted()) {
					computerApplicationService.reactivateMapping(computerUuid, application.getUuid(),
							software.getInstalledDate());
					logger.debug("Reactivated mapping for application UUID: {}", application.getUuid());
				} else {
					logger.debug("Found existing active mapping for application UUID: {}", application.getUuid());
					 // Update installed_date if changed
                    if (!Objects.equals(existingMapping.get().getInstalledDate(), software.getInstalledDate())) {
                        computerApplicationService.updateMapping(computerUuid, application.getUuid(), software.getInstalledDate());
                        logger.debug("Updated installed_date for mapping with application UUID: {}", application.getUuid());
                    }
				}
			} else {
				// Create new mapping
				int mappingStatus = computerApplicationService.createComputerApplication(computerUuid,
						application.getUuid(), software.getInstalledDate());
				if (mappingStatus != 1) {
					logger.warn("Failed to create mapping for application UUID: {}, status: {}", application.getUuid(),
							mappingStatus);
					return mappingStatus;
				}
			}
		} else {
			// Create new application
			application = new Application();
			application.setUuid(UUIDUtil.generateUUID());
			application.setName(software.getName());
			application.setVersion(version);
			application.setVendorName(vendorName);
			application.setCreatedAt(LocalDateTime.now());

			if (applicationRepository.save(application) != 1) {
				logger.error("Failed to save application with UUID: {}", application.getUuid());
				return -5; // Internal error
			}
			logger.info("Created new application with UUID: {}", application.getUuid());

			// Create new mapping
			int mappingStatus = computerApplicationService.createComputerApplication(computerUuid,
					application.getUuid(), software.getInstalledDate());
			if (mappingStatus != 1) {
				logger.warn("Failed to create mapping for application UUID: {}, status: {}", application.getUuid(),
						mappingStatus);
				return mappingStatus;
			}
		}

		// Soft-delete mappings for other applications with same name and vendor but
		// different version
		Optional<Application> currentMappedApp = applicationRepository.findByComputerUuidAndNameVendor(computerUuid,
				software.getName(), vendorName);
		if (currentMappedApp.isPresent() && !currentMappedApp.get().getUuid().equals(application.getUuid())) {
			computerApplicationService.softDeleteMapping(computerUuid, currentMappedApp.get().getUuid());
			logger.debug("Soft deleted old mapping for application UUID: {}", currentMappedApp.get().getUuid());
		}

		logger.info("Created/updated application mapping for computer UUID: {}", computerUuid);
		return 1; // Success
	}

	@Transactional(readOnly = true)
	@Override
	public List<Application> getApplicationsByComputerUuid(String computerUuid) {
		logger.info("Fetching applications for computer UUID: {}", computerUuid);
		return applicationRepository.findByComputerUuid(computerUuid);
	}

	@Transactional(readOnly = true)
	@Override
	public Application getApplicationByUuid(String uuid) {
		logger.info("Fetching application with UUID: {}", uuid);
		return applicationRepository.findByUuidAndIsDeletedFalse(uuid).orElseThrow(() -> {
			logger.warn("Application not found for UUID: {}", uuid);
			return new BussinessException(CVSSEnum.APPLICATION_NOT_FOUND);
		});
	}
}