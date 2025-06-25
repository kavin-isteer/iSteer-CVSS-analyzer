package com.isteer.cvssapplication.datastore.service.impl;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.isteer.cvssapplication.datastore.dao.ApplicationDao;
import com.isteer.cvssapplication.datastore.dao.ComputerApplicationDao;
import com.isteer.cvssapplication.datastore.dto.SoftwareDTO;
import com.isteer.cvssapplication.datastore.entity.Application;
import com.isteer.cvssapplication.datastore.entity.ComputerApplication;
import com.isteer.cvssapplication.datastore.enums.CVSSEnum;
import com.isteer.cvssapplication.datastore.exception.BussinessException;
import com.isteer.cvssapplication.datastore.service.ApplicationService;
import com.isteer.cvssapplication.datastore.service.ComputerApplicationService;
import com.isteer.cvssapplication.datastore.util.UUIDUtil;

@Service
public class ApplicationServiceImpl implements ApplicationService {
	private static final Logger logger = LoggerFactory.getLogger(ApplicationServiceImpl.class);

	@Autowired
	private ApplicationDao applicationRepository;

	@Autowired
	private ComputerApplicationDao computerApplicationRepository;

	@Autowired
	private ComputerApplicationService computerApplicationService;

	public int createOrUpdateApplication(List<SoftwareDTO> softwares, String computerUuid) {
		Map<Application, Boolean> appExistenceMap = applicationRepository.isRecordExists(softwares);
		List<Application> newApplications = new ArrayList<>();
		appExistenceMap.forEach((app, exists) -> {
			if (!exists) {
				newApplications.add(app);
			}
		});
		if (!newApplications.isEmpty()) {
			for (Application app : newApplications) {
				app.setUuid(UUIDUtil.generateUUID());
				app.setCreatedAt(LocalDateTime.now());
			}
			int[] applicationBatchResult = applicationRepository.batchSave(newApplications);
			for (int res : applicationBatchResult) {
				if (res != 1) {
					logger.error("Failed to save some applications");
					return -1; // Internal error
				}
			}
			logger.info("Batch saved {} new applications", newApplications.size());
		}
		int[] computerApplicationBatchResult = computerApplicationRepository
				.batchMapApplicaitonAndComputer(newApplications, computerUuid);
		for (int res : computerApplicationBatchResult) {
			if (res != 1) {
				logger.error("Failed to map some applications to computer UUID: {}", computerUuid);
				return -1; // Internal error
			}
		}

		computerApplicationService.sampleService(newApplications);
//		List<Application> applications = new ArrayList<>();
//		for(SoftwareDTO software : softwares) {
//			Application application = new Application();
//			application.setUuid(UUIDUtil.generateUUID());
//			application.setName(software.getName());
//			application.setVendorName(software.getVendorName() == null ? "" : software.getVendorName());
//			application.setVersion(software.getVersion() == null ? "" : software.getVersion());
//			application.setCreatedAt(LocalDateTime.now());
//			application.setInstalledDate(software.getInstalledDate());
//		}
		return 1;
	}

	/*
	 * public int createOrUpdateApplication1(List<SoftwareDTO> softwares, String
	 * computerUuid) {
	 * logger.debug("Processing {} applications for computer UUID: {}",
	 * softwares.size(), computerUuid); // Check existence of all applications in
	 * one query Map<Application, Boolean> appExistenceMap =
	 * applicationRepository.isRecordExists(softwares); List<Application>
	 * newApplications = new ArrayList<>(); Map<SoftwareDTO, String> appUuids = new
	 * HashMap<>(); // Normalize version: treat null or "null" as empty string
	 * 
	 * // Process each software for (SoftwareDTO software : softwares) { String
	 * version = software.getVersion() == null ? "" : software.getVersion(); String
	 * vendorName = software.getVendorName() == null ? "" :
	 * software.getVendorName(); String key = software.getName() + "|" + version +
	 * "|" + vendorName; Application existingApp = appExistenceMap.get(key);
	 * 
	 * if (existingApp != null) { appUuids.put(software, existingApp.getUuid()); }
	 * else { Application application = new Application();
	 * application.setUuid(UUIDUtil.generateUUID());
	 * application.setName(software.getName()); application.setVersion(version);
	 * application.setVendorName(vendorName);
	 * application.setCreatedAt(LocalDateTime.now());
	 * newApplications.add(application); appUuids.put(software,
	 * application.getUuid()); } }
	 * 
	 * // Batch save new applications if (!newApplications.isEmpty()) { int[]
	 * results = applicationRepository.batchSave(newApplications); for (int result :
	 * results) { if (result != 1) {
	 * logger.error("Failed to save some applications"); return -1; // Internal
	 * error } } logger.info("Batch saved {} new applications",
	 * newApplications.size()); } // try { //
	 * computerApplicationService.sampleService(application); // } catch (Exception
	 * e) { // // TODO Auto-generated catch block // e.printStackTrace(); // }
	 * 
	 * // Process mappings for (SoftwareDTO software : softwares) { String version =
	 * software.getVersion() == null ? "" : software.getVersion(); String vendorName
	 * = software.getVendorName() == null ? "" : software.getVendorName(); String
	 * appUuid = appUuids.get(software);
	 * 
	 * // Check for existing mapping Optional<ComputerApplication> existingMapping =
	 * computerApplicationRepository .findByComputerAndApplicationUuid(computerUuid,
	 * appUuid); if (existingMapping.isPresent()) { // Reactivate soft-deleted
	 * mapping if (existingMapping.get().isDeleted()) {
	 * computerApplicationService.reactivateMapping(computerUuid, appUuid,
	 * software.getInstalledDate());
	 * logger.debug("Reactivated mapping for application UUID: {}", appUuid); } else
	 * if (!Objects.equals(existingMapping.get().getInstalledDate(),
	 * software.getInstalledDate())) { // Update installed_date if changed
	 * computerApplicationService.updateMapping(computerUuid, appUuid,
	 * software.getInstalledDate());
	 * logger.debug("Updated installed_date for mapping with application UUID: {}",
	 * appUuid); } } else { // Create new mapping int mappingStatus =
	 * computerApplicationService.createComputerApplication(computerUuid, appUuid,
	 * software.getInstalledDate()); if (mappingStatus != 1) {
	 * logger.warn("Failed to create mapping for application UUID: {}, status: {}",
	 * appUuid, mappingStatus); return mappingStatus; } }
	 * 
	 * // Soft-delete mappings for other applications with same name and vendor but
	 * different version Optional<Application> currentMappedApp =
	 * applicationRepository.findByComputerUuidAndNameVendor(computerUuid,
	 * software.getName(), vendorName); if (currentMappedApp.isPresent() &&
	 * !currentMappedApp.get().getUuid().equals(appUuid)) {
	 * computerApplicationService.softDeleteMapping(computerUuid,
	 * currentMappedApp.get().getUuid());
	 * logger.debug("Soft deleted old mapping for application UUID: {}",
	 * currentMappedApp.get().getUuid()); }
	 * 
	 * 
	 * }
	 * 
	 * logger.info("Created/updated application mappings for computer UUID: {}",
	 * computerUuid); return 1; // Success }
	 */

	@Override
	public int createOrUpdateApplication(SoftwareDTO software, String computerUuid) {
		// Delegate to batch method for single application
		return createOrUpdateApplication(Collections.singletonList(software), computerUuid);
	}

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

	@Override
	public List<Application> getAllApplications() {
		logger.info("Fetching all applications");
		List<Application> applications = applicationRepository.findAll();
		if (applications.isEmpty()) {
			logger.warn("No applications found");
			return Collections.emptyList();
		}
		return applications;
	}
}