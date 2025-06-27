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
import com.isteer.cvssapplication.datastore.dao.VulnerabilityDao;
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
	private VulnerabilityDao vulnerabilityRepository;
	
	@Autowired
	private ComputerApplicationService computerApplicationService;

	public int createOrUpdateApplication(List<SoftwareDTO> softwares, String computerUuid) {
		Map<Application, Boolean> appExistenceMap = applicationRepository.isRecordExists1(softwares);
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
		
		computerApplicationService.sampleService(newApplications);

		return 1;
	}


	@Override
	public int createOrUpdateApplication(SoftwareDTO software, String computerUuid) {
		// Delegate to batch method for single application
		return createOrUpdateApplication(Collections.singletonList(software), computerUuid);
	}

	
	 @Override
	    public List<Application> getApplicationsByComputerUuid(String computerUuid, Boolean status) {
	        logger.info("Fetching applications for computer UUID: {} with status: {}", computerUuid, status);
	        List<Application> applications = applicationRepository.findByComputerUuid(computerUuid, status);
	        for (Application app : applications) {
	            app.setVulnerabilities(vulnerabilityRepository.findByApplicationUuid(app.getUuid()));
	        }
	        logger.info("Found {} applications for computer UUID: {}", applications.size(), computerUuid);
	        return applications;
	    }


	 
	  @Override
	    public Application getApplicationByUuid(String uuid) {
	        logger.info("Fetching application with UUID: {}", uuid);
	        // Modified: Remove is_deleted check and fetch vulnerabilities
	        Application application = applicationRepository.findByApplicationUuid(uuid).orElseThrow(() -> {
	            logger.warn("Application not found for UUID: {}", uuid);
	            return new BussinessException(CVSSEnum.APPLICATION_NOT_FOUND);
	        });
	        // Added: Fetch and set vulnerabilities for the application
	        application.setVulnerabilities(vulnerabilityRepository.findByApplicationUuid(uuid));
	        logger.info("Fetched application with UUID: {} and {} vulnerabilities", uuid, application.getVulnerabilities().size());
	        return application;
	    }

	@Override
	public List<Application> getAllApplications() {
		logger.info("Fetching all applications");
		List<Application> applications = applicationRepository.findAllApplications();
		if (applications.isEmpty()) {
			logger.warn("No applications found");
			return Collections.emptyList();
		}
		return applications;
	}
}