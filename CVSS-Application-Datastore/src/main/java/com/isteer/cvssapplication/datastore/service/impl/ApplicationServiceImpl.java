package com.isteer.cvssapplication.datastore.service.impl;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.isteer.cvssapplication.datastore.dao.ApplicationDao;
import com.isteer.cvssapplication.datastore.dao.ComputerDao;
import com.isteer.cvssapplication.datastore.dao.VulnerabilityDao;
import com.isteer.cvssapplication.datastore.dto.SoftwareDTO;
import com.isteer.cvssapplication.datastore.entity.Application;
import com.isteer.cvssapplication.datastore.entity.Computer;
import com.isteer.cvssapplication.datastore.entity.Vulnerability;
import com.isteer.cvssapplication.datastore.enums.CVSSEnum;
import com.isteer.cvssapplication.datastore.exception.BussinessException;
import com.isteer.cvssapplication.datastore.service.ApplicationService;
import com.isteer.cvssapplication.datastore.util.UUIDUtil;

import jakarta.validation.constraints.NotBlank;

@Service
public class ApplicationServiceImpl implements ApplicationService {
	private static final Logger logger = LoggerFactory.getLogger(ApplicationServiceImpl.class);

	@Autowired
	private ApplicationDao applicationRepository;

	@Autowired
	private ComputerDao computerRepository;

	@Autowired
	private VulnerabilityService vulnerabilityService;

	@Autowired
	private VulnerabilityDao vulnerabilityRepository;

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

		vulnerabilityService.analyzeAndSaveApplicationVulnerabilitiesAsync(newApplications);
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
	    return applications;
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

	@Override
	public List<Vulnerability> getVulnerabilitiesByApplicationUuid(String uuid) {
		logger.info("Fetching vulnerabilities for application UUID: {}", uuid);
		if (!(applicationRepository.findByApplicationUuid(uuid)).isPresent()) {
			logger.warn("Application not found for UUID: {}", uuid);
			throw new BussinessException(CVSSEnum.APPLICATION_NOT_FOUND);
		}
		List<Vulnerability> vulnerabilities = vulnerabilityRepository.findByApplicationUuid(uuid);
		logger.info("Found {} vulnerabilities for application UUID: {}", vulnerabilities.size(), uuid);
		return vulnerabilities;
	}

	public Application getApplicationByUuid(String uuid) {
		logger.info("Fetching application by UUID: {}", uuid);
		Optional<Application> application = applicationRepository.findByApplicationUuid(uuid);
		if (!application.isPresent()) {
			logger.warn("Application not found for UUID: {}", uuid);
			throw new BussinessException(CVSSEnum.APPLICATION_NOT_FOUND);
		}
		return application.get();

	}

	public List<Application> getApplicationsWithUnresolvedCpeNames() {
		logger.info("Fetching applications with unresolved CPE names");
		List<Application> applications = applicationRepository.findAllUnresolvedCpeApplications();
		if (applications.isEmpty()) {
			logger.warn("No applications found");
			return Collections.emptyList();
		}
		return applications;
	}
}