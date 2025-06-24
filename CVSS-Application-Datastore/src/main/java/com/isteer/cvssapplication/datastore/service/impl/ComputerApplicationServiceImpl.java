package com.isteer.cvssapplication.datastore.service.impl;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.isteer.cvssanalyser.core.OsSoftwareAnalyzerAndNormalizer;
import com.isteer.cvssanalyser.core.model.ApplicationModel;
import com.isteer.cvssanalyser.core.model.DependencyModel;
import com.isteer.cvssanalyser.core.model.VulnerabilityCvssMetricsModel;
import com.isteer.cvssapplication.datastore.dao.ApplicationVulnerabilityDao;
import com.isteer.cvssapplication.datastore.dao.ComputerApplicationDao;
import com.isteer.cvssapplication.datastore.dao.VulnerabilityDao;
import com.isteer.cvssapplication.datastore.entity.Application;
import com.isteer.cvssapplication.datastore.entity.ApplicationVulnerability;
import com.isteer.cvssapplication.datastore.entity.ComputerApplication;
import com.isteer.cvssapplication.datastore.entity.Vulnerability;
import com.isteer.cvssapplication.datastore.enums.Severity;
import com.isteer.cvssapplication.datastore.service.ComputerApplicationService;
import com.isteer.cvssapplication.datastore.util.UUIDUtil;

@Service
public class ComputerApplicationServiceImpl implements ComputerApplicationService {
	private static final Logger logger = LoggerFactory.getLogger(ComputerApplicationServiceImpl.class);

	@Autowired
	private ComputerApplicationDao computerApplicationRepository;

	@Autowired
	private VulnerabilityDao vulnerabilityDao;
	
	@Autowired
	private ApplicationVulnerabilityDao applicationVulnerabilityDao;

	@Transactional
	@Override
	public int createComputerApplication(String computerUuid, String applicationUuid, LocalDateTime installedDate) {
		logger.debug("Processing mapping for computer UUID: {} and application UUID: {}", computerUuid,
				applicationUuid);

		// Use null if installedDate is null
		LocalDateTime effectiveInstalledDate = installedDate != null ? installedDate : null;
		logger.debug("Effective installedDate: {}", effectiveInstalledDate);

		// Check for existing active mapping
		Optional<ComputerApplication> existingMapping = computerApplicationRepository
				.findByComputerAndApplicationUuid(computerUuid, applicationUuid);
		if (existingMapping.isPresent() && !existingMapping.get().isDeleted()) {
			ComputerApplication mapping = existingMapping.get();
			// Update existing mapping if installed_date changed
			// Compare installedDate safely
			if (!Objects.equals(mapping.getInstalledDate(), installedDate)) {
				mapping.setInstalledDate(installedDate); // Store null if installedDate is null
				mapping.setUpdatedAt(LocalDateTime.now());
				int result = computerApplicationRepository.update(mapping);
				if (result != 1) {
					logger.error("Failed to update mapping for computer UUID: {}, application UUID: {}", computerUuid,
							applicationUuid);
					return -5; // Internal error
				}
				logger.info("Updated mapping for computer UUID: {}, application UUID: {}", computerUuid,
						applicationUuid);
			} else {
				logger.debug("No changes to mapping for computer UUID: {}, application UUID: {}", computerUuid,
						applicationUuid);
			}
			return 1; // Success (no change or updated)
		}

		// Create new mapping
		ComputerApplication ca = new ComputerApplication();
		ca.setUuid(UUIDUtil.generateUUID());
		ca.setComputerUuid(computerUuid);
		ca.setApplicationUuid(applicationUuid);
		ca.setInstalledDate(installedDate);
		ca.setDeleted(false);
		ca.setCreatedAt(LocalDateTime.now());

		int result = computerApplicationRepository.save(ca);
		if (result != 1) {
			logger.error("Failed to save mapping for computer UUID: {}, application UUID: {}", computerUuid,
					applicationUuid);
			return -5; // Internal error
		}

		logger.info("Created mapping for computer UUID: {}, application UUID: {}", computerUuid, applicationUuid);
		return 1; // Success
	}

	@Transactional
	@Override
	public int softDeleteMapping(String computerUuid, String applicationUuid) {
		int result = computerApplicationRepository.softDeleteByComputerAndApplicationUuid(computerUuid,
				applicationUuid);
		logger.debug("Soft deleted mapping for computer UUID: {}, application UUID: {}, updated rows: {}", computerUuid,
				applicationUuid, result);
		return result;
	}

	@Override
	public int reactivateMapping(String computerUuid, String applicationUuid, LocalDateTime installedDate) {
		logger.debug("Reactivating mapping for computer UUID: {} and application UUID: {}", computerUuid,
				applicationUuid);
		int result = computerApplicationRepository.reactivateByComputerAndApplicationUuid(computerUuid, applicationUuid,
				installedDate);
		if (result != 1) {
			logger.error("Failed to reactivate mapping for computer UUID: {}, application UUID: {}", computerUuid,
					applicationUuid);
			return -5; // Internal error
		}
		logger.info("Reactivated mapping for computer UUID: {}, application UUID: {}", computerUuid, applicationUuid);
		return 1; // Success

	}

	@Transactional
	@Override
	public int updateMapping(String computerUuid, String applicationUuid, LocalDateTime installedDate) {
		logger.debug("Updating mapping for computer UUID: {} and application UUID: {}", computerUuid, applicationUuid);
		int result = computerApplicationRepository.updateInstalledDate(computerUuid, applicationUuid, installedDate);
		if (result != 1) {
			logger.error("Failed to update mapping for computer UUID: {}, application UUID: {}", computerUuid,
					applicationUuid);
			return -5; // Internal error
		}
		logger.info("Updated mapping for computer UUID: {}, application UUID: {}", computerUuid, applicationUuid);
		return 1; // Success
	}

	@Override
	@Async("asyncExecutor")
	public void sampleService(List<Application> application) {
		logger.info("Starting async processing of applications");
		List<ApplicationModel> applications = new ArrayList<>();
		for (Application app : application) {
			ApplicationModel appModel = new ApplicationModel();
			appModel.setApplicationUuid(app.getUuid());
			appModel.setApplicationName(app.getName());
			appModel.setApplicationVendor(app.getVendorName());
			appModel.setApplicationVersion(app.getVersion());
			appModel.setExists(false);
			applications.add(appModel);
		}
		logger.info("Calling the resloution method");
		Map<String, DependencyModel> normalizedApplications = new OsSoftwareAnalyzerAndNormalizer()
				.softwareAnalyzerAndNormalizer(applications);
		logger.info("Resolution completed, processing vulnerabilities");
		if (normalizedApplications != null && !normalizedApplications.isEmpty()) {
			normalizedApplications.forEach((key, value) -> {
				value.getVulnerabilities().forEach(vulnerability -> {
					Vulnerability vuln = new Vulnerability();
					vuln.setUuid(UUIDUtil.generateUUID());
					vuln.setCveId(vulnerability.getCveId());
					vuln.setDescription(vulnerability.getCveDescription());
					vuln.setSourceIdentifier(vulnerability.getSourceIdentifier());

					Optional<VulnerabilityCvssMetricsModel> highestVersionMetric = vulnerability.getCvssMetrics()
							.stream().max((m1, m2) -> {
								double v1 = 0.0;
								double v2 = 0.0;
								try {
									v1 = Double.parseDouble(m1.getVersion());
								} catch (Exception ignored) {
								}
								try {
									v2 = Double.parseDouble(m2.getVersion());
								} catch (Exception ignored) {
								}
								return Double.compare(v1, v2);
							});

					highestVersionMetric.ifPresent(metric -> {
						vuln.setCvssVersion(metric.getVersion());
						vuln.setCvssScore(metric.getBaseScore());
						vuln.setSeverity(Severity.valueOf(metric.getBaseSeverity()));
						vuln.setVectorString(metric.getVectorString());

					});
					vulnerabilityDao.save(vuln);
					
					 ApplicationVulnerability appVuln = new ApplicationVulnerability();
				        appVuln.setUuid(UUIDUtil.generateUUID());
				        appVuln.setApplicationUuid(key); // from DependencyModel
				        appVuln.setVulnerabilityUuid(vuln.getUuid());           // from saved Vulnerability
//				        appVuln.setDeleted
//				        appVuln.setCreatedAt(LocalDateTime.now());
//				        appVuln.setUpdatedAt(null); // or LocalDateTime.now() if needed

				        applicationVulnerabilityDao.save(appVuln);
				});
			});

		}
	}

}