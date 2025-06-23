package com.isteer.cvssapplication.datastore.service.impl;

import java.sql.SQLException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.isteer.cvssanalyser.core.OsSoftwareAnalyzerAndNormalizer;
import com.isteer.cvssanalyser.core.cveclient.CveClient;
import com.isteer.cvssanalyser.core.model.ApplicationModel;
import com.isteer.cvssanalyser.core.model.DependencyModel;
import com.isteer.cvssapplication.datastore.dao.ComputerApplicationDao;
import com.isteer.cvssapplication.datastore.entity.Application;
import com.isteer.cvssapplication.datastore.entity.ComputerApplication;
import com.isteer.cvssapplication.datastore.service.ComputerApplicationService;
import com.isteer.cvssapplication.datastore.util.UUIDUtil;

@Service
public class ComputerApplicationServiceImpl implements ComputerApplicationService {
	 private static final Logger logger = LoggerFactory.getLogger(ComputerApplicationServiceImpl.class);

	    @Autowired
	    private ComputerApplicationDao computerApplicationRepository;

	    @Transactional
	    @Override
	    public int createComputerApplication(String computerUuid, String applicationUuid, LocalDateTime installedDate) {
	        logger.debug("Processing mapping for computer UUID: {} and application UUID: {}", computerUuid, applicationUuid);


	        // Use null if installedDate is null
	        LocalDateTime effectiveInstalledDate = installedDate != null ? installedDate : null;
	        logger.debug("Effective installedDate: {}", effectiveInstalledDate);

	        
	        // Check for existing active mapping
	        Optional<ComputerApplication> existingMapping = computerApplicationRepository.findByComputerAndApplicationUuid(computerUuid, applicationUuid);
	        if (existingMapping.isPresent() && !existingMapping.get().isDeleted()) {
	            ComputerApplication mapping = existingMapping.get();
	            // Update existing mapping if installed_date changed
	            // Compare installedDate safely
	            if (!Objects.equals(mapping.getInstalledDate(), installedDate)) {
	                mapping.setInstalledDate(installedDate); // Store null if installedDate is null
	                mapping.setUpdatedAt(LocalDateTime.now());
	                int result = computerApplicationRepository.update(mapping);
	                if (result != 1) {
	                    logger.error("Failed to update mapping for computer UUID: {}, application UUID: {}", computerUuid, applicationUuid);
	                    return -5; // Internal error
	                }
	                logger.info("Updated mapping for computer UUID: {}, application UUID: {}", computerUuid, applicationUuid);
	            } else {
	                logger.debug("No changes to mapping for computer UUID: {}, application UUID: {}", computerUuid, applicationUuid);
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
	            logger.error("Failed to save mapping for computer UUID: {}, application UUID: {}", computerUuid, applicationUuid);
	            return -5; // Internal error
	        }

	        logger.info("Created mapping for computer UUID: {}, application UUID: {}", computerUuid, applicationUuid);
	        return 1; // Success
	    }

	    @Transactional
	    @Override
	    public int softDeleteMapping(String computerUuid, String applicationUuid) {
	        int result = computerApplicationRepository.softDeleteByComputerAndApplicationUuid(computerUuid, applicationUuid);
	        logger.debug("Soft deleted mapping for computer UUID: {}, application UUID: {}, updated rows: {}", computerUuid, applicationUuid, result);
	        return result;
	    }

		@Override
		public int reactivateMapping(String computerUuid,  String applicationUuid, LocalDateTime installedDate) {
			 logger.debug("Reactivating mapping for computer UUID: {} and application UUID: {}", computerUuid, applicationUuid);
		        int result = computerApplicationRepository.reactivateByComputerAndApplicationUuid(computerUuid, applicationUuid, installedDate);
		        if (result != 1) {
		            logger.error("Failed to reactivate mapping for computer UUID: {}, application UUID: {}", computerUuid, applicationUuid);
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
	            logger.error("Failed to update mapping for computer UUID: {}, application UUID: {}", computerUuid, applicationUuid);
	            return -5; // Internal error
	        }
	        logger.info("Updated mapping for computer UUID: {}, application UUID: {}", computerUuid, applicationUuid);
	        return 1; // Success
	    }

		@Override
		@Async("asyncExecutor")
		public void sampleService(Application application) {
			try {
				ApplicationModel applications = new ApplicationModel();
				applications.setApplicationName(application.getName());
				applications.setApplicationVendor(application.getVendorName());
				applications.setApplicationVersion(application.getVersion());
//				logger.info("Calling the resloution method");
				List<DependencyModel> normalizedApplications = new OsSoftwareAnalyzerAndNormalizer().resolveOsSoftwareNames(applications);
				for( DependencyModel normalizedApplication : normalizedApplications) {
					DependencyModel vuln = new CveClient().fetchVulnerabilitiesForDependency(normalizedApplication);
					System.out.println(vuln);
				}
			}catch (SQLException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		}

}