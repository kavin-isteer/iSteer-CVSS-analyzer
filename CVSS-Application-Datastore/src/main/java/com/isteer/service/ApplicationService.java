package com.isteer.service;

import com.isteer.entity.Application;
import com.isteer.enums.CVSSEnum;
import com.isteer.exception.BussinessException;
import com.isteer.repository.dao.ApplicationRepositoryDao;
import com.isteer.service.dao.ApplicationServiceDao;

import com.isteer.util.StatusMessageUtil;

import java.util.Optional;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ApplicationService implements ApplicationServiceDao {
    private final ApplicationRepositoryDao applicationRepository;

    public ApplicationService(ApplicationRepositoryDao applicationRepository) {
        this.applicationRepository = applicationRepository;
    }

    @Transactional
    @Override
    public Application createApplication(Application application, String computerUuid) {
        try {
            // Check if application exists by name, version, vendor_name
            Optional<Application> existingApp = applicationRepository.findByNameVersionVendor(
                    application.getName(), application.getVersion(), application.getVendorName());

            if (existingApp.isPresent()) {
                return existingApp.get(); // Skip insertion if exists
            }

            // Soft delete previous versions
            softDeletePreviousVersions(application.getName(), application.getVendorName(), application.getVersion());

            // Save new application
            int rows = applicationRepository.save(application);
            if (rows != 1) {
                throw new BussinessException(CVSSEnum.APPLICATION_ADD.getStatusCode(),
                      StatusMessageUtil.getMessage(CVSSEnum.APPLICATION_ADD));
            }

            return application;
        } catch (DataIntegrityViolationException e) {
            if (e.getMessage().contains("applications_name_version_vendor_name_uindex")) {
                // Handle race condition: another thread inserted the same application
                return applicationRepository.findByNameVersionVendor(
                        application.getName(), application.getVersion(), application.getVendorName())
                        .orElseThrow(() -> new BussinessException(CVSSEnum.APPLICATION_NOT_FOUND.getStatusCode(),
                                StatusMessageUtil.getMessage(CVSSEnum.APPLICATION_NOT_FOUND)));
            }
            throw new BussinessException(CVSSEnum.INVALID_SQL_SYNTAX.getStatusCode(),
					StatusMessageUtil.getMessage(CVSSEnum.INVALID_SQL_SYNTAX));
		} catch (Exception e) {
			throw new BussinessException(CVSSEnum.APPLICATION_ADD.getStatusCode(),StatusMessageUtil.getMessage(CVSSEnum.Internal_Server_Error));
        }
    }

    @Override
    public void softDeletePreviousVersions(String name, String vendorName, String version) {
        applicationRepository.softDeleteByNameAndVendor(name, vendorName, version);
    }
}