package com.isteer.cvssapplication.datastore.service.impl;

import java.time.LocalDateTime;
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
import com.isteer.cvssapplication.datastore.dto.ComputerDetailsResponseDTO;
import com.isteer.cvssapplication.datastore.dto.ComputerPayloadDTO;
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
	        logger.info("Processing computer with deviceId: {}", payload.getDeviceId());
	        Set<ConstraintViolation<ComputerPayloadDTO>> violations = validator.validate(payload);
	        if (!violations.isEmpty()) {
	            logger.warn("Validation errors: {}", violations.stream().map(ConstraintViolation::getMessage).collect(Collectors.joining("; ")));
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
	                }
	                else {
	                	isComputerUpdated = true;
	                logger.info("Updated computer with UUID: {}", computer.getUuid());
	            }
	            }
	            // Process application mappings
	            List<ComputerApplication> currentMappings = computerApplicationRepository.findByComputerUuid(computer.getUuid());
	            Set<String> newAppKeys = payload.getInstalledSoftware().stream()
	                    .map(s -> s.getName() + ":" + s.getVendorName() + ":" + s.getVersion())
	                    .collect(Collectors.toSet());
	            for (ComputerApplication mapping : currentMappings) {
	                Application app = applicationRepository.findByUuidAndIsDeletedFalse(mapping.getApplicationUuid()).orElse(null);
	                if (app != null) {
	                    String appKey = app.getName() + ":" + app.getVendorName() + ":" + app.getVersion();
	                    if (!newAppKeys.contains(appKey)) {
	                        computerApplicationRepository.softDeleteByComputerAndApplicationUuid(computer.getUuid(), app.getUuid());
	                        logger.debug("Soft deleted mapping for application UUID: {}", app.getUuid());
	                    }
	                }
	            }
	        } else {
	            if (computerRepository.findByDeviceIdAndIsDeletedFalse(payload.getDeviceId()).isPresent()) {
	                logger.warn("Device ID {} already exists", payload.getDeviceId());
	                return -3; // Device ID exists
	            }
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
	            }
	            logger.info("Created new computer with UUID: {}", computer.getUuid());
	        }

	        Set<Integer> appStatuses = payload.getInstalledSoftware().stream()
	                .map(software -> applicationService.createOrUpdateApplication(software, computer.getUuid()))
	                .collect(Collectors.toSet());
	        	  isApplicationsUpdated = true;
	            logger.info("Processed applications for computer UUID: {}", computer.getUuid());
	            if (appStatuses.contains(-1)) {
	                logger.error("Error processing applications for computer UUID: {}", computer.getUuid());
	                return -4; // Error in application processing
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

//	        return isUpdate ? 2 : 1; // 2 for update success, 1 for create success
	    }

	    private boolean isComputerUnchanged(Computer computer, ComputerPayloadDTO payload) {
	        return computer.getMachineName().equals(payload.getMachineName()) &&
	               computer.getIpAddress().equals(payload.getIpAddress()) &&
	               computer.getOsVersion().equals(payload.getOsVersion()) &&
	               (computer.getAntivirusStatus() == null ? payload.getAntivirusStatus() == null : computer.getAntivirusStatus().equals(payload.getAntivirusStatus())) &&
	               (computer.getFirewallStatus() == null ? payload.getFirewallStatus() == null : computer.getFirewallStatus().equals(payload.getFirewallStatus())) &&
	               (computer.getLoggedInUser() == null ? payload.getLoggedInUser() == null : computer.getLoggedInUser().equals(payload.getLoggedInUser())) &&
	               computer.getLastUpdateCheck().equals(payload.getLastUpdateCheck())
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
	        return computerRepository.findByUuidAndIsDeletedFalse(uuid)
	                .orElseThrow(() -> {
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
}