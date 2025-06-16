package com.isteer.service;

import com.isteer.entity.Application;
import com.isteer.entity.Computer;
import com.isteer.entity.ComputerApplication;
import com.isteer.dto.ComputerPayloadDTO;
import com.isteer.enums.CVSSEnum;
import com.isteer.exception.BussinessException;
import com.isteer.repository.dao.ApplicationRepositoryDao;
import com.isteer.repository.dao.ComputerApplicationRepositoryDao;
import com.isteer.repository.dao.ComputerRepositoryDao;
import com.isteer.service.dao.ApplicationServiceDao;
import com.isteer.service.dao.ComputerServiceDao;
import com.isteer.util.UUIDUtil;
import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

@Service
public class ComputerService implements ComputerServiceDao {
	 private static final Logger logger = LoggerFactory.getLogger(ComputerService.class);

	    @Autowired
	    private ComputerRepositoryDao computerRepository;

	    @Autowired
	    private ApplicationRepositoryDao applicationRepository;

	    @Autowired
	    private ApplicationServiceDao applicationService;

	    @Autowired
	    private ComputerApplicationRepositoryDao computerApplicationRepository;

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
	                    return -5; // Internal error
	                }
	                logger.info("Updated computer with UUID: {}", computer.getUuid());
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
	            computer.setHostname(payload.getMachineName());
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
	                return -5; // Internal error
	            }
	            logger.info("Created new computer with UUID: {}", computer.getUuid());
	        }

	        Set<Integer> appStatuses = payload.getInstalledSoftware().stream()
	                .map(software -> applicationService.createOrUpdateApplication(software, computer.getUuid()))
	                .collect(Collectors.toSet());

	        if (appStatuses.contains(-5)) {
	            logger.error("Internal error processing applications for computer UUID: {}", computer.getUuid());
	            return -5; // Internal error
	        }

	        return isUpdate ? 2 : 1; // 2 for update success, 1 for create success
	    }

	    private boolean isComputerUnchanged(Computer computer, ComputerPayloadDTO payload) {
	        return computer.getHostname().equals(payload.getMachineName()) &&
	               computer.getIpAddress().equals(payload.getIpAddress()) &&
	               computer.getOsVersion().equals(payload.getOsVersion()) &&
	               (computer.getAntivirusStatus() == null ? payload.getAntivirusStatus() == null : computer.getAntivirusStatus().equals(payload.getAntivirusStatus())) &&
	               (computer.getFirewallStatus() == null ? payload.getFirewallStatus() == null : computer.getFirewallStatus().equals(payload.getFirewallStatus())) &&
	               (computer.getLoggedInUser() == null ? payload.getLoggedInUser() == null : computer.getLoggedInUser().equals(payload.getLoggedInUser())) &&
	               computer.getLastUpdateCheck().equals(payload.getLastUpdateCheck())
	               && computer.getTimestamp().equals(payload.getTimestamp());
	    }

	    private void updateComputerDetails(Computer computer, ComputerPayloadDTO payload) {
	        computer.setHostname(payload.getMachineName());
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
}