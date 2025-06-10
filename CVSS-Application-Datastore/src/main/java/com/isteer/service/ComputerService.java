package com.isteer.service;

import com.isteer.dto.ComputerPayloadDTO;
import com.isteer.entity.Application;
import com.isteer.entity.Computer;
import com.isteer.entity.ComputerApplication;
import com.isteer.enums.CVSSEnum;
import com.isteer.exception.BussinessException;
import com.isteer.repository.dao.ComputerRepositoryDao;
import com.isteer.service.dao.ApplicationServiceDao;
import com.isteer.service.dao.ComputerApplicationServiceDao;
import com.isteer.service.dao.ComputerServiceDao;
import com.isteer.util.StatusMessageUtil;
import com.isteer.util.UUIDUtil;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validator;
import java.time.LocalDateTime;
import java.util.Set;

@Service
public class ComputerService implements ComputerServiceDao {
    private final ComputerRepositoryDao computerRepository;
    private final ApplicationServiceDao applicationService;
    private final ComputerApplicationServiceDao computerApplicationService;
    private final Validator validator;

    public ComputerService(ComputerRepositoryDao computerRepository, ApplicationServiceDao applicationService,
                           ComputerApplicationServiceDao computerApplicationService, Validator validator) {
        this.computerRepository = computerRepository;
        this.applicationService = applicationService;
        this.computerApplicationService = computerApplicationService;
        this.validator = validator;
    }

    @Transactional
    @Override
    public int createComputer(ComputerPayloadDTO payload) {
        // Validate payload
        Set<ConstraintViolation<ComputerPayloadDTO>> violations = validator.validate(payload);
        if (!violations.isEmpty()) {
            StringBuilder errorMsg = new StringBuilder("Validation errors: ");
            for (ConstraintViolation<ComputerPayloadDTO> violation : violations) {
                errorMsg.append(violation.getPropertyPath()).append(": ").append(violation.getMessage()).append("; ");
            }
            throw new BussinessException(CVSSEnum.COMPUTER_PAYLOAD_INVALID.getStatusCode(),
					StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_PAYLOAD_INVALID));
        }

        try {
            // Check if computer exists by device_id
            computerRepository.findByDeviceId(payload.getDeviceId())
                    .ifPresent(c -> {
                    	 throw new BussinessException(CVSSEnum.COMPUTER_NOT_FOUND.getStatusCode(),
             					StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_NOT_FOUND));
                    });

            // Create Computer entity
            Computer computer = new Computer();
            computer.setUuid(UUIDUtil.generateUUID());
            computer.setDeviceId(payload.getDeviceId());
            computer.setHostname(payload.getMachineName());
            computer.setIpAddress(payload.getIpAddress());
            computer.setOsVersion(payload.getOsVersion());
            computer.setAntivirusStatus(payload.getAntivirusStatus());
            computer.setFirewallStatus(payload.getFirewallStatus());
            computer.setLoggedInUser(payload.getLoggedInUser());
            computer.setLastUpdateCheck(payload.getLastUpdateCheck());
            computer.setActive(true);
            computer.setDeleted(false);
            computer.setCreatedAt(LocalDateTime.now());

            // Save computer
            int rows = computerRepository.save(computer);
            if (rows != 1) {
            	 throw new BussinessException(CVSSEnum.COMPUTER_NOT_FOUND.getStatusCode(),
      					StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_NOT_FOUND));
       
            }

            // Process installed software
            for (ComputerPayloadDTO.SoftwareDTO software : payload.getInstalledSoftware()) {
                // Create Application entity
                Application application = new Application();
                application.setUuid(UUIDUtil.generateUUID());
                application.setName(software.getName());
                application.setVersion(software.getVersion());
                application.setVendorName(software.getVendorName());
                application.setInstalledDate(software.getInstalledDate());
                application.setDeleted(false);
                application.setCreatedAt(LocalDateTime.now());

                // Save application and handle previous versions
                Application savedApplication = applicationService.createApplication(application, computer.getUuid());

                // Create ComputerApplication mapping
                ComputerApplication computerApplication = new ComputerApplication();
                computerApplication.setUuid(UUIDUtil.generateUUID());
                computerApplication.setComputerUuid(computer.getUuid());
                computerApplication.setApplicationUuid(savedApplication.getUuid());
                computerApplication.setInstalledDate(software.getInstalledDate());
                computerApplication.setDeleted(false);
                computerApplication.setCreatedAt(LocalDateTime.now());

                computerApplicationService.createComputerApplication(computerApplication);
            }

            return 1;
        } catch (DataIntegrityViolationException e) {
            if (e.getMessage().contains("computers_device_id_uindex")) {
                throw new BussinessException(CVSSEnum.COMPUTER_WITH_SAME_IP_EXISTS.getStatusCode(),
						StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_WITH_SAME_IP_EXISTS));
			} else if (e.getMessage().contains("computers_hostname_uindex")) {
			} else if (e.getMessage().contains("computers_uuid_uindex")) {
				 throw new BussinessException(CVSSEnum.COMPUTER_WITH_SAME_IP_EXISTS.getStatusCode(),
							StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_WITH_SAME_IP_EXISTS));
            } else if (e.getMessage().contains("computers_ip_address")) {
            	 throw new BussinessException(CVSSEnum.COMPUTER_WITH_SAME_IP_EXISTS.getStatusCode(),
 						StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_WITH_SAME_IP_EXISTS));        }
    }
		return 0 ;
}
}