package com.isteer.cvssapplication.datastore.controller;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.isteer.cvssanalyser.core.cache.FuzzySearchCache;
import com.isteer.cvssapplication.datastore.dto.ComputerDetailsResponseDTO;
import com.isteer.cvssapplication.datastore.dto.ComputerPayloadDTO;
import com.isteer.cvssapplication.datastore.dto.ErrorMessageDTO;
import com.isteer.cvssapplication.datastore.dto.StatusMessageDTO;
import com.isteer.cvssapplication.datastore.entity.Application;
import com.isteer.cvssapplication.datastore.entity.Computer;
import com.isteer.cvssapplication.datastore.enums.CVSSEnum;
import com.isteer.cvssapplication.datastore.service.impl.ApplicationServiceImpl;
import com.isteer.cvssapplication.datastore.service.impl.ComputerServiceImpl;
import com.isteer.cvssapplication.datastore.util.StatusMessageUtil;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;

@RestController
@RequestMapping("/api")
public class ComputerController {
	private static final Logger logger = LoggerFactory.getLogger(ComputerController.class);

	@Autowired
	private ComputerServiceImpl computerService;

	@Autowired
	private ApplicationServiceImpl applicationService;

	@PostMapping("/computers")
	public ResponseEntity<?> createComputer(@Valid @RequestBody ComputerPayloadDTO payload) {
//		new FuzzySearchCache();
//		FuzzySearchCache.refreshCacheFromDb(); // Refresh cache before processing request
		logger.info("Received request to create/update computer with deviceId: {}", payload.getDeviceId());
		int status = computerService.createComputer(payload);

		switch (status) {
		case 1:
			logger.info("Computer created successfully");
			return ResponseEntity.ok(new StatusMessageDTO(CVSSEnum.COMPUTER_ADD.getStatusCode(),
					StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_ADD)));
		case 2:
			logger.info("Computer and applications updated successfully");
			return ResponseEntity.ok(new StatusMessageDTO(CVSSEnum.COMPUTER_APP_UPDATE.getStatusCode(),
					StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_APP_UPDATE)));
		case 3:
			logger.info("Computer updated successfully");
			return ResponseEntity.ok(new StatusMessageDTO(CVSSEnum.COMPUTER_UPDATE.getStatusCode(),
					StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_UPDATE)));
		case 4:
			logger.info("Applications updated successfully");
			return ResponseEntity.ok(new StatusMessageDTO(CVSSEnum.APPLICATION_UPDATE.getStatusCode(),
					StatusMessageUtil.getMessage(CVSSEnum.APPLICATION_UPDATE)));
		case 0:
			logger.info("No changes made to the computer or applications");
			return ResponseEntity.ok(new StatusMessageDTO(CVSSEnum.NO_CHANGES.getStatusCode(),
					StatusMessageUtil.getMessage(CVSSEnum.NO_CHANGES)));
		case -1:
			logger.warn("Invalid payload received");
			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
					.body(new ErrorMessageDTO(CVSSEnum.COMPUTER_PAYLOAD_INVALID.getStatusCode(),
							StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_PAYLOAD_INVALID)));
			case -2:
				logger.warn("Application name is blank");
				return ResponseEntity.status(HttpStatus.BAD_REQUEST)
					.body(new ErrorMessageDTO(CVSSEnum.APPLICATION_NAME_BLANK.getStatusCode(),
							StatusMessageUtil.getMessage(CVSSEnum.APPLICATION_NAME_BLANK)));
	
		default:
			logger.error("Unexpected error during computer creation/update");
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(new ErrorMessageDTO(CVSSEnum.Internal_Server_Error.getStatusCode(),
							StatusMessageUtil.getMessage(CVSSEnum.Internal_Server_Error)));
		}
	}

	@GetMapping("/computers")
	public ResponseEntity<List<Computer>> getAllComputers() {
		logger.info("Received request to fetch all computers");
		List<Computer> computers = computerService.getAllComputers();
		logger.info("Returning {} computers", computers.size());
		return ResponseEntity.ok(computers);
	}

  

	@GetMapping("computers/{uuid}")
	public ResponseEntity<ComputerDetailsResponseDTO> getComputer(
			@PathVariable @NotBlank(message = "UUID cannot be blank") String uuid) {
		logger.info("Received request to fetch computer with UUID: {}", uuid);
		ComputerDetailsResponseDTO response = computerService.getComputerDetailsByUuid(uuid);
		logger.info("Returning computer with UUID: {} and {} applications", uuid, response.getApplications().size());
		return ResponseEntity.ok(response);
	}


    @GetMapping("/computers/{computerUuid}/applications")
    public ResponseEntity<List<Application>> getApplicationsByComputer(
            @PathVariable @NotBlank(message = "Computer UUID cannot be blank") String computerUuid,
            @RequestParam(required = false) Boolean status) {
        logger.info("Received request to fetch applications for computer UUID: {} with status: {}", computerUuid, status);
        List<Application> applications = applicationService.getApplicationsByComputerUuid(computerUuid, status);
        logger.info("Returning {} applications for computer UUID: {}", applications.size(), computerUuid);
        return ResponseEntity.ok(applications);
    }

    @GetMapping("/applications/{uuid}")
    public ResponseEntity<Application> getApplication(
            @PathVariable @NotBlank(message = "UUID cannot be blank") String uuid) {
        logger.info("Received request to fetch application with UUID: {}", uuid);
        Application application = applicationService.getApplicationByUuid(uuid);
        logger.info("Returning application with UUID: {}", uuid);
        return ResponseEntity.ok(application);
    }
}