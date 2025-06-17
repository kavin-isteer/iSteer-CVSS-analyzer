package com.isteer.controller;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

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
import org.springframework.web.bind.annotation.RestController;

import com.isteer.dto.ComputerPayloadDTO;
import com.isteer.dto.ErrorMessageDto;
import com.isteer.dto.StatusMessageDto;
import com.isteer.entity.Application;
import com.isteer.entity.Computer;
import com.isteer.enums.CVSSEnum;
import com.isteer.service.dao.ApplicationServiceDao;
import com.isteer.service.dao.ComputerServiceDao;
import com.isteer.util.StatusMessageUtil;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;

@RestController
@RequestMapping("/api")
public class ComputerController {
    private static final Logger logger = LoggerFactory.getLogger(ComputerController.class);

    @Autowired
    private ComputerServiceDao computerService;

    @Autowired
    private ApplicationServiceDao applicationService;

    @PostMapping("/computers")
    public ResponseEntity<?> createComputer(@Valid @RequestBody ComputerPayloadDTO payload) {
        logger.info("Received request to create/update computer with deviceId: {}", payload.getDeviceId());
        int status = computerService.createComputer(payload);

        switch (status) {
            case 1:
                logger.info("Computer created successfully");
                return ResponseEntity.ok(new StatusMessageDto(CVSSEnum.COMPUTER_ADD.getStatusCode(),
                        StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_ADD)));
            case 2:
                logger.info("Computer updated successfully");
                return ResponseEntity.ok(new StatusMessageDto(CVSSEnum.COMPUTER_UPDATE.getStatusCode(),
                        StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_UPDATE)));
            case -1:
                logger.warn("Invalid payload received");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                        new ErrorMessageDto(CVSSEnum.COMPUTER_PAYLOAD_INVALID.getStatusCode(),
                                StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_PAYLOAD_INVALID)));
            case -3:
                logger.warn("Device ID already exists");
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(
                        new ErrorMessageDto(CVSSEnum.COMPUTER_DEVICE_ID_EXISTS.getStatusCode(),
                                StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_DEVICE_ID_EXISTS)));

            default:
                logger.error("Unexpected error during computer creation/update");
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(
                        new ErrorMessageDto(CVSSEnum.Internal_Server_Error.getStatusCode(),
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

    @GetMapping("/computers/{uuid}")
    public ResponseEntity<Map<String, Object>> getComputer(
            @PathVariable @NotBlank(message = "UUID cannot be blank") String uuid) {
        logger.info("Received request to fetch computer with UUID: {}", uuid);
        Computer computer = computerService.getComputerByUuid(uuid);
        List<Application> applications = applicationService.getApplicationsByComputerUuid(uuid);

        Map<String, Object> response = new HashMap<>();
        response.put("computer", computer);
        response.put("applications", applications);

        logger.info("Returning computer with UUID: {} and {} applications", uuid, applications.size());
        return ResponseEntity.ok(response);
    }

    @GetMapping("/computers/{computerUuid}/applications")
    public ResponseEntity<List<Application>> getApplicationsByComputer(
            @PathVariable @NotBlank(message = "Computer UUID cannot be blank") String computerUuid) {
        logger.info("Received request to fetch applications for computer UUID: {}", computerUuid);
        List<Application> applications = applicationService.getApplicationsByComputerUuid(computerUuid);
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
    }}