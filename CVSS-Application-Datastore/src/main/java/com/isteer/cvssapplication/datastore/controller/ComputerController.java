package com.isteer.cvssapplication.datastore.controller;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.isteer.cvssapplication.datastore.dto.ComputerDetailsResponseDTO;
import com.isteer.cvssapplication.datastore.dto.ComputerPayloadDTO;
import com.isteer.cvssapplication.datastore.dto.ErrorMessageDTO;
import com.isteer.cvssapplication.datastore.dto.StatusMessageDTO;
import com.isteer.cvssapplication.datastore.entity.Application;
import com.isteer.cvssapplication.datastore.entity.Computer;
import com.isteer.cvssapplication.datastore.entity.Vulnerability;
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
		case -3:
			logger.warn("Duplicate applications found in payload");
			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
					.body(new ErrorMessageDTO(CVSSEnum.DUPLICATE_APPLICATIONS.getStatusCode(),
							StatusMessageUtil.getMessage(CVSSEnum.DUPLICATE_APPLICATIONS)));
		case -4:
			logger.warn("Computer is deleted or inactive for deviceId: {}", payload.getDeviceId());
			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
					.body(new ErrorMessageDTO(CVSSEnum.COMPUTER_INACTIVE.getStatusCode(),
							StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_INACTIVE)));

		default:
			logger.error("Unexpected error during computer creation/update");
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(new ErrorMessageDTO(CVSSEnum.Internal_Server_Error.getStatusCode(),
							StatusMessageUtil.getMessage(CVSSEnum.Internal_Server_Error)));
		}
	}

	@GetMapping("/computers")
	public ResponseEntity<List<Computer>> getAllPresentComputers() {
		logger.info("Received request to fetch all computers");
		List<Computer> computers = computerService.getAllPresentComputers();
		if (computers.isEmpty()) { // Check if the list is empty
			return ResponseEntity.noContent().build(); // Return no content status
		}
		logger.info("Returning {} computers", computers.size());
		return ResponseEntity.ok(computers);
	}

	@GetMapping("/computers/is-deleted")
	public ResponseEntity<List<Computer>> getAllDeletedComputers() {
		logger.info("Received request to fetch all deleted computers");
		List<Computer> computers = computerService.getAllDeletedComputers();
		if (computers.isEmpty()) { // Check if the list is empty
			return ResponseEntity.noContent().build(); // Return no content status
		}
		logger.info("Returning {} deleted computers", computers.size());
		return ResponseEntity.ok(computers);
	}

	@GetMapping("/computers/{uuid}")
	public ResponseEntity<ComputerDetailsResponseDTO> getComputerDetails(@PathVariable String uuid) {
		logger.info("Received request to fetch computer details with UUID: {}", uuid);
		ComputerDetailsResponseDTO computerDetails = computerService.getComputerDetailsByUuid(uuid);
		logger.info("Returning computer details for UUID: {}", uuid);
		return ResponseEntity.ok(computerDetails);
	}

	@GetMapping("/computers/{computerUuid}/applications")
	public ResponseEntity<?> getApplicationsByComputer(@PathVariable String computerUuid,
			@RequestParam(required = false) String status) {
		// Validate the status string
		if (status != null && !status.equalsIgnoreCase("true") && !status.equalsIgnoreCase("false")) {
			logger.warn("Invalid activation status provided: {}", status);
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorMessageDTO(
					CVSSEnum.INVALID_STATUS.getStatusCode(), StatusMessageUtil.getMessage(CVSSEnum.INVALID_STATUS)));
		}

		// Default to true (active) if status is not provided
		Boolean isDeleted = (status == null) ? null : Boolean.parseBoolean(status);
		logger.info("Received request to fetch applications for computer UUID: {} with status: {}", computerUuid,
				status);

		List<Application> applications = applicationService.getApplicationsByComputerUuid(computerUuid, isDeleted);
		if (applications.isEmpty()) { // Check if the list is empty
			return ResponseEntity.noContent().build(); // Return no content status
		}
		logger.info("Returning {} applications for computer UUID: {}", applications.size(), computerUuid);
		return ResponseEntity.ok(applications);
	}

	@GetMapping("/applications/{uuid}/vulnerabilities")
	public ResponseEntity<List<Vulnerability>> getApplicationVulnerabilities(
			@PathVariable String uuid) {
		logger.info("Received request to fetch vulnerabilities for application with UUID: {}", uuid);
		List<Vulnerability> vulnerabilities = applicationService.getVulnerabilitiesByApplicationUuid(uuid);

		if (vulnerabilities.isEmpty()) {
			logger.warn("No vulnerabilities found for application UUID: {}", uuid);
			return ResponseEntity.noContent().build(); // Return no content status
		}
		logger.info("Returning {} vulnerabilities for application UUID: {}", vulnerabilities.size(), uuid);
		return ResponseEntity.ok(vulnerabilities);
	}
	
	@GetMapping("/applications/{uuid}")
	public ResponseEntity<Application> getApplicationByUuid(
			@PathVariable String uuid) {
		logger.info("Received request to fetch application with UUID: {}", uuid);
		Application application = applicationService.getApplicationByUuid(uuid);
		if (application == null) {
			logger.warn("Application not found for UUID: {}", uuid);
			return ResponseEntity.noContent().build();
		}
		logger.info("Returning application details for UUID: {}", uuid);
		return ResponseEntity.ok(application);
	}
	
	@GetMapping({"/applications/unresolved-cpe", "/applications/unresolved-cpe/{uuid}"})
	public ResponseEntity<List<Application>> getApplicationsWithUnresolvedCpeNames(@PathVariable(required = false) String uuid) {
		logger.info("Received request to fetch applications with unresolved CPE names");
		List<Application> applications = applicationService.getApplicationsWithUnresolvedCpeNames(uuid);
		if (applications.isEmpty()) {
			logger.warn("No applications found with unresolved CPE names");
			return ResponseEntity.noContent().build(); // Return no content status
		}
		logger.info("Returning {} applications with unresolved CPE names", applications.size());
		return ResponseEntity.ok(applications);
	}

	// Added: Soft delete computer by UUID
	@DeleteMapping("/computers/{uuid}/soft-delete")
	public ResponseEntity<?> softDeleteComputer(@PathVariable String uuid) {
		logger.info("Received request to soft delete computer with UUID: {}", uuid);
		int status = computerService.softDeleteComputer(uuid);
		switch (status) {
		case 1:
			logger.info("Computer soft deleted successfully");
			return ResponseEntity.ok(new StatusMessageDTO(CVSSEnum.COMPUTER_SOFT_DELETED.getStatusCode(),
					StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_SOFT_DELETED)));
		case -1:
			logger.warn("Computer not found for UUID: {}", uuid);
			return ResponseEntity.status(HttpStatus.NOT_FOUND)
					.body(new ErrorMessageDTO(CVSSEnum.COMPUTER_NOT_FOUND.getStatusCode(),
							StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_NOT_FOUND)));
		case -2:
			logger.warn("Computer already soft deleted for UUID: {}", uuid);
			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
					.body(new ErrorMessageDTO(CVSSEnum.COMPUTER_ALREADY_DELETED.getStatusCode(),
							StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_ALREADY_DELETED)));
		default:
			logger.error("Unexpected error during soft delete for UUID: {}", uuid);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(new ErrorMessageDTO(CVSSEnum.Internal_Server_Error.getStatusCode(),
							StatusMessageUtil.getMessage(CVSSEnum.Internal_Server_Error)));
		}
	}

	// Added: Revert soft delete computer by UUID
	@PatchMapping("/computers/{uuid}/revert-soft-delete")
	public ResponseEntity<?> revertSoftDeleteComputer(
			@PathVariable @NotBlank(message = "UUID cannot be blank") String uuid) {
		logger.info("Received request to revert soft delete for computer with UUID: {}", uuid);
		int status = computerService.revertSoftDeleteComputer(uuid);
		switch (status) {
		case 1:
			logger.info("Computer soft delete reverted successfully");
			return ResponseEntity.ok(new StatusMessageDTO(CVSSEnum.COMPUTER_REVERT_SOFT_DELETE.getStatusCode(),
					StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_REVERT_SOFT_DELETE)));
		case -1:
			logger.warn("Computer not found for UUID: {}", uuid);
			return ResponseEntity.status(HttpStatus.NOT_FOUND)
					.body(new ErrorMessageDTO(CVSSEnum.COMPUTER_NOT_FOUND.getStatusCode(),
							StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_NOT_FOUND)));
		case -2:
			logger.warn("Computer not soft deleted for UUID: {}", uuid);
			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
					.body(new ErrorMessageDTO(CVSSEnum.COMPUTER_NOT_DELETED.getStatusCode(),
							StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_NOT_DELETED)));
		default:
			logger.error("Unexpected error during revert soft delete for UUID: {}", uuid);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(new ErrorMessageDTO(CVSSEnum.Internal_Server_Error.getStatusCode(),
							StatusMessageUtil.getMessage(CVSSEnum.Internal_Server_Error)));
		}
	}

	// Added: Activate computer by UUID
	@PatchMapping("/computers/{uuid}/activate")
	public ResponseEntity<?> activateComputer(@PathVariable String uuid) {
		logger.info("Received request to activate computer with UUID: {}", uuid);
		int status = computerService.activateComputer(uuid);
		switch (status) {
		case 1:
			logger.info("Computer activated successfully");
			return ResponseEntity.ok(new StatusMessageDTO(CVSSEnum.COMPUTER_ACTIVATED.getStatusCode(),
					StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_ACTIVATED)));
		case -1:
			logger.warn("Computer not found for UUID: {}", uuid);
			return ResponseEntity.status(HttpStatus.NOT_FOUND)
					.body(new ErrorMessageDTO(CVSSEnum.COMPUTER_NOT_FOUND.getStatusCode(),
							StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_NOT_FOUND)));
		case -2:
			logger.warn("Computer already active for UUID: {}", uuid);
			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
					.body(new ErrorMessageDTO(CVSSEnum.COMPUTER_ALREADY_ACTIVE.getStatusCode(),
							StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_ALREADY_ACTIVE)));
		case -3:
			logger.warn("Computer is soft deleted for UUID: {}", uuid);
			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
					.body(new ErrorMessageDTO(CVSSEnum.COMPUTER_DELETED.getStatusCode(),
							StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_DELETED)));
		default:
			logger.error("Unexpected error during activation for UUID: {}", uuid);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(new ErrorMessageDTO(CVSSEnum.Internal_Server_Error.getStatusCode(),
							StatusMessageUtil.getMessage(CVSSEnum.Internal_Server_Error)));
		}
	}

	// Added: Deactivate computer by UUID
	@PatchMapping("/computers/{uuid}/deactivate")
	public ResponseEntity<?> deactivateComputer(@PathVariable String uuid) {
		logger.info("Received request to deactivate computer with UUID: {}", uuid);
		int status = computerService.deactivateComputer(uuid);
		switch (status) {
		case 1:
			logger.info("Computer deactivated successfully");
			return ResponseEntity.ok(new StatusMessageDTO(CVSSEnum.COMPUTER_DEACTIVATED.getStatusCode(),
					StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_DEACTIVATED)));
		case -1:
			logger.warn("Computer not found for UUID: {}", uuid);
			return ResponseEntity.status(HttpStatus.NOT_FOUND)
					.body(new ErrorMessageDTO(CVSSEnum.COMPUTER_NOT_FOUND.getStatusCode(),
							StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_NOT_FOUND)));
		case -2:
			logger.warn("Computer already deactivated for UUID: {}", uuid);
			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
					.body(new ErrorMessageDTO(CVSSEnum.COMPUTER_ALREADY_DEACTIVATED.getStatusCode(),
							StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_ALREADY_DEACTIVATED)));
		case -3:
			logger.warn("Computer is soft deleted for UUID: {}", uuid);
			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
					.body(new ErrorMessageDTO(CVSSEnum.COMPUTER_DELETED.getStatusCode(),
							StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_DELETED)));
		default:
			logger.error("Unexpected error during deactivation for UUID: {}", uuid);
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
					.body(new ErrorMessageDTO(CVSSEnum.Internal_Server_Error.getStatusCode(),
							StatusMessageUtil.getMessage(CVSSEnum.Internal_Server_Error)));
		}
	}

	// Added: List computers by deletion status
	@GetMapping("/computers/by-deletion-status")
	public ResponseEntity<?> getComputersByDeletionStatus(@RequestParam(required = false) String status) {
		logger.info("Received request to fetch computers with deletion status: {}", status);
		if (status != null && !status.equals("true") && !status.equals("false")) {
			logger.warn("Invalid deletion status provided: {}", status);
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorMessageDTO(
					CVSSEnum.INVALID_STATUS.getStatusCode(), StatusMessageUtil.getMessage(CVSSEnum.INVALID_STATUS)));
		}
		Boolean isDeleted = status == null ? null : Boolean.parseBoolean(status);
		List<Computer> computers = computerService.getComputersByDeletionStatus(isDeleted);
		if (computers.isEmpty()) { // Check if the list is empty
			return ResponseEntity.noContent().build(); // Return no content status
		}
		logger.info("Returning {} computers for deletion status: {}", computers.size(), isDeleted);
		return ResponseEntity.ok(computers);
	}

	// Added: List computers by activation status
	@GetMapping("/computers/by-activation-status")
	public ResponseEntity<?> getComputersByActivationStatus(@RequestParam(required = false) String status) {
		logger.info("Received request to fetch computers with activation status: {}", status);
		if (status != null && !status.equals("true") && !status.equals("false")) {
			logger.warn("Invalid activation status provided: {}", status);
			return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(new ErrorMessageDTO(
					CVSSEnum.INVALID_STATUS.getStatusCode(), StatusMessageUtil.getMessage(CVSSEnum.INVALID_STATUS)));
		}
		Boolean isActive = status == null ? null : Boolean.parseBoolean(status); // Default to true (active)
		List<Computer> computers = computerService.getComputersByActivationStatus(isActive);
		if (computers.isEmpty()) { // Check if the list is empty
			return ResponseEntity.noContent().build(); // Return no content status
		}
		logger.info("Returning {} computers for activation status: {}", computers.size(), isActive);
		return ResponseEntity.ok(computers);
	}
}