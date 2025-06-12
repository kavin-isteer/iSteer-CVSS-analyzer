//package com.isteer.controller;
//
//import java.util.List;
//
//import org.springframework.beans.factory.annotation.Autowired;
//import org.springframework.http.HttpStatus;
//import org.springframework.http.ResponseEntity;
//import org.springframework.web.bind.annotation.DeleteMapping;
//import org.springframework.web.bind.annotation.GetMapping;
//import org.springframework.web.bind.annotation.PostMapping;
//import org.springframework.web.bind.annotation.PutMapping;
//import org.springframework.web.bind.annotation.RequestBody;
//import org.springframework.web.bind.annotation.RequestMapping;
//import org.springframework.web.bind.annotation.RequestParam;
//import org.springframework.web.bind.annotation.RestController;
//
//import com.isteer.dto.ErrorMessageDto;
//import com.isteer.dto.StatusMessageDto;
//import com.isteer.entity.Application;
//import com.isteer.enums.CVSSEnum;
//import com.isteer.service.ApplicationService;
//import com.isteer.util.StatusMessageUtil;
//
//import jakarta.validation.Valid;
//
//@RestController
//@RequestMapping("/api") // Base URL for all endpoints in this controller
//public class ApplicationController {
//
//	@Autowired
//	ApplicationService applicationService; // Service layer dependency for business logic
//
//	
//	
//	@Autowired
//	StatusMessageUtil statusMessageUtil; // Utility for status messages
//
//	@PostMapping("/application") // Endpoint to create a new application
//	public ResponseEntity<?> createApplication(@RequestParam String computerUuid, @Valid @RequestBody Application application) {
//		// Call service method to create application
//		int status = applicationService.createApplication(computerUuid, application);
//		switch (status) {
//		case 1:
//			// Return success response if application is created
//			return ResponseEntity.status(HttpStatus.OK).body(new StatusMessageDto(
//					CVSSEnum.APPLICATION_ADD.getStatusCode(), StatusMessageUtil.getMessage(CVSSEnum.APPLICATION_ADD)));
//		case -1:
//			// Return error response if computer is not found
//			return ResponseEntity.status(HttpStatus.NOT_FOUND)
//					.body(new ErrorMessageDto(CVSSEnum.COMPUTER_NOT_FOUND.getStatusCode(),
//							StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_NOT_FOUND)));
//		case -3:
//			// Return error response if computer UUID is empty
//			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
//					.body(new ErrorMessageDto(CVSSEnum.COMPUTER_UUID_EMPTY.getStatusCode(),
//							StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_UUID_EMPTY)));
//		case -4:
//			// Return error response if computer is inactive
//			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
//					.body(new ErrorMessageDto(CVSSEnum.COMPUTER_INACTIVE.getStatusCode(),
//							StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_INACTIVE)));
//		default:
//			// Return generic error response for unexpected cases
//			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
//					.body(new ErrorMessageDto(CVSSEnum.Internal_Server_Error.getStatusCode(),
//							StatusMessageUtil.getMessage(CVSSEnum.Internal_Server_Error)));
//		}
//	}
//
//	@GetMapping("/applications") // Endpoint to fetch all applications
//	public ResponseEntity<List<Application>> getAllApplications() {
//		// Call service method to retrieve all applications
//		List<Application> application = applicationService.getAllApplications();
//		if (application.isEmpty()) {
//			// Return no content response if no applications are found
//			return ResponseEntity.status(HttpStatus.NO_CONTENT).build();
//		}
//		// Return list of applications
//		return ResponseEntity.ok(application);
//	}
//	
//	@GetMapping("/uuid/application") // Endpoint to fetch application by UUID
//	public ResponseEntity<?> getApplicationByUuid(@RequestParam String applicationUuid) {
//		// Call service method to retrieve application by UUID
//		Application application = applicationService.getApplicationByUuid(applicationUuid);
//		if (application == null) {
//			// Return error response if application is not found
//			return ResponseEntity.status(HttpStatus.NOT_FOUND)
//					.body(new ErrorMessageDto(CVSSEnum.APPLICATION_NOT_FOUND.getStatusCode(),
//							StatusMessageUtil.getMessage(CVSSEnum.APPLICATION_NOT_FOUND)));
//		}
//		// Return application details
//		return ResponseEntity.ok(application);
//	}
//
//	@PutMapping("/application") // Endpoint to update an application
//	public ResponseEntity<?> updateApplication(@RequestParam String applicationUuid, @Valid @RequestBody Application application) {
//		// Call service method to update application
//		int status = applicationService.updateApplication(applicationUuid, application);
//		switch (status) {
//		case 1:
//			// Return success response if application is updated
//			return ResponseEntity.ok(new StatusMessageDto(CVSSEnum.APPLICATION_UPDATE.getStatusCode(),
//					StatusMessageUtil.getMessage(CVSSEnum.APPLICATION_UPDATE)));
//		case -1:
//			// Return error response if application is not found
//			return ResponseEntity.status(HttpStatus.NOT_FOUND)
//					.body(new ErrorMessageDto(CVSSEnum.APPLICATION_NOT_FOUND.getStatusCode(),
//							StatusMessageUtil.getMessage(CVSSEnum.APPLICATION_NOT_FOUND)));
//		case -2:
//			// Return error response if application UUID is empty
//			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
//					.body(new ErrorMessageDto(CVSSEnum.APPLICATION_UUID_EMPTY.getStatusCode(),
//							StatusMessageUtil.getMessage(CVSSEnum.APPLICATION_UUID_EMPTY)));
//		case -4:
//			// Return error response if computer is inactive
//			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
//					.body(new ErrorMessageDto(CVSSEnum.COMPUTER_INACTIVE.getStatusCode(),
//							StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_INACTIVE)));
//		default:
//			// Return generic error response for unexpected cases
//			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
//					.body(new ErrorMessageDto(CVSSEnum.Internal_Server_Error.getStatusCode(),
//							StatusMessageUtil.getMessage(CVSSEnum.Internal_Server_Error)));
//		}
//	}
//	
//	@DeleteMapping("/application") // Endpoint to delete an application
//	public ResponseEntity<?> deleteApplication(@RequestParam String applicationUuid) {
//		// Call service method to soft delete application
//		int status = applicationService.softDeleteApplication(applicationUuid);
//		switch (status) {
//		case 1:
//			// Return success response if application is deleted
//			return ResponseEntity.ok(new StatusMessageDto(CVSSEnum.APPLICATION_DELETE.getStatusCode(),
//					StatusMessageUtil.getMessage(CVSSEnum.APPLICATION_DELETE)));
//		case -1:
//			// Return error response if application is not found
//			return ResponseEntity.status(HttpStatus.NOT_FOUND)
//					.body(new ErrorMessageDto(CVSSEnum.APPLICATION_NOT_FOUND.getStatusCode(),
//							StatusMessageUtil.getMessage(CVSSEnum.APPLICATION_NOT_FOUND)));
//		case -2:
//			// Return error response if application UUID is empty
//			return ResponseEntity.status(HttpStatus.BAD_REQUEST)
//					.body(new ErrorMessageDto(CVSSEnum.APPLICATION_UUID_EMPTY.getStatusCode(),
//							StatusMessageUtil.getMessage(CVSSEnum.APPLICATION_UUID_EMPTY)));
//		default:
//			// Return generic error response for unexpected cases
//			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
//					.body(new ErrorMessageDto(CVSSEnum.Internal_Server_Error.getStatusCode(),
//							StatusMessageUtil.getMessage(CVSSEnum.Internal_Server_Error)));
//		}
//	}
//}