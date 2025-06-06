package com.isteer.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.isteer.dto.ErrorMessageDto;
import com.isteer.dto.StatusMessageDto;
import com.isteer.entity.Dependency;
import com.isteer.enums.CVSSEnum;
import com.isteer.service.DependencyService;
import com.isteer.util.StatusMessageUtil;

import java.util.List;

@RestController
@RequestMapping("/api") // Base URL for all endpoints in this controller
public class DependencyController {

    @Autowired
    DependencyService dependencyService; // Service layer for business logic

    @Autowired
    StatusMessageUtil statusMessageUtil; // Utility for status messages

    @PostMapping("/dependency") // Endpoint to create a new dependency
    public ResponseEntity<?> createDependency(@RequestParam String applicationUuid,
                                              @RequestBody Dependency dependency) {
        // Call service method to create dependency
        int status = dependencyService.createDependency(applicationUuid, dependency);

        // Handle different status codes returned by the service
        switch (status) {
            case 1: // Dependency created successfully
                StatusMessageDto createdMsg = new StatusMessageDto(CVSSEnum.DEPENDENCY_ADD.getStatusCode(),
                        StatusMessageUtil.getMessage(CVSSEnum.DEPENDENCY_ADD));
                return ResponseEntity.status(HttpStatus.OK).body(createdMsg);
            case -1: // Application not found
                ErrorMessageDto notFoundMsg = new ErrorMessageDto(CVSSEnum.APPLICATION_NOT_FOUND.getStatusCode(),
                        StatusMessageUtil.getMessage(CVSSEnum.APPLICATION_NOT_FOUND));
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(notFoundMsg);
            case -2: // Application UUID is empty
                ErrorMessageDto uuidEmptyMsg = new ErrorMessageDto(CVSSEnum.APPLICATION_UUID_EMPTY.getStatusCode(),
                        StatusMessageUtil.getMessage(CVSSEnum.APPLICATION_UUID_EMPTY));
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(uuidEmptyMsg);
            case -4: // Dependency already exists or application is not active
                ErrorMessageDto dependencyExistsMsg = new ErrorMessageDto(
                        CVSSEnum.APPLICATION_NOT_ACTIVE.getStatusCode(),
                        StatusMessageUtil.getMessage(CVSSEnum.APPLICATION_NOT_ACTIVE));
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(dependencyExistsMsg);
            default: // Internal server error
                ErrorMessageDto errorMsg = new ErrorMessageDto(CVSSEnum.Internal_Server_Error.getStatusCode(),
                        StatusMessageUtil.getMessage(CVSSEnum.Internal_Server_Error));
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorMsg);
        }
    }

    @GetMapping("/dependencies") // Endpoint to fetch all dependencies
    public ResponseEntity<List<Dependency>> getAllDependencies() {
        // Fetch all dependencies from the service
        List<Dependency> dependencies = dependencyService.getAllDependencies();

        // Return no content if the list is empty
        if (dependencies.isEmpty()) {
            return ResponseEntity.noContent().build();
        }
        return ResponseEntity.ok(dependencies); // Return the list of dependencies
    }

    @GetMapping("/uuid/dependency") // Endpoint to fetch a dependency by UUID
    public ResponseEntity<?> getDependencyByUuid(@RequestParam String dependencyUuid) {
        // Fetch dependency by UUID from the service
        Dependency dependency = dependencyService.getDependencyByUuid(dependencyUuid);
        if (dependency == null) { // If dependency is not found
            ErrorMessageDto message = new ErrorMessageDto(CVSSEnum.DEPENDENCY_NOT_FOUND.getStatusCode(),
                    StatusMessageUtil.getMessage(CVSSEnum.DEPENDENCY_NOT_FOUND));
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(message);
        }

        return ResponseEntity.ok(dependency); // Return the found dependency
    }

    @PutMapping("/dependency") // Endpoint to update a dependency
    public ResponseEntity<?> updateDependency(@RequestParam String dependencyUuid, @RequestBody Dependency dependency) {
        // Call service method to update dependency
        int status = dependencyService.updateDependency(dependencyUuid, dependency);

        // Handle different status codes returned by the service
        switch (status) {
            case 1: // Dependency updated successfully
                StatusMessageDto updateMsg = new StatusMessageDto(CVSSEnum.DEPENDENCY_UPDATE.getStatusCode(),
                        StatusMessageUtil.getMessage(CVSSEnum.DEPENDENCY_UPDATE));
                return ResponseEntity.ok(updateMsg);
            case -1: // Dependency not found
                ErrorMessageDto notFoundMsg = new ErrorMessageDto(CVSSEnum.DEPENDENCY_NOT_FOUND.getStatusCode(),
                        StatusMessageUtil.getMessage(CVSSEnum.DEPENDENCY_NOT_FOUND));
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(notFoundMsg);
            case -2: // Dependency UUID is empty
                ErrorMessageDto uuidEmptyMsg = new ErrorMessageDto(CVSSEnum.DEPENDENCY_UUID_EMPTY.getStatusCode(),
                        StatusMessageUtil.getMessage(CVSSEnum.DEPENDENCY_UUID_EMPTY));
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(uuidEmptyMsg);
            default: // Internal server error
                ErrorMessageDto errorMsg = new ErrorMessageDto(CVSSEnum.Internal_Server_Error.getStatusCode(),
                        StatusMessageUtil.getMessage(CVSSEnum.Internal_Server_Error));
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorMsg);
        }
    }

    @DeleteMapping("/dependency") // Endpoint to delete a dependency
    public ResponseEntity<?> deleteDependency(@RequestParam String dependencyUuid) {
        // Call service method to delete dependency
        int status = dependencyService.softDeleteDependency(dependencyUuid);

        // Handle different status codes returned by the service
        switch (status) {
            case 1: // Dependency deleted successfully
                StatusMessageDto deleteMsg = new StatusMessageDto(CVSSEnum.DEPENDENCY_DELETE.getStatusCode(),
                        StatusMessageUtil.getMessage(CVSSEnum.DEPENDENCY_DELETE));
                return ResponseEntity.status(HttpStatus.OK).body(deleteMsg);
            case -2: // Dependency UUID is empty
                ErrorMessageDto uuidEmptyMsg = new ErrorMessageDto(CVSSEnum.DEPENDENCY_UUID_EMPTY.getStatusCode(),
                        StatusMessageUtil.getMessage(CVSSEnum.DEPENDENCY_UUID_EMPTY));
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(uuidEmptyMsg);
            case -1: // Dependency not found
                ErrorMessageDto notFoundMsg = new ErrorMessageDto(CVSSEnum.DEPENDENCY_NOT_FOUND.getStatusCode(),
                        StatusMessageUtil.getMessage(CVSSEnum.DEPENDENCY_NOT_FOUND));
                return ResponseEntity.status(HttpStatus.NOT_FOUND).body(notFoundMsg);
            default: // Internal server error
                ErrorMessageDto errorMsg = new ErrorMessageDto(CVSSEnum.Internal_Server_Error.getStatusCode(),
                        StatusMessageUtil.getMessage(CVSSEnum.Internal_Server_Error));
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(errorMsg);
        }
    }
}
// This code defines a REST controller for managing dependencies in an application.