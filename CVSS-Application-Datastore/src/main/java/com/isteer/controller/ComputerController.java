// File: ComputerController.java
package com.isteer.controller;

import jakarta.validation.Valid;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.isteer.dto.ErrorMessageDto;
import com.isteer.dto.StatusMessageDto;
import com.isteer.entity.Computer;
import com.isteer.enums.CVSSEnum;
import com.isteer.service.ComputerService;
import com.isteer.util.StatusMessageUtil;

import java.util.List;

@RestController
@RequestMapping("/api")
public class ComputerController {

    @Autowired
    ComputerService computerService; // Injecting the ComputerService dependency

    @Autowired
    StatusMessageUtil statusMessageUtil; // Injecting the StatusMessageUtil dependency

    // Endpoint to create a new computer
    @PostMapping("/computer")
    public ResponseEntity<?> createMachine(@Valid @RequestBody Computer computer) {
        int status = computerService.createMachine(computer); // Call service to create a computer

        switch (status) {
            case 1: // Success case
                return ResponseEntity.status(HttpStatus.OK).body(new StatusMessageDto(
                        CVSSEnum.COMPUTER_ADD.getStatusCode(), StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_ADD)));
            case -4: // Invalid IP address case
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new ErrorMessageDto(CVSSEnum.IP_ADDRESS_INVALID.getStatusCode(),
                                StatusMessageUtil.getMessage(CVSSEnum.IP_ADDRESS_INVALID)));
            default: // Internal server error case
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(new ErrorMessageDto(CVSSEnum.Internal_Server_Error.getStatusCode(),
                                StatusMessageUtil.getMessage(CVSSEnum.Internal_Server_Error)));
        }
    }

    // Endpoint to fetch all computers
    @GetMapping("/allComputers")
    public ResponseEntity<?> getAllComputers() {
        List<Computer> machines = computerService.getAllComputers(); // Fetch all computers

        if (machines.isEmpty()) { // Check if the list is empty
            return ResponseEntity.noContent().build(); // Return no content status
        }

        return ResponseEntity.ok(machines); // Return the list of computers
    }

    // Endpoint to fetch a computer by UUID
    @GetMapping("/uuid/computer")
    public ResponseEntity<?> getComputerByUuid(@RequestParam String computerUuid) {
        Computer computer = computerService.findComputerByUuid(computerUuid); // Fetch computer by UUID

        if (computer == null || computerUuid.trim().isEmpty()) { // Check if computer is not found or UUID is empty
            return ResponseEntity.status(HttpStatus.NOT_FOUND)
                    .body(new ErrorMessageDto(CVSSEnum.COMPUTER_NOT_FOUND.getStatusCode(),
                            StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_NOT_FOUND)));
        } else if (computer.getUuid() == null || computer.getUuid().trim().isEmpty()) { // Check if UUID is empty
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                    .body(new ErrorMessageDto(CVSSEnum.COMPUTER_UUID_EMPTY.getStatusCode(),
                            StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_UUID_EMPTY)));
        }

        return ResponseEntity.ok(computer); // Return the computer details
    }

    // Endpoint to update a computer
    @PutMapping("computer")
    public ResponseEntity<?> updateMachine(@RequestParam String computerUuid, @Valid @RequestBody Computer computer) {
        int status = computerService.updateMachine(computerUuid, computer); // Call service to update computer

        switch (status) {
            case 1: // Success case
                return ResponseEntity.status(HttpStatus.OK).body(new StatusMessageDto(CVSSEnum.COMPUTER_ADD.getStatusCode(),
                        StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_UPDATE)));
            case -1: // Computer not found case
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(new ErrorMessageDto(CVSSEnum.COMPUTER_NOT_FOUND.getStatusCode(),
                                StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_NOT_FOUND)));
            case -2: // Invalid IP address case
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new ErrorMessageDto(CVSSEnum.IP_ADDRESS_INVALID.getStatusCode(),
                                StatusMessageUtil.getMessage(CVSSEnum.IP_ADDRESS_INVALID)));
            case -3: // Empty UUID case
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new ErrorMessageDto(CVSSEnum.COMPUTER_UUID_EMPTY.getStatusCode(),
                                StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_UUID_EMPTY)));
            case -5: // Inactive computer case
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new ErrorMessageDto(CVSSEnum.COMPUTER_INACTIVE.getStatusCode(),
                                StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_INACTIVE)));
            default: // Internal server error case
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(new ErrorMessageDto(CVSSEnum.Internal_Server_Error.getStatusCode(),
                                StatusMessageUtil.getMessage(CVSSEnum.Internal_Server_Error)));
        }
    }

    // Endpoint to delete a computer
    @DeleteMapping("/computer")
    public ResponseEntity<?> deleteMachine(@RequestParam String computerUuid) {
        int status = computerService.softDeleteComputer(computerUuid); // Call service to delete computer

        switch (status) {
            case 1: // Success case
                return ResponseEntity.ok(new StatusMessageDto(CVSSEnum.COMPUTER_DELETE.getStatusCode(),
                        StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_DELETE)));
            case -1: // Computer not found case
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(new ErrorMessageDto(CVSSEnum.COMPUTER_NOT_FOUND.getStatusCode(),
                                StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_NOT_FOUND)));
            case -2: // Empty UUID case
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new ErrorMessageDto(CVSSEnum.COMPUTER_UUID_EMPTY.getStatusCode(),
                                StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_UUID_EMPTY)));
            default: // Internal server error case
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(new ErrorMessageDto(CVSSEnum.Internal_Server_Error.getStatusCode(),
                                StatusMessageUtil.getMessage(CVSSEnum.Internal_Server_Error)));
        }
    }

    // Endpoint to deactivate a computer
    @PatchMapping("computer/deactivate")
    public ResponseEntity<?> deactivateMachine(@RequestParam String computerUuid) {
        int status = computerService.deactivateComputers(computerUuid); // Call service to deactivate computer

        switch (status) {
            case 1: // Success case
                return ResponseEntity.ok(new StatusMessageDto(CVSSEnum.COMPUTER_DEACTIVATED.getStatusCode(),
                        StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_DEACTIVATED)));
            case -1: // Computer not found case
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(new ErrorMessageDto(CVSSEnum.COMPUTER_NOT_FOUND.getStatusCode(),
                                StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_NOT_FOUND)));
            case -2: // Empty UUID case
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new ErrorMessageDto(CVSSEnum.COMPUTER_UUID_EMPTY.getStatusCode(),
                                StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_UUID_EMPTY)));
            case 0: // Already deactivated case
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new ErrorMessageDto(CVSSEnum.COMPUTER_ALREADY_DELETED.getStatusCode(),
                                StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_ALREADY_DELETED)));
            default: // Internal server error case
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(new ErrorMessageDto(CVSSEnum.Internal_Server_Error.getStatusCode(),
                                StatusMessageUtil.getMessage(CVSSEnum.Internal_Server_Error)));
        }
    }

    // Endpoint to activate a computer
    @PatchMapping("computer/activate")
    public ResponseEntity<?> activateMachine(@RequestParam String computerUuid) {
        int status = computerService.activateComputers(computerUuid); // Call service to activate computer

        switch (status) {
            case 1: // Success case
                return ResponseEntity.ok(new StatusMessageDto(CVSSEnum.COMPUTER_ACTIVATED.getStatusCode(),
                        StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_ACTIVATED)));
            case -1: // Computer not found case
                return ResponseEntity.status(HttpStatus.NOT_FOUND)
                        .body(new ErrorMessageDto(CVSSEnum.COMPUTER_NOT_FOUND.getStatusCode(),
                                StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_NOT_FOUND)));
            case -2: // Empty UUID case
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new ErrorMessageDto(CVSSEnum.COMPUTER_UUID_EMPTY.getStatusCode(),
                                StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_UUID_EMPTY)));
            case 0: // Already active case
                return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                        .body(new ErrorMessageDto(CVSSEnum.COMPUTER_ALREADY_ACTIVE.getStatusCode(),
                                StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_ALREADY_ACTIVE)));
            default: // Internal server error case
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                        .body(new ErrorMessageDto(CVSSEnum.Internal_Server_Error.getStatusCode(),
                                StatusMessageUtil.getMessage(CVSSEnum.Internal_Server_Error)));
        }
    }

    // Endpoint to fetch all active computers
    @GetMapping("/activeComputers")
    public ResponseEntity<?> getActiveComputers() {
        List<Computer> activeComputers = computerService.getActiveComputers(); // Fetch active computers

        if (activeComputers.isEmpty()) { // Check if the list is empty
            return ResponseEntity.noContent().build(); // Return no content status
        }

        return ResponseEntity.ok(activeComputers); // Return the list of active computers
    }

    // Endpoint to fetch all inactive computers
    @GetMapping("/inactiveComputers")
    public ResponseEntity<?> getInactiveComputers() {
        List<Computer> inactiveComputers = computerService.getInactiveComputers(); // Fetch inactive computers

        if (inactiveComputers.isEmpty()) { // Check if the list is empty
            return ResponseEntity.noContent().build(); // Return no content status
        }

        return ResponseEntity.ok(inactiveComputers); // Return the list of inactive computers
    }
}
