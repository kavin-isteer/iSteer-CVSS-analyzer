package com.isteer.service;

import java.util.List;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.isteer.entity.Computer;
import com.isteer.repository.ApplicationRepository;
import com.isteer.repository.ComputerRepository;
import com.isteer.repository.DependencyRepository;
import com.isteer.repository.VulnerabilityRepository;

@Service
public class ComputerService {
    // Logger instance for logging messages during execution
    private static final Logger logger = LoggerFactory.getLogger(ComputerService.class);

    // Regular expression pattern to validate IP addresses (IPv4 format)
    private static final Pattern IP_PATTERN = Pattern
            .compile("^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");

    // Autowired repositories for performing database operations
    @Autowired
    ComputerRepository computerRepository; // Repository for Computer entity
    @Autowired
    ApplicationRepository applicationRepository; // Repository for Application entity
    @Autowired
    DependencyRepository dependencyRepository; // Repository for Dependency entity
    @Autowired
    VulnerabilityRepository vulnerabilityRepository; // Repository for Vulnerability entity

    /**
     * Creates a new computer record in the database.
     * Validates the IP address before saving.
     *
     * @param computer The computer entity to be saved.
     * @return Status code indicating success or failure.
     */
    public int createMachine(Computer computer) {
        // Validate IP address format using the defined pattern
        if (computer.getIpAddress() == null || !IP_PATTERN.matcher(computer.getIpAddress()).matches()) {
            logger.error("Invalid IP address: {}", computer.getIpAddress()); // Log error for invalid IP
            return -4; // Return error code for invalid IP address
        }
        logger.info("Creating machine with IP: {}", computer.getIpAddress()); // Log the creation process
        return computerRepository.save(computer); // Save the computer entity to the database
    }

    /**
     * Fetches all computers from the database without any hierarchy.
     *
     * @return List of all computers.
     */
    public List<Computer> getAllComputers() {
        logger.info("Fetching all computers (no hierarchy)"); // Log the fetch operation
        return computerRepository.findAll(); // Retrieve all computer records from the database
    }

    /**
     * Finds a computer by its UUID, including full hierarchy (joined data).
     *
     * @param uuid The UUID of the computer.
     * @return The computer entity or null if not found.
     */
    public Computer findComputerByUuid(String uuid) {
        logger.info("Fetching computer with UUID: {} including full hierarchy (joined).", uuid); // Log the fetch operation

        // Validate UUID input to ensure it is not null or empty
        if (uuid == null || uuid.trim().isEmpty()) {
            logger.warn("UUID is empty. Returning null."); // Log warning for empty UUID
            return null; // Return null for invalid UUID
        }

        return computerRepository.computerByUuid(uuid); // Fetch computer by UUID from the database
    }

    /**
     * Updates an existing computer record based on its UUID.
     * Validates the UUID and IP address before updating.
     *
     * @param uuid The UUID of the computer to be updated.
     * @param computer The updated computer entity.
     * @return Status code indicating success or failure.
     */
    public int updateMachine(String uuid, Computer computer) {
        // Validate UUID input to ensure it is not null or empty
        if (uuid == null || uuid.trim().isEmpty()) {
            return -3; // Return error code for empty UUID
        }
        // Validate IP address format using the defined pattern
        if (computer.getIpAddress() == null || !IP_PATTERN.matcher(computer.getIpAddress()).matches()) {
            logger.error("Invalid IP address: {}", computer.getIpAddress()); // Log error for invalid IP
            return -2; // Return error code for invalid IP address
        }
        // Check if the computer exists in the database
        if (computerRepository.findByUuid(uuid) == null) {
            return -1; // Return error code for computer not found
        }

        logger.info("Updating machine with UUID: {}", uuid); // Log the update process
        int rowsUpdated = computerRepository.update(uuid, computer); // Perform update operation in the database
        if (rowsUpdated == 0) {
            logger.warn("No active computer found for UUID: {}", uuid); // Log warning for inactive computer
            return -5; // Return error code for inactive computer
        }
        return 1; // Return success code for update operation
    }

    /**
     * Soft deletes a computer record by marking it inactive.
     *
     * @param uuid The UUID of the computer to be soft deleted.
     * @return Status code indicating success or failure.
     */
    public int softDeleteComputer(String uuid) {
        // Validate UUID input to ensure it is not null or empty
        if (uuid == null || uuid.trim().isEmpty()) {
            return -2; // Return error code for empty UUID
        }
        // Check if the computer exists in the database
        if (computerRepository.findByUuid(uuid) == null) {
            return -1; // Return error code for computer not found
        }
        logger.info("Soft deleting machine with UUID: {}", uuid); // Log the soft delete process
        return computerRepository.softDelete(uuid); // Perform soft delete operation in the database
    }

    /**
     * Deactivates a computer record by marking it inactive.
     *
     * @param uuid The UUID of the computer to be deactivated.
     * @return Status code indicating success or failure.
     */
    public int deactivateComputers(String uuid) {
        // Validate UUID input to ensure it is not null or empty
        if (uuid == null || uuid.trim().isEmpty()) {
            return -2; // Return error code for empty UUID
        }
        // Check if the computer exists in the database
        if (computerRepository.findByUuid(uuid) == null) {
            return -1; // Return error code for computer not found
        }
        logger.info("Deactivating machine with UUID: {}", uuid); // Log the deactivation process
        return computerRepository.deactivate(uuid); // Perform deactivation operation in the database
    }

    /**
     * Activates a computer record by marking it active.
     *
     * @param uuid The UUID of the computer to be activated.
     * @return Status code indicating success or failure.
     */
    public int activateComputers(String uuid) {
        // Validate UUID input to ensure it is not null or empty
        if (uuid == null || uuid.trim().isEmpty()) {
            return -2; // Return error code for empty UUID
        }

        int updatedRows = computerRepository.activateComputer(uuid); // Perform activation operation in the database

        if (updatedRows > 0) {
            return 1; // Return success code for activation
        }

        // Check if the computer exists in the database
        if (computerRepository.findByUuid(uuid) == null) {
            return -1; // Return error code for computer not found
        }

        return 0; // Return code indicating the computer is already active
    }

    /**
     * Fetches all active computers from the database.
     *
     * @return List of active computers.
     */
    public List<Computer> getActiveComputers() {
        logger.info("Fetching all active machines"); // Log the fetch operation
        return computerRepository.findAll().stream()
                .filter(Computer::isActive) // Filter active computers using the `isActive` method
                .collect(Collectors.toList()); // Collect the filtered results into a list
    }

    /**
     * Fetches all inactive computers from the database.
     *
     * @return List of inactive computers.
     */
    public List<Computer> getInactiveComputers() {
        logger.info("Fetching all inactive machines"); // Log the fetch operation
        return computerRepository.findAll().stream()
                .filter(computer -> !computer.isActive()) // Filter inactive computers using the negation of `isActive`
                .collect(Collectors.toList()); // Collect the filtered results into a list
    }
}
