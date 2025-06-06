package com.isteer.service;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.isteer.entity.Application;
import com.isteer.repository.ApplicationRepository;
import com.isteer.repository.ComputerRepository;
import com.isteer.repository.DependencyRepository;
import com.isteer.repository.VulnerabilityRepository;

@Service
public class ApplicationService {
    // Logger instance for logging messages
    private static final Logger logger = LoggerFactory.getLogger(ApplicationService.class);

    // Autowired repositories for database operations
    @Autowired
    ApplicationRepository applicationRepository;
    @Autowired
    ComputerRepository computerRepository;
    @Autowired
    DependencyRepository dependencyRepository;
    @Autowired
    VulnerabilityRepository vulnerabilityRepository;

    /**
     * Creates a new application and associates it with a computer.
     * @param computerId The UUID of the computer to associate the application with.
     * @param application The application object to be created.
     * @return Status code indicating the result of the operation.
     */
    public int createApplication(String computerId, Application application) {
        // Validate computerId input
        if (computerId == null || computerId.trim().isEmpty()) {
            return -3; // Return error code if computer UUID is empty
        }
        // Check if the computer exists in the database
        if (computerRepository.findByUuid(computerId) == null) {
            return -1; // Return error code if computer is not found
        }
        // Set the computer UUID in the application object
        application.setComputerUuid(computerId);
        // Log the creation of the application
        logger.info("Creating application: {}", application.getName());
        // Save the application to the database and return the result
        return applicationRepository.save(application);
    }

    /**
     * Retrieves all applications from the database.
     * @return List of all applications.
     */
    public List<Application> getAllApplications() {
        // Log the fetch operation
        logger.info("Fetching All applications"); 
        // Retrieve and return all applications from the repository
        return applicationRepository.findAll();
    }

    /**
     * Retrieves an application by its UUID.
     * @param uuid The UUID of the application to retrieve.
     * @return The application object if found, otherwise null.
     */
    public Application getApplicationByUuid(String uuid) {
        // Validate UUID input
        if (uuid == null || uuid.trim().isEmpty()) {
            return null; // Return null if UUID is empty
        }
        // Log the fetch operation
        logger.info("Fetching application with UUID: {}", uuid);
        // Retrieve and return the application from the repository
        return applicationRepository.findByApplicationUuid(uuid);
    }

    /**
     * Updates an existing application identified by its UUID.
     * @param uuid The UUID of the application to update.
     * @param application The updated application object.
     * @return Status code indicating the result of the operation.
     */
    public int updateApplication(String uuid, Application application) {
        // Validate UUID input
        if (uuid == null || uuid.trim().isEmpty()) {
            return -2; // Return error code if UUID is empty
        }
        // Check if the application exists in the database
        if (applicationRepository.findByUuid(uuid) == null) {
            return -1; // Return error code if application is not found
        }
        // Log the update operation
        logger.info("Updating application with UUID: {}", uuid);
        // Update the application in the repository
        applicationRepository.update(uuid, application);
        return 1; // Return success code
    }

    /**
     * Soft deletes an application identified by its UUID.
     * @param uuid The UUID of the application to delete.
     * @return Status code indicating the result of the operation.
     */
    public int softDeleteApplication(String uuid) {
        // Validate UUID input
        if (uuid == null || uuid.trim().isEmpty()) {
            return -2; // Return error code if UUID is empty
        }
        // Check if the application exists in the database
        if (applicationRepository.findByUuid(uuid) == null) {
            return -1; // Return error code if application is not found
        }
        // Log the soft delete operation
        logger.info("Soft deleting application with UUID: {}", uuid);
        // Perform the soft delete operation in the repository
        return applicationRepository.softDelete(uuid);
    }
}
