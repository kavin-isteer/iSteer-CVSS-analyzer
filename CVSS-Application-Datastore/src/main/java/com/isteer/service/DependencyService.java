package com.isteer.service;

import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.isteer.entity.Dependency;
import com.isteer.repository.ApplicationRepository;
import com.isteer.repository.DependencyRepository;
import com.isteer.repository.VulnerabilityRepository;

@Service
public class DependencyService {
    // Logger instance for logging messages
    private static final Logger logger = LoggerFactory.getLogger(DependencyService.class);

    // Autowired repositories for database operations
    @Autowired
    DependencyRepository dependencyRepository; // Repository for Dependency entity
    @Autowired
    ApplicationRepository applicationRepository; // Repository for Application entity
    @Autowired
    VulnerabilityRepository vulnerabilityRepository; // Repository for Vulnerability entity

    /**
     * Creates a new dependency for a given application.
     * @param applicationId The UUID of the application.
     * @param dependency The dependency object to be created.
     * @return Status code indicating success or failure.
     */
    public int createDependency(String applicationId, Dependency dependency) {
        // Validate application ID is not null or empty
        if (applicationId == null || applicationId.trim().isEmpty()) {
            return -2; // Return error code for empty application ID
        }

        // Check if the application exists in the database
        if (applicationRepository.findByUuid(applicationId) == null) {
            return -1; // Return error code if application does not exist
        }

        // Set the application UUID in the dependency object
        dependency.setApplicationUuid(applicationId);

        // Log the creation of the dependency
        logger.info("Creating dependency: {}", dependency.getName());

        // Save the dependency to the database and return the result
        return dependencyRepository.save(dependency);
    }

    /**
     * Fetches all dependencies from the database.
     * @return List of all dependencies.
     */
    public List<Dependency> getAllDependencies() {
        // Log the fetch operation
        logger.info("Fetching all dependencies");

        // Retrieve all dependencies from the repository
        return dependencyRepository.findAll();
    }

    /**
     * Fetches a dependency by its UUID.
     * @param uuid The UUID of the dependency.
     * @return The dependency object or null if not found.
     */
    public Dependency getDependencyByUuid(String uuid) {
        // Validate UUID is not null or empty
        if (uuid == null || uuid.trim().isEmpty()) {
            return null; // Return null for empty UUID
        }

        // Log the fetch operation
        logger.info("Fetching dependency with UUID: {}", uuid);

        // Retrieve the dependency from the repository
        return dependencyRepository.findByDependencyUuid(uuid);
    }

    /**
     * Updates an existing dependency.
     * @param uuid The UUID of the dependency to be updated.
     * @param dependency The updated dependency object.
     * @return Status code indicating success or failure.
     */
    public int updateDependency(String uuid, Dependency dependency) {
        // Validate UUID is not null or empty
        if (uuid == null || uuid.trim().isEmpty()) {
            return -2; // Return error code for empty UUID
        }

        // Check if the dependency exists in the database
        if (dependencyRepository.findByUuid(uuid) == null) {
            return -1; // Return error code if dependency not found
        }

        // Log the update operation
        logger.info("Updating dependency with UUID: {}", uuid);

        // Update the dependency in the database and return the result
        return dependencyRepository.update(uuid, dependency);
    }

    /**
     * Soft deletes a dependency by marking it inactive.
     * @param uuid The UUID of the dependency to be deleted.
     * @return Status code indicating success or failure.
     */
    public int softDeleteDependency(String uuid) {
        // Validate UUID is not null or empty
        if (uuid == null || uuid.trim().isEmpty()) {
            return -2; // Return error code for empty UUID
        }

        // Check if the dependency exists in the database
        if (dependencyRepository.findByUuid(uuid) == null) {
            return -1; // Return error code if dependency not found
        }

        // Log the soft delete operation
        logger.info("Soft deleting dependency with UUID: {}", uuid);

        // Perform the soft delete operation and return the result
        return dependencyRepository.softDelete(uuid);
    }
}
