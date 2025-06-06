package com.isteer.util;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.ResultSetExtractor;

import com.isteer.entity.Application;
import com.isteer.entity.Dependency;
import com.isteer.entity.Vulnerability;

public class ApplicationResultSetExtractor implements ResultSetExtractor<Application> {

    @Override
    public Application extractData(ResultSet rs) throws SQLException, DataAccessException {
        // Map to store unique applications by their UUID
        Map<String, Application> appMap = new HashMap<>();
        // Map to store unique dependencies by their UUID
        Map<String, Dependency> depMap = new HashMap<>();

        // Iterate through the result set
        while (rs.next()) {
            // Extract application UUID from the current row
            String appUuid = rs.getString("app_uuid");

            // Retrieve or create a new Application object for the given UUID
            Application application = appMap.computeIfAbsent(appUuid, k -> {
                Application app = new Application();
                try {
                    // Populate Application object with data from the result set
                    app.setId(rs.getLong("app_id")); // Set application ID
                    app.setUuid(appUuid); // Set application UUID
                    app.setComputerUuid(rs.getString("app_computer_uuid")); // Set computer UUID
                    app.setName(rs.getString("app_name")); // Set application name
                    app.setVersion(rs.getString("app_version")); // Set application version
                    app.setVendor(rs.getString("app_vendor")); // Set application vendor
                    app.setInstalledDate(rs.getDate("app_install_date") != null ?
                            rs.getDate("app_install_date").toLocalDate() : null); // Set installation date
                    app.setStatus(rs.getBoolean("app_status")); // Set application status
                    app.setCreatedAt(rs.getTimestamp("app_created_at").toLocalDateTime()); // Set creation timestamp
                    app.setUpdatedAt(rs.getTimestamp("app_updated_at") != null ?
                            rs.getTimestamp("app_updated_at").toLocalDateTime() : null); // Set update timestamp
                    app.setDependencies(new ArrayList<>()); // Initialize dependencies list
                } catch (SQLException e) {
                    // Handle SQL exception during Application mapping
                    throw new RuntimeException("Error mapping Application", e);
                }
                return app; // Return the populated Application object
            });

            // Extract dependency UUID from the current row
            String depUuid = rs.getString("dep_uuid");
            if (depUuid != null && !depMap.containsKey(depUuid)) {
                // Create and populate a new Dependency object if UUID is not already mapped
                Dependency dep = new Dependency();
                dep.setId(rs.getLong("dep_id")); // Set dependency ID
                dep.setUuid(depUuid); // Set dependency UUID
                dep.setApplicationUuid(appUuid); // Associate dependency with application UUID
                dep.setName(rs.getString("dep_name")); // Set dependency name
                dep.setVersion(rs.getString("dep_version")); // Set dependency version
                dep.setGroupId(rs.getString("dep_group_id")); // Set dependency group ID
                dep.setArtifactId(rs.getString("dep_artifact_id")); // Set dependency artifact ID
                dep.setStatus(rs.getBoolean("dep_status")); // Set dependency status
                dep.setCreatedAt(rs.getTimestamp("dep_created_at").toLocalDateTime()); // Set creation timestamp
                dep.setUpdatedAt(rs.getTimestamp("dep_updated_at") != null ?
                        rs.getTimestamp("dep_updated_at").toLocalDateTime() : null); // Set update timestamp
                dep.setVulnerabilities(new ArrayList<>()); // Initialize vulnerabilities list

                // Add the dependency to the application's dependencies list
                application.getDependencies().add(dep);
                // Store the dependency in the map for future reference
                depMap.put(depUuid, dep);
            }

            // Extract vulnerability UUID from the current row
            String vulnUuid = rs.getString("vuln_uuid");
            if (vulnUuid != null && depUuid != null) {
                // Create and populate a new Vulnerability object
                Vulnerability vuln = new Vulnerability();
                vuln.setId(rs.getLong("vuln_id")); // Set vulnerability ID
                vuln.setUuid(vulnUuid); // Set vulnerability UUID
                vuln.setDependencyUuid(depUuid); // Associate vulnerability with dependency UUID
                vuln.setCveId(rs.getString("vuln_cve_id")); // Set CVE ID
                vuln.setSeverity(rs.getString("vuln_severity")); // Set severity level
                vuln.setDescription(rs.getString("vuln_description")); // Set vulnerability description
                vuln.setCvssScore(rs.getObject("vuln_cvss_score") != null ?
                        rs.getDouble("vuln_cvss_score") : null); // Set CVSS score if available
                vuln.setPublishedDate(rs.getDate("vuln_published_date") != null ?
                        rs.getDate("vuln_published_date").toLocalDate() : null); // Set published date
                vuln.setStatus(rs.getBoolean("vuln_status")); // Set vulnerability status
                vuln.setCreatedAt(rs.getTimestamp("vuln_created_at").toLocalDateTime()); // Set creation timestamp
                vuln.setUpdatedAt(rs.getTimestamp("vuln_updated_at") != null ?
                        rs.getTimestamp("vuln_updated_at").toLocalDateTime() : null); // Set update timestamp

                // Add the vulnerability to the corresponding dependency's vulnerabilities list
                depMap.get(depUuid).getVulnerabilities().add(vuln);
            }
        }

        // Return the first application from the map, or null if the map is empty
        return appMap.isEmpty() ? null : appMap.values().iterator().next();
    }
}
