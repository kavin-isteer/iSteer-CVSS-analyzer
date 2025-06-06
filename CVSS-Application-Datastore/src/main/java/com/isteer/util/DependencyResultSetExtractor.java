package com.isteer.util;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;

import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.ResultSetExtractor;

import com.isteer.entity.Dependency;
import com.isteer.entity.Vulnerability;

public class DependencyResultSetExtractor implements ResultSetExtractor<Dependency> {

    @Override
    public Dependency extractData(ResultSet rs) throws SQLException, DataAccessException {
        // Map to store dependencies by their UUID for efficient lookup and aggregation
        Map<String, Dependency> depMap = new HashMap<>();

        // Iterate through the result set to process each row
        while (rs.next()) {
            // Extract the dependency UUID from the current row
            String depUuid = rs.getString("dep_uuid");

            // Retrieve or create a Dependency object for the current UUID
            Dependency dependency = depMap.computeIfAbsent(depUuid, k -> {
                Dependency dep = new Dependency();
                try {
                    // Populate the Dependency object with data from the result set
                    dep.setId(rs.getLong("dep_id")); // Set the dependency ID
                    dep.setUuid(depUuid); // Set the dependency UUID
                    dep.setApplicationUuid(rs.getString("dep_application_uuid")); // Set the application UUID
                    dep.setName(rs.getString("dep_name")); // Set the dependency name
                    dep.setVersion(rs.getString("dep_version")); // Set the dependency version
                    dep.setGroupId(rs.getString("dep_group_id")); // Set the group ID
                    dep.setArtifactId(rs.getString("dep_artifact_id")); // Set the artifact ID
                    dep.setStatus(rs.getBoolean("dep_status")); // Set the status (active/inactive)
                    dep.setCreatedAt(rs.getTimestamp("dep_created_at").toLocalDateTime()); // Set the creation timestamp
                    dep.setUpdatedAt(rs.getTimestamp("dep_updated_at") != null ?
                            rs.getTimestamp("dep_updated_at").toLocalDateTime() : null); // Set the update timestamp (if available)
                    dep.setVulnerabilities(new ArrayList<>()); // Initialize the vulnerabilities list
                } catch (SQLException e) {
                    // Handle SQL exceptions during Dependency object creation
                    throw new RuntimeException("Error mapping Dependency", e);
                }
                return dep; // Return the newly created Dependency object
            });

            // Extract the vulnerability UUID from the current row (if present)
            String vulnUuid = rs.getString("vuln_uuid");
            if (vulnUuid != null) {
                // Create and populate a Vulnerability object with data from the result set
                Vulnerability vuln = new Vulnerability();
                vuln.setId(rs.getLong("vuln_id")); // Set the vulnerability ID
                vuln.setUuid(vulnUuid); // Set the vulnerability UUID
                vuln.setDependencyUuid(depUuid); // Associate the vulnerability with the dependency UUID
                vuln.setCveId(rs.getString("vuln_cve_id")); // Set the CVE ID
                vuln.setSeverity(rs.getString("vuln_severity")); // Set the severity level
                vuln.setDescription(rs.getString("vuln_description")); // Set the vulnerability description
                vuln.setCvssScore(rs.getObject("vuln_cvss_score") != null ?
                        rs.getDouble("vuln_cvss_score") : null); // Set the CVSS score (if available)
                vuln.setPublishedDate(rs.getDate("vuln_published_date") != null ?
                        rs.getDate("vuln_published_date").toLocalDate() : null); // Set the published date (if available)
                vuln.setStatus(rs.getBoolean("vuln_status")); // Set the status (active/inactive)
                vuln.setCreatedAt(rs.getTimestamp("vuln_created_at").toLocalDateTime()); // Set the creation timestamp
                vuln.setUpdatedAt(rs.getTimestamp("vuln_updated_at") != null ?
                        rs.getTimestamp("vuln_updated_at").toLocalDateTime() : null); // Set the update timestamp (if available)

                // Add the Vulnerability object to the Dependency's vulnerabilities list
                dependency.getVulnerabilities().add(vuln);
            }
        }

        // Return the first Dependency object from the map, or null if the map is empty
        return depMap.isEmpty() ? null : depMap.values().iterator().next();
    }
}
