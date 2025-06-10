//package com.isteer.util;
//
//import java.sql.ResultSet;
//import java.sql.SQLException;
//import java.util.ArrayList;
//import java.util.HashMap;
//import java.util.Map;
//
//import org.springframework.dao.DataAccessException;
//import org.springframework.jdbc.core.ResultSetExtractor;
//
//import com.isteer.entity.Application;
//import com.isteer.entity.Computer;
//import com.isteer.entity.Dependency;
//import com.isteer.entity.Vulnerability;
//
//public class ComputerResultSetExtractor implements ResultSetExtractor<Computer> {
//
//    @Override
//    public Computer extractData(ResultSet rs) throws SQLException, DataAccessException {
//        // Maps to store unique entities to avoid duplication during extraction
//        Map<String, Computer> computerMap = new HashMap<>();
//        Map<String, Application> appMap = new HashMap<>();
//        Map<String, Dependency> depMap = new HashMap<>();
//
//        // Iterate through the ResultSet rows
//        while (rs.next()) {
//            // Extract computer details using its unique UUID
//            String computerUuid = rs.getString("computer_uuid");
//            Computer computer = computerMap.computeIfAbsent(computerUuid, k -> {
//                Computer c = new Computer();
//                try {
//                    // Populate Computer entity fields from ResultSet
//                    c.setId(rs.getLong("computer_id"));
//                    c.setUuid(computerUuid);
//                    c.setIpAddress(rs.getString("computer_ip_address"));
//                    c.setHostName(rs.getString("computer_host_name"));
//                    c.setOsName(rs.getString("computer_os_name"));
//                    c.setOsVersion(rs.getString("computer_os_version"));
//                    c.setLocation(rs.getString("computer_location"));
//                    c.setActive(rs.getBoolean("computer_is_active"));
//                    c.setStatus(rs.getBoolean("computer_status"));
//                    c.setCreatedAt(rs.getTimestamp("computer_created_at").toLocalDateTime());
//                    c.setUpdatedAt(rs.getTimestamp("computer_updated_at") != null ?
//                            rs.getTimestamp("computer_updated_at").toLocalDateTime() : null);
//                    c.setApplications(new ArrayList<>()); // Initialize applications list
//                } catch (SQLException e) {
//                    // Handle SQL exception during mapping
//                    throw new RuntimeException("Error mapping Computer", e);
//                }
//                return c;
//            });
//
//            // Extract application details using its unique UUID
//            String appUuid = rs.getString("app_uuid");
//            if (appUuid != null && !appMap.containsKey(appUuid)) {
//                Application app = new Application();
//                // Populate Application entity fields from ResultSet
//                app.setId(rs.getLong("app_id"));
//                app.setUuid(appUuid);
//                app.setComputerUuid(computerUuid); // Associate application with computer
//                app.setName(rs.getString("app_name"));
//                app.setVersion(rs.getString("app_version"));
//                app.setVendor(rs.getString("app_vendor"));
//                app.setInstalledDate(rs.getDate("app_install_date") != null ?
//                        rs.getDate("app_install_date").toLocalDate() : null);
//                app.setStatus(rs.getBoolean("app_status"));
//                app.setCreatedAt(rs.getTimestamp("app_created_at").toLocalDateTime());
//                app.setUpdatedAt(rs.getTimestamp("app_updated_at") != null ?
//                        rs.getTimestamp("app_updated_at").toLocalDateTime() : null);
//                app.setDependencies(new ArrayList<>()); // Initialize dependencies list
//                computer.getApplications().add(app); // Add application to computer's list
//                appMap.put(appUuid, app); // Store application in map
//            }
//
//            // Extract dependency details using its unique UUID
//            String depUuid = rs.getString("dep_uuid");
//            if (depUuid != null && !depMap.containsKey(depUuid)) {
//                Dependency dep = new Dependency();
//                // Populate Dependency entity fields from ResultSet
//                dep.setId(rs.getLong("dep_id"));
//                dep.setUuid(depUuid);
//                dep.setApplicationUuid(appUuid); // Associate dependency with application
//                dep.setName(rs.getString("dep_name"));
//                dep.setVersion(rs.getString("dep_version"));
//                dep.setGroupId(rs.getString("dep_group_id"));
//                dep.setArtifactId(rs.getString("dep_artifact_id"));
//                dep.setStatus(rs.getBoolean("dep_status"));
//                dep.setCreatedAt(rs.getTimestamp("dep_created_at").toLocalDateTime());
//                dep.setUpdatedAt(rs.getTimestamp("dep_updated_at") != null ?
//                        rs.getTimestamp("dep_updated_at").toLocalDateTime() : null);
//                dep.setVulnerabilities(new ArrayList<>()); // Initialize vulnerabilities list
//                appMap.get(appUuid).getDependencies().add(dep); // Add dependency to application's list
//                depMap.put(depUuid, dep); // Store dependency in map
//            }
//
//            // Extract vulnerability details using its unique UUID
//            String vulnUuid = rs.getString("vuln_uuid");
//            if (vulnUuid != null) {
//                Vulnerability vuln = new Vulnerability();
//                // Populate Vulnerability entity fields from ResultSet
//                vuln.setId(rs.getLong("vuln_id"));
//                vuln.setUuid(vulnUuid);
//                vuln.setDependencyUuid(depUuid); // Associate vulnerability with dependency
//                vuln.setCveId(rs.getString("vuln_cve_id"));
//                vuln.setSeverity(rs.getString("vuln_severity"));
//                vuln.setDescription(rs.getString("vuln_description"));
//                vuln.setCvssScore(rs.getObject("vuln_cvss_score") != null ?
//                        rs.getDouble("vuln_cvss_score") : null);
//                vuln.setPublishedDate(rs.getDate("vuln_published_date") != null ?
//                        rs.getDate("vuln_published_date").toLocalDate() : null);
//                vuln.setStatus(rs.getBoolean("vuln_status"));
//                vuln.setCreatedAt(rs.getTimestamp("vuln_created_at").toLocalDateTime());
//                vuln.setUpdatedAt(rs.getTimestamp("vuln_updated_at") != null ?
//                        rs.getTimestamp("vuln_updated_at").toLocalDateTime() : null);
//                depMap.get(depUuid).getVulnerabilities().add(vuln); // Add vulnerability to dependency's list
//            }
//        }
//
//        // Return the first Computer object from the map or null if no data exists
//        return computerMap.isEmpty() ? null : computerMap.values().iterator().next();
//    }
//}
