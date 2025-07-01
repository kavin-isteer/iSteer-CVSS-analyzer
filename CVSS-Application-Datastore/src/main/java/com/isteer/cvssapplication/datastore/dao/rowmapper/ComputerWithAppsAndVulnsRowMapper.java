package com.isteer.cvssapplication.datastore.dao.rowmapper;
import com.isteer.cvssapplication.datastore.dto.ComputerDetailsResponseDTO;
import com.isteer.cvssapplication.datastore.entity.Application;
import com.isteer.cvssapplication.datastore.entity.Computer;
import com.isteer.cvssapplication.datastore.entity.Vulnerability;
import com.isteer.cvssapplication.datastore.enums.Severity;

import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.ResultSetExtractor;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ComputerWithAppsAndVulnsRowMapper implements ResultSetExtractor<ComputerDetailsResponseDTO> {
    @Override
    public ComputerDetailsResponseDTO extractData(ResultSet rs) throws SQLException, DataAccessException {
        Computer computer = null;
        Map<String, Application> applicationMap = new HashMap<>();
        Map<String, List<Vulnerability>> vulnerabilityMap = new HashMap<>();

        while (rs.next()) {
            // Map Computer
            if (computer == null) {
                computer = new Computer();
                computer.setId(rs.getLong("c_id"));
                computer.setUuid(rs.getString("c_uuid"));
                computer.setDeviceId(rs.getString("device_id"));
                computer.setMachineName(rs.getString("hostname"));
                computer.setIpAddress(rs.getString("ip_address"));
                computer.setOsVersion(rs.getString("os_version"));
                computer.setAntivirusStatus(rs.getString("antivirus_status"));
                computer.setFirewallStatus(rs.getString("firewall_status"));
                computer.setLoggedInUser(rs.getString("logged_in_user"));
                computer.setLastUpdateCheck(rs.getTimestamp("last_update_check") != null
                        ? rs.getTimestamp("last_update_check").toLocalDateTime() : null);
                computer.setTimestamp(rs.getTimestamp("timestamp") != null
                        ? rs.getTimestamp("timestamp").toLocalDateTime() : null);
                computer.setActive(rs.getBoolean("is_active"));
                computer.setDeleted(rs.getBoolean("is_deleted"));
                computer.setCreatedAt(rs.getTimestamp("c_created_at").toLocalDateTime());
                computer.setUpdatedAt(rs.getTimestamp("c_updated_at") != null
                        ? rs.getTimestamp("c_updated_at").toLocalDateTime() : null);
            }

            // Map Application
            String appUuid = rs.getString("a_uuid");
            if (appUuid != null && !applicationMap.containsKey(appUuid)) {
                Application application = new Application();
                application.setId(rs.getLong("a_id"));
                application.setUuid(appUuid);
                application.setName(rs.getString("name"));
                application.setVersion(rs.getString("version"));
                application.setVendorName(rs.getString("a_vendor_name"));
                application.setCreatedAt(rs.getTimestamp("a_created_at").toLocalDateTime());
                application.setInstalledDate(rs.getTimestamp("ca_installed_date") != null
                        ? rs.getTimestamp("ca_installed_date").toLocalDateTime() : null);
                application.setDeleted(rs.getBoolean("ca_is_deleted")); // Added
                application.setUpdatedAt(rs.getTimestamp("ca_updated_at") != null
                        ? rs.getTimestamp("ca_updated_at").toLocalDateTime() : null); // Added
                applicationMap.put(appUuid, application);
                vulnerabilityMap.put(appUuid, new ArrayList<>());
            }

            // Map Vulnerability
            String vulnUuid = rs.getString("v_uuid");
            if (vulnUuid != null) {
                String appUuidForVuln = rs.getString("a_uuid");
                Vulnerability vulnerability = new Vulnerability();
                vulnerability.setId(rs.getLong("v_id"));
                vulnerability.setUuid(vulnUuid);
                vulnerability.setCveId(rs.getString("cve_id"));
                vulnerability.setSeverity(Severity.valueOf(rs.getString("severity")));
                vulnerability.setDescription(rs.getString("description"));
                vulnerability.setVectorString(rs.getString("vector_string"));
                vulnerability.setSourceIdentifier(rs.getString("source_identifier"));
                vulnerability.setCvssScore(rs.getDouble("cvss_score"));
                vulnerability.setCvssVersion(rs.getString("cvss_version"));
                vulnerability.setCreatedAt(rs.getTimestamp("v_created_at").toLocalDateTime());
                vulnerability.setDeleted(rs.getBoolean("v_is_deleted"));
                vulnerabilityMap.get(appUuidForVuln).add(vulnerability);
            }
        }

        // Build response
        ComputerDetailsResponseDTO response = new ComputerDetailsResponseDTO();
        response.setComputer(computer != null ? computer : new Computer());
        List<Application> applications = new ArrayList<>(applicationMap.values());
        applications.forEach(app -> app.setVulnerabilities(vulnerabilityMap.get(app.getUuid())));
        response.setApplications(applications);
        return response;
    }
}

