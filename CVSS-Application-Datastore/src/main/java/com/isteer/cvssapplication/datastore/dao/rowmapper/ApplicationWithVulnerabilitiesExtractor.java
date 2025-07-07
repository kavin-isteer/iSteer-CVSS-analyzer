
package com.isteer.cvssapplication.datastore.dao.rowmapper;

import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.ResultSetExtractor;

import com.isteer.cvssapplication.datastore.entity.Application;
import com.isteer.cvssapplication.datastore.entity.Vulnerability;
import com.isteer.cvssapplication.datastore.enums.Severity;

public class ApplicationWithVulnerabilitiesExtractor implements ResultSetExtractor<List<Application>> {
    @Override
    public List<Application> extractData(ResultSet rs) throws SQLException, DataAccessException {
        Map<String, Application> applicationMap = new HashMap<>();
        Map<String, List<Vulnerability>> vulnerabilityMap = new HashMap<>();

        while (rs.next()) {
            String appUuid = rs.getString("uuid");
            if (!applicationMap.containsKey(appUuid)) {
                Application application = new Application();
                application.setId(rs.getLong("id"));
                application.setUuid(appUuid);
                application.setSoftwareName(rs.getString("name"));
                application.setSoftwareVersion(rs.getString("version"));
                application.setVendorName(rs.getString("vendor_name"));
                application.setCreatedAt(rs.getTimestamp("created_at").toLocalDateTime());
                application.setInstalledDate(rs.getTimestamp("installed_date") != null
                        ? rs.getTimestamp("installed_date").toLocalDateTime() : null);
                application.setDeleted(rs.getBoolean("ca_is_deleted")); // Added
                application.setUpdatedAt(rs.getTimestamp("ca_updated_at") != null
                        ? rs.getTimestamp("ca_updated_at").toLocalDateTime() : null); // Added
                applicationMap.put(appUuid, application);
                vulnerabilityMap.put(appUuid, new ArrayList<>());
            }

            String vulnUuid = rs.getString("v_uuid");
            if (vulnUuid != null) {
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
                vulnerability.setCpeName(rs.getString("cpe_name"));
                vulnerabilityMap.get(appUuid).add(vulnerability);
            }
        }

        List<Application> applications = new ArrayList<>(applicationMap.values());
        applications.forEach(app -> app.setVulnerabilities(vulnerabilityMap.get(app.getUuid())));
        return applications;
    }
}