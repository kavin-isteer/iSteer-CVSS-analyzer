package com.isteer.repository;

import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.isteer.entity.Application;
import com.isteer.repository.dao.ApplicationRepositoryDao;
import com.isteer.util.ApplicationResultSetExtractor;
import com.isteer.util.ApplicationRowMapper;

@Repository
public class ApplicationRepository implements ApplicationRepositoryDao {

    // Injecting NamedParameterJdbcTemplate for executing SQL queries with named parameters
    @Autowired
    NamedParameterJdbcTemplate jdbcTemplate;

    @Transactional
    @Override
    public int save(Application application) {
        // SQL query to validate if the computer exists and is active
        String validateSql = """
            SELECT COUNT(*)
            FROM computers
            WHERE uuid = :computerUuid
              AND status = TRUE AND is_active = TRUE
        """;

        // Setting parameters for the validation query
        MapSqlParameterSource validateParams = new MapSqlParameterSource()
                .addValue("computerUuid", application.getComputerUuid());

        // Executing the validation query and retrieving the count
        Integer count = jdbcTemplate.queryForObject(validateSql, validateParams, Integer.class);

        // If the computer does not exist or is inactive, return -4 as an error code
        if (count == null || count == 0) {
            return -4; // Computer does not exist or is not active
        }

        // SQL query to insert a new application record
        String sql = """
            INSERT INTO applications (uuid, computer_uuid, name, version, vendor, install_date)
            VALUES (:uuid, :computerId, :name, :version, :vendor, :installDate)
        """;

        // Generating a new UUID for the application
        application.setUuid(UUID.randomUUID().toString());

        // Setting parameters for the insert query
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("uuid", application.getUuid())
                .addValue("computerId", application.getComputerUuid())
                .addValue("name", application.getName())
                .addValue("version", application.getVersion())
                .addValue("vendor", application.getVendor())
                .addValue("installDate", application.getInstalledDate());

        // Executing the insert query
        jdbcTemplate.update(sql, params);

        // Return 1 to indicate that one row was successfully inserted
        return 1;
    }

    @Override
    public List<Application> findAll() {
        // SQL query to retrieve all active applications joined with active computers
    	String sql = """
    		    SELECT applications.id, applications.uuid, applications.computer_uuid,
    		           applications.name, applications.version, applications.vendor, applications.install_date,
    		           applications.status, applications.created_at, applications.updated_at
    		    FROM applications
    		    JOIN computers ON applications.computer_uuid = computers.uuid AND computers.status = TRUE 
    		    AND computers.is_active = TRUE
    		    WHERE applications.status = TRUE
    		""";

        // Executing the query and mapping the result to a list of Application objects
        return jdbcTemplate.query(sql, new ApplicationRowMapper());
    }

    @Override
    public Application findByApplicationUuid(String uuid) {
        // SQL query to retrieve application details along with its dependencies and vulnerabilities
    	String sql = """
    		    SELECT a.id AS app_id, a.uuid AS app_uuid, a.computer_uuid AS app_computer_uuid,
    		           a.name AS app_name, a.version AS app_version, a.vendor AS app_vendor,
    		           a.install_date AS app_install_date, a.status AS app_status,
    		           a.created_at AS app_created_at, a.updated_at AS app_updated_at,
    		           d.id AS dep_id, d.uuid AS dep_uuid, d.name AS dep_name, d.version AS dep_version,
    		           d.group_id AS dep_group_id, d.artifact_id AS dep_artifact_id, d.status AS dep_status,
    		           d.created_at AS dep_created_at, d.updated_at AS dep_updated_at,
    		           v.id AS vuln_id, v.uuid AS vuln_uuid, v.cve_id AS vuln_cve_id, v.severity AS vuln_severity,
    		           v.description AS vuln_description, v.cvss_score AS vuln_cvss_score,
    		           v.published_date AS vuln_published_date, v.status AS vuln_status,
    		           v.created_at AS vuln_created_at, v.updated_at AS vuln_updated_at
    		    FROM applications a
    		    LEFT JOIN dependencies d ON d.application_uuid = a.uuid AND d.status = TRUE
    		    LEFT JOIN vulnerabilities v ON v.dependency_uuid = d.uuid AND v.status = TRUE
    		    WHERE a.uuid = :uuid AND a.status = TRUE
    		""";


        // Setting parameters for the query
        MapSqlParameterSource params = new MapSqlParameterSource().addValue("uuid", uuid);

        try {
            // Executing the query and extracting the result using ApplicationResultSetExtractor
            return jdbcTemplate.query(sql, params, new ApplicationResultSetExtractor());
        } catch (EmptyResultDataAccessException e) {
            // Return null if no result is found
            return null;
        }
    }

    @Override
    public Application findByUuid(String uuid) {
        // SQL query to retrieve application details by UUID
    	String sql = """
    		    SELECT id, uuid, computer_uuid, name, version, vendor, install_date, status, created_at, updated_at
    		    FROM applications
    		    WHERE uuid = :uuid AND status = TRUE
    		""";

        // Setting parameters for the query
        MapSqlParameterSource params = new MapSqlParameterSource().addValue("uuid", uuid);

        try {
            // Executing the query and mapping the result to an Application object
            return jdbcTemplate.queryForObject(sql, params, new ApplicationRowMapper());
        } catch (EmptyResultDataAccessException e) {
            // Return null if no result is found
            return null;
        }
    }

    @Transactional
    @Override
    public int update(String uuid, Application application) {
        // SQL query to update application details by UUID
    	String sql = """
    		    UPDATE applications
    		    SET name = :name, version = :version,
    		        vendor = :vendor, install_date = :installDate
    		    WHERE uuid = :uuid
    		""";
		// Check if the application exists

        // Setting parameters for the update query
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("name", application.getName())
                .addValue("version", application.getVersion())
                .addValue("vendor", application.getVendor())
                .addValue("installDate", application.getInstalledDate())
                .addValue("uuid", uuid);

        // Executing the update query
        return jdbcTemplate.update(sql, params);
    }

    @Transactional
    @Override
    public int softDelete(String uuid) {
        // SQL query to perform a soft delete by setting the status to false
    	String sql = """
    		    UPDATE applications
    		    SET status = FALSE, updated_at = CURRENT_TIMESTAMP
    		    WHERE uuid = :uuid AND status = TRUE
    		""";

        // Setting parameters for the soft delete query
        MapSqlParameterSource params = new MapSqlParameterSource().addValue("uuid", uuid);

        // Executing the soft delete query
        return jdbcTemplate.update(sql, params);
    }
}
