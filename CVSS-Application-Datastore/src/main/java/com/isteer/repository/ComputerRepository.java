package com.isteer.repository;

import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.isteer.entity.Computer;
import com.isteer.repository.dao.ComputerRepositoryDao;
import com.isteer.util.ComputerResultSetExtractor;
import com.isteer.util.ComputerRowMapper;

@Repository
public class ComputerRepository implements ComputerRepositoryDao {

    // Injecting NamedParameterJdbcTemplate to execute SQL queries with named parameters
    @Autowired
    NamedParameterJdbcTemplate jdbcTemplate;

    // Method to save a new Computer entity into the database
    @Transactional
    @Override
    public int save(Computer computer) {
        // SQL query to insert a new record into the Computers table
        String sql = """
            INSERT INTO Computers (uuid, ip_address, hostName, os_name, os_version, location)
            VALUES (:uuid, :ipAddress, :hostName, :osName, :osVersion, :location)
        """;

        // Generate a random UUID for the computer and set it
        computer.setUuid(UUID.randomUUID().toString());

        // Map parameters to the SQL query using MapSqlParameterSource
        MapSqlParameterSource params = new MapSqlParameterSource()
            .addValue("uuid", computer.getUuid())
            .addValue("ipAddress", computer.getIpAddress())
            .addValue("hostName", computer.getHostName())
            .addValue("osName", computer.getOsName())
            .addValue("osVersion", computer.getOsVersion())
            .addValue("location", computer.getLocation());

        // Execute the query and return 1 assuming the insert is successful
        jdbcTemplate.update(sql, params);
        return 1;
    }

    // Method to retrieve all active Computers from the database
    @Override
    public List<Computer> findAll() {
        // SQL query to select all active computers (status = TRUE)
        String sql = """
            SELECT id, uuid, ip_address, hostName, os_name, os_version, location,
            is_active, status, created_at, updated_at FROM Computers WHERE status = TRUE
        """;

        // Use ComputerRowMapper to map the result set to Computer objects
        return jdbcTemplate.query(sql, new ComputerRowMapper());
    }

    // Method to find a Computer by its UUID
    @Override
    public Computer findByUuid(String uuid) {
        // SQL query to select a computer by UUID and ensure it is active (status = TRUE)
        String sql = """
            SELECT id, uuid, ip_address, hostName, os_name, os_version, location, is_active, status,
            created_at, updated_at FROM Computers WHERE uuid = :uuid AND status = TRUE 
        """;

        // Map the UUID parameter to the query
        MapSqlParameterSource params = new MapSqlParameterSource().addValue("uuid", uuid);

        try {
            // Query for a single Computer object using ComputerRowMapper
            return jdbcTemplate.queryForObject(sql, params, new ComputerRowMapper());
        } catch (EmptyResultDataAccessException e) {
            // Return null if no result is found
            return null;
        }
    }

    // Method to retrieve detailed information about a Computer, including related entities
    @Override
    public Computer computerByUuid(String uuid) {
        // SQL query to join Computers with applications, dependencies, and vulnerabilities
        String sql = """
            SELECT c.id AS computer_id, c.uuid AS computer_uuid, c.ip_address AS computer_ip_address,
                   c.hostName AS computer_host_name, c.os_name AS computer_os_name, c.os_version 
                   AS computer_os_version,
                   c.location AS computer_location, c.is_active AS computer_is_active, c.status AS
                   computer_status, c.created_at AS computer_created_at, c.updated_at AS computer_updated_at,
                   a.id AS app_id, a.uuid AS app_uuid, a.name AS app_name, a.version AS app_version,
                   a.vendor AS app_vendor, a.install_date AS app_install_date, a.status AS app_status,
                   a.created_at AS app_created_at, a.updated_at AS app_updated_at,
                   d.id AS dep_id, d.uuid AS dep_uuid, d.name AS dep_name, d.version AS dep_version,
                   d.group_id AS dep_group_id, d.artifact_id AS dep_artifact_id, d.status AS dep_status,
                   d.created_at AS dep_created_at, d.updated_at AS dep_updated_at,
                   v.id AS vuln_id, v.uuid AS vuln_uuid, v.cve_id AS vuln_cve_id, v.severity AS vuln_severity,
                   v.description AS vuln_description, v.cvss_score AS vuln_cvss_score,
                   v.published_date AS vuln_published_date,
                   v.status AS vuln_status, v.created_at AS vuln_created_at, v.updated_at AS vuln_updated_at
            FROM Computers c
            LEFT JOIN applications a ON a.computer_uuid = c.uuid AND a.status = TRUE
            LEFT JOIN dependencies d ON d.application_uuid = a.uuid AND d.status = TRUE
            LEFT JOIN vulnerabilities v ON v.dependency_uuid = d.uuid AND v.status = TRUE
            WHERE c.uuid = :uuid AND c.status = TRUE AND c.is_active = TRUE
        """;

        // Map the UUID parameter to the query
        MapSqlParameterSource params = new MapSqlParameterSource().addValue("uuid", uuid);

        try {
            // Use ComputerResultSetExtractor to extract and map the result set
            return jdbcTemplate.query(sql, params, new ComputerResultSetExtractor());
        } catch (EmptyResultDataAccessException e) {
            // Return null if no result is found
            return null;
        }
    }

    // Method to update a Computer's details by its UUID
    @Transactional
    @Override
    public int update(String uuid, Computer computer) {
        // SQL query to update a computer's details
        String sql = """
            UPDATE Computers SET ip_address = :ipAddress, hostName = :hostName, os_name = :osName,
            os_version = :osVersion, location = :location WHERE uuid = :uuid AND status = TRUE AND is_active = TRUE
        """;

        // Map parameters to the query
        MapSqlParameterSource params = new MapSqlParameterSource()
            .addValue("ipAddress", computer.getIpAddress())
            .addValue("hostName", computer.getHostName())
            .addValue("osName", computer.getOsName())
            .addValue("osVersion", computer.getOsVersion())
            .addValue("location", computer.getLocation())
            .addValue("isActive", computer.isActive())
            .addValue("status", computer.isStatus())
            .addValue("updatedAt", computer.getUpdatedAt())
            .addValue("uuid", uuid);

        // Execute the update query and return the number of rows affected
        return jdbcTemplate.update(sql, params);
    }

    // Method to perform a soft delete on a Computer by its UUID
    @Transactional
    @Override
    public int softDelete(String uuid) {
        // SQL query to mark a computer as inactive (status = FALSE)
        String sql = """
            UPDATE Computers SET status = FALSE, updated_at = CURRENT_TIMESTAMP WHERE uuid = :uuid AND status = TRUE 
        """;

        // Map the UUID parameter to the query
        MapSqlParameterSource params = new MapSqlParameterSource().addValue("uuid", uuid);

        // Execute the update query and return the number of rows affected
        return jdbcTemplate.update(sql, params);
    }

    // Method to deactivate a Computer by its UUID
    @Transactional
    @Override
    public int deactivate(String uuid) {
        // SQL query to set is_active to FALSE for a computer
        String sql = """
            UPDATE Computers SET is_active = FALSE, updated_at = CURRENT_TIMESTAMP WHERE uuid = :uuid AND status = TRUE
            AND is_active = TRUE
        """;

        // Map the UUID parameter to the query
        MapSqlParameterSource params = new MapSqlParameterSource().addValue("uuid", uuid);

        // Execute the update query and return the number of rows affected
        return jdbcTemplate.update(sql, params);
    }

    // Method to activate a Computer by its UUID
    @Transactional
    @Override
    public int activateComputer(String uuid) {
        // SQL query to set is_active to TRUE for a computer
        String updateSql = """
            UPDATE Computers SET is_active = TRUE, updated_at = CURRENT_TIMESTAMP
            WHERE uuid = :uuid AND is_active = FALSE AND status = TRUE
        """;

        // Map the UUID parameter to the query
        MapSqlParameterSource params = new MapSqlParameterSource().addValue("uuid", uuid);

        // Execute the update query and return the number of rows affected
        return jdbcTemplate.update(updateSql, params);
    }
}
