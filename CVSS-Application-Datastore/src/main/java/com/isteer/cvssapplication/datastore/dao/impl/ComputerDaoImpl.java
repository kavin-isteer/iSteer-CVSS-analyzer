package com.isteer.cvssapplication.datastore.dao.impl;

import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import com.isteer.cvssapplication.datastore.dao.ComputerDao;
import com.isteer.cvssapplication.datastore.dao.rowmapper.RowMapper;
import com.isteer.cvssapplication.datastore.entity.Computer;

@Repository
public class ComputerDaoImpl implements ComputerDao {
	   private static final Logger logger = LoggerFactory.getLogger(ComputerDaoImpl.class);

	    @Autowired
	    private NamedParameterJdbcTemplate jdbcTemplate;

	    @Override
	    public int save(Computer computer) {
	        String sql = "INSERT INTO computers (uuid, device_id, hostname, ip_address, os_version, antivirus_status, " +
	                "firewall_status, logged_in_user, last_update_check, timestamp, is_deleted, is_active, created_at) " +
	                "VALUES (:uuid, :deviceId, :hostname, :ipAddress, :osVersion, :antivirusStatus, :firewallStatus, " +
	                ":loggedInUser, :lastUpdateCheck,:timestamp, :isDeleted, :isActive, :createdAt)";
	        MapSqlParameterSource params = new MapSqlParameterSource()
	                .addValue("uuid", computer.getUuid())
	                .addValue("deviceId", computer.getDeviceId())
	                .addValue("hostname", computer.getMachineName())
	                .addValue("ipAddress", computer.getIpAddress())
	                .addValue("osVersion", computer.getOsVersion())
	                .addValue("antivirusStatus", computer.getAntivirusStatus())
	                .addValue("firewallStatus", computer.getFirewallStatus())
	                .addValue("loggedInUser", computer.getLoggedInUser())
	                .addValue("lastUpdateCheck", computer.getLastUpdateCheck())
	                .addValue("timestamp", computer.getTimestamp())
	                .addValue("isDeleted", computer.isDeleted())
	                .addValue("isActive", computer.isActive())
	                .addValue("createdAt", computer.getCreatedAt());
	        logger.debug("Saving computer with UUID: {}", computer.getUuid());
	        return jdbcTemplate.update(sql, params);
	    }
//
//	    @Override
//	    public int update(Computer computer) {
//	        String sql = "UPDATE computers SET hostname = :hostname, ip_address = :ipAddress, os_version = :osVersion, " +
//	                "antivirus_status = :antivirusStatus, firewall_status = :firewallStatus, logged_in_user = :loggedInUser, " +
//	                "last_update_check = :lastUpdateCheck, updated_at = :updatedAt " +
//	                "WHERE uuid = :uuid AND is_deleted = false";
//	        MapSqlParameterSource params = new MapSqlParameterSource()
//	                .addValue("uuid", computer.getUuid())
//	                .addValue("hostname", computer.getMachineName())
//	                .addValue("ipAddress", computer.getIpAddress())
//	                .addValue("osVersion", computer.getOsVersion())
//	                .addValue("antivirusStatus", computer.getAntivirusStatus())
//	                .addValue("firewallStatus", computer.getFirewallStatus())
//	                .addValue("loggedInUser", computer.getLoggedInUser())
//	                .addValue("lastUpdateCheck", computer.getLastUpdateCheck())
//	                .addValue("updatedAt", computer.getUpdatedAt());
//	        logger.debug("Updating computer with UUID: {}", computer.getUuid());
//	        return jdbcTemplate.update(sql, params);
//	    }
	    
	    @Override
	    public int update(Computer computer) {
	        String sql = "UPDATE computers SET hostname = :hostname, ip_address = :ipAddress, os_version = :osVersion, "
	                + "antivirus_status = :antivirusStatus, firewall_status = :firewallStatus, "
	                + "logged_in_user = :loggedInUser, last_update_check = :lastUpdateCheck, "
	                + "timestamp = :timestamp, updated_at = :updatedAt WHERE uuid = :uuid";
	        MapSqlParameterSource params = new MapSqlParameterSource()
	                .addValue("uuid", computer.getUuid())
	                .addValue("hostname", computer.getMachineName())
	                .addValue("ipAddress", computer.getIpAddress())
	                .addValue("osVersion", computer.getOsVersion())
	                .addValue("antivirusStatus", computer.getAntivirusStatus())
	                .addValue("firewallStatus", computer.getFirewallStatus())
	                .addValue("loggedInUser", computer.getLoggedInUser())
	                .addValue("lastUpdateCheck", computer.getLastUpdateCheck())
	                .addValue("timestamp", computer.getTimestamp())
	                .addValue("updatedAt", computer.getUpdatedAt());
	        logger.debug("Updating computer with UUID: {}", computer.getUuid());
	        return jdbcTemplate.update(sql, params);
	    }

	    @Override
	    public Optional<Computer> findByDeviceIdAndIsDeletedFalse(String deviceId) {
	        String sql = "SELECT * FROM computers WHERE device_id = :deviceId AND is_deleted = false";
	        MapSqlParameterSource params = new MapSqlParameterSource("deviceId", deviceId);
	        try {
	            Computer computer = jdbcTemplate.queryForObject(sql, params, RowMapper::mapComputerRow);
	            return Optional.ofNullable(computer);
	        } catch (Exception e) {
	            logger.debug("No computer found for deviceId: {}", deviceId);
	            return Optional.empty();
	        }
	    }

	    @Override
	    public Optional<Computer> findByUuidAndIsDeletedFalse(String uuid) {
	        String sql = "SELECT * FROM computers WHERE uuid = :uuid AND is_deleted = false";
	        MapSqlParameterSource params = new MapSqlParameterSource("uuid", uuid);
	        try {
	            Computer computer = jdbcTemplate.queryForObject(sql, params, RowMapper::mapComputerRow);
	            return Optional.ofNullable(computer);
	        } catch (Exception e) {
	            logger.debug("No computer found for UUID: {}", uuid);
	            return Optional.empty();
	        }
	    }

//	    @Override
//	    public int softDeleteByUuid(String uuid) {
//	        String sql = "UPDATE computers SET is_deleted = true, updated_at = CURRENT_TIMESTAMP " +
//	                "WHERE uuid = :uuid AND is_deleted = false";
//	        MapSqlParameterSource params = new MapSqlParameterSource("uuid", uuid);
//	        int updated = jdbcTemplate.update(sql, params);
//	        logger.debug("Soft deleted computer with UUID: {}, updated rows: {}", uuid, updated);
//	        return updated;
//	    }

	    @Override
	    public List<Computer> findAllComputers() {
	        String sql = "SELECT * FROM computers WHERE is_deleted = false";
	        return jdbcTemplate.query(sql, RowMapper::mapComputerRow);
	    }
	    
	    // Added: Find computer by UUID (regardless of is_deleted)
	    @Override
	    public Optional<Computer> findByUuid(String uuid) {
	        String sql = "SELECT * FROM computers WHERE uuid = :uuid";
	        MapSqlParameterSource params = new MapSqlParameterSource("uuid", uuid);
	        try {
	            Computer computer = jdbcTemplate.queryForObject(sql, params, RowMapper::mapComputerRow);
	            return Optional.ofNullable(computer);
	        } catch (Exception e) {
	            logger.debug("No computer found for UUID: {}", uuid);
	            return Optional.empty();
	        }
	    }

	    // Added: Update deletion status (is_deleted and is_active)
	    @Override
	    public int updateDeletionStatus(Computer computer) {
	        String sql = "UPDATE computers SET is_deleted = :isDeleted, is_active = :isActive, updated_at = :updatedAt WHERE uuid = :uuid";
	        MapSqlParameterSource params = new MapSqlParameterSource()
	                .addValue("uuid", computer.getUuid())
	                .addValue("isDeleted", computer.isDeleted())
	                .addValue("isActive", computer.isActive())
	                .addValue("updatedAt", computer.getUpdatedAt());
	        logger.debug("Updating deletion status for computer with UUID: {}", computer.getUuid());
	        return jdbcTemplate.update(sql, params);
	    }

	    // Added: Update activation status (is_active)
	    @Override
	    public int updateActivationStatus(Computer computer) {
	        String sql = "UPDATE computers SET is_active = :isActive, updated_at = :updatedAt WHERE uuid = :uuid";
	        MapSqlParameterSource params = new MapSqlParameterSource()
	                .addValue("uuid", computer.getUuid())
	                .addValue("isActive", computer.isActive())
	                .addValue("updatedAt", computer.getUpdatedAt());
	        logger.debug("Updating activation status for computer with UUID: {}", computer.getUuid());
	        return jdbcTemplate.update(sql, params);
	    }

	    // Added: Find computers by deletion status
	    @Override
	    public List<Computer> findByDeletionStatus(Boolean isDeleted) {
	        String sql;
	        MapSqlParameterSource params = new MapSqlParameterSource();
	        if (isDeleted == null) {
	            sql = "SELECT * FROM computers";
	        } else {
	            sql = "SELECT * FROM computers WHERE is_deleted = :isDeleted";
	            params.addValue("isDeleted", isDeleted);
	        }
	        logger.debug("Fetching computers with deletion status: {}", isDeleted);
	        return jdbcTemplate.query(sql, params, RowMapper::mapComputerRow);
	    }

	    // Added: Find computers by activation status
	    @Override
	    public List<Computer> findByActivationStatus(Boolean isActive) {
	        String sql;
	        MapSqlParameterSource params = new MapSqlParameterSource();
	        if (isActive == null) {
	            sql = "SELECT * FROM computers WHERE is_deleted = false AND is_active = true";
	        } else {
	            sql = "SELECT * FROM computers WHERE is_deleted = false AND is_active = :isActive";
	            params.addValue("isActive", isActive);
	        }
	        logger.debug("Fetching computers with activation status: {}", isActive);
	        return jdbcTemplate.query(sql, params, RowMapper::mapComputerRow);
	    }

}
