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
import com.isteer.cvssapplication.datastore.dao.rowmapper.ComputerWithAppsAndVulnsRowMapper;
import com.isteer.cvssapplication.datastore.dao.rowmapper.RowMapper;
import com.isteer.cvssapplication.datastore.dto.ComputerDetailsResponseDTO;
import com.isteer.cvssapplication.datastore.entity.Computer;

@Repository
public class ComputerDaoImpl implements ComputerDao {
	private static final Logger logger = LoggerFactory.getLogger(ComputerDaoImpl.class);

	@Autowired
	private NamedParameterJdbcTemplate jdbcTemplate;

	@Override
	public int save(Computer computer) {
		String sql = "INSERT INTO computers (uuid, device_id, hostname, ip_address, os_version, antivirus_status, "
				+ "firewall_status, logged_in_user, last_update_check, timestamp, is_deleted, is_active, created_at) "
				+ "VALUES (:uuid, :deviceId, :hostname, :ipAddress, :osVersion, :antivirusStatus, :firewallStatus, "
				+ ":loggedInUser, :lastUpdateCheck,:timestamp, :isDeleted, :isActive, :createdAt)";
		MapSqlParameterSource params = new MapSqlParameterSource().addValue("uuid", computer.getUuid())
				.addValue("deviceId", computer.getDeviceId()).addValue("hostname", computer.getMachineName())
				.addValue("ipAddress", computer.getIpAddress()).addValue("osVersion", computer.getOsVersion())
				.addValue("antivirusStatus", computer.getAntivirusStatus())
				.addValue("firewallStatus", computer.getFirewallStatus())
				.addValue("loggedInUser", computer.getLoggedInUser())
				.addValue("lastUpdateCheck", computer.getLastUpdateCheck())
				.addValue("timestamp", computer.getTimestamp()).addValue("isDeleted", computer.isDeleted())
				.addValue("isActive", computer.isActive()).addValue("createdAt", computer.getCreatedAt());
		logger.debug("Saving computer with UUID: {}", computer.getUuid());
		return jdbcTemplate.update(sql, params);
	}

	@Override
	public int update(Computer computer) {
		String sql = "UPDATE computers SET hostname = :hostname, ip_address = :ipAddress, os_version = :osVersion, "
				+ "antivirus_status = :antivirusStatus, firewall_status = :firewallStatus, "
				+ "logged_in_user = :loggedInUser, last_update_check = :lastUpdateCheck, "
				+ "timestamp = :timestamp, updated_at = :updatedAt WHERE uuid = :uuid";
		MapSqlParameterSource params = new MapSqlParameterSource().addValue("uuid", computer.getUuid())
				.addValue("hostname", computer.getMachineName()).addValue("ipAddress", computer.getIpAddress())
				.addValue("osVersion", computer.getOsVersion())
				.addValue("antivirusStatus", computer.getAntivirusStatus())
				.addValue("firewallStatus", computer.getFirewallStatus())
				.addValue("loggedInUser", computer.getLoggedInUser())
				.addValue("lastUpdateCheck", computer.getLastUpdateCheck())
				.addValue("timestamp", computer.getTimestamp()).addValue("updatedAt", computer.getUpdatedAt());
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
	public List<Computer> findAllPresentComputers() {
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
		MapSqlParameterSource params = new MapSqlParameterSource().addValue("uuid", computer.getUuid())
				.addValue("isDeleted", computer.isDeleted()).addValue("isActive", computer.isActive())
				.addValue("updatedAt", computer.getUpdatedAt());
		logger.debug("Updating deletion status for computer with UUID: {}", computer.getUuid());
		return jdbcTemplate.update(sql, params);
	}

	// Added: Update activation status (is_active)
	@Override
	public int updateActivationStatus(Computer computer) {
		String sql = "UPDATE computers SET is_active = :isActive, updated_at = :updatedAt WHERE uuid = :uuid";
		MapSqlParameterSource params = new MapSqlParameterSource().addValue("uuid", computer.getUuid())
				.addValue("isActive", computer.isActive()).addValue("updatedAt", computer.getUpdatedAt());
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
			sql = "SELECT * FROM computers WHERE is_deleted = false AND is_active = true OR is_active = false";
		} else {
			sql = "SELECT * FROM computers WHERE is_deleted = false AND is_active = :isActive";
			params.addValue("isActive", isActive);
		}
		logger.debug("Fetching computers with activation status: {}", isActive);
		return jdbcTemplate.query(sql, params, RowMapper::mapComputerRow);
	}

	@Override
	public List<Computer> findAllDeletedComputers() {
		String sql = "SELECT * FROM computers WHERE is_deleted = true";
		logger.debug("Fetching all deleted computers");
		return jdbcTemplate.query(sql, RowMapper::mapComputerRow);

	}
	
	  @Override
	    public ComputerDetailsResponseDTO findDetailsByUuid(String uuid) {
	        String sql = "SELECT c.id AS c_id, c.uuid AS c_uuid, c.device_id, c.hostname, c.ip_address, c.os_version, " +
	                     "c.antivirus_status, c.firewall_status, c.logged_in_user, c.last_update_check, c.timestamp, " +
	                     "c.is_active, c.is_deleted, c.created_at AS c_created_at, c.updated_at AS c_updated_at, " +
	                     "a.id AS a_id, a.uuid AS a_uuid, a.name, a.version, a.vendor_name AS a_vendor_name, a.created_at AS a_created_at, " +
	                     "ca.installed_date AS ca_installed_date, ca.updated_at AS ca_updated_at, ca.is_deleted AS ca_is_deleted, " +
	                     "v.id AS v_id, v.uuid AS v_uuid, v.cve_id, v.severity, v.description, v.vector_string, " +
	                     "v.source_identifier, v.cvss_score, v.cvss_version, v.created_at AS v_created_at, v.is_deleted AS v_is_deleted " +
	                     "FROM computers c " +
	                     "LEFT JOIN computer_applications ca ON c.uuid = ca.computer_uuid AND ca.is_deleted = false " +
	                     "LEFT JOIN applications a ON ca.application_uuid = a.uuid " +
	                     "LEFT JOIN application_vulnerabilities av ON a.uuid = av.application_uuid " +
	                     "LEFT JOIN vulnerabilities v ON av.vulnerability_uuid = v.id AND v.is_deleted = false " +
	                     "WHERE c.uuid = :uuid AND c.is_deleted = false";
	        MapSqlParameterSource params = new MapSqlParameterSource("uuid", uuid);
	        logger.debug("Fetching details for computer UUID: {}", uuid);
	        return jdbcTemplate.query(sql, params, new ComputerWithAppsAndVulnsRowMapper());
	    }
}
