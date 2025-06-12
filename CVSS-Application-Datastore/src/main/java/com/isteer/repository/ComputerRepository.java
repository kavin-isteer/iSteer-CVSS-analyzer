package com.isteer.repository;

import com.isteer.entity.Computer;
import com.isteer.repository.dao.ComputerRepositoryDao;
import com.isteer.util.ComputerRowMapper;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;
import java.util.Optional;

@Repository
public class ComputerRepository implements ComputerRepositoryDao {
    private final NamedParameterJdbcTemplate jdbcTemplate;

    public ComputerRepository(NamedParameterJdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Transactional
    @Override
    public int save(Computer computer) {
        String sql = "INSERT INTO computers (uuid, device_id, hostname, ip_address, os_version, antivirus_status, " +
                "firewall_status, logged_in_user, last_update_check, is_deleted, is_active, created_at) " +
                "VALUES (:uuid, :deviceId, :hostname, :ipAddress, :osVersion, :antivirusStatus, :firewallStatus, " +
                ":loggedInUser, :lastUpdateCheck, :isDeleted, :isActive, :createdAt)";
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("uuid", computer.getUuid())
                .addValue("deviceId", computer.getDeviceId())
                .addValue("hostname", computer.getHostname())
                .addValue("ipAddress", computer.getIpAddress())
                .addValue("osVersion", computer.getOsVersion())
                .addValue("antivirusStatus", computer.getAntivirusStatus())
                .addValue("firewallStatus", computer.getFirewallStatus())
                .addValue("loggedInUser", computer.getLoggedInUser())
                .addValue("lastUpdateCheck", computer.getLastUpdateCheck())
                .addValue("isDeleted", computer.isDeleted())
                .addValue("isActive", computer.isActive())
                .addValue("createdAt", computer.getCreatedAt());
        return jdbcTemplate.update(sql, params);
    }

    @Override
    public List<Computer> findAll() {
        String sql = "SELECT * FROM computers WHERE is_deleted = false";
        return jdbcTemplate.query(sql, new ComputerRowMapper());
    }

    @Override
    public Optional<Computer> findByUuid(String uuid) {
        String sql = "SELECT * FROM computers WHERE uuid = :uuid AND is_deleted = false";
        MapSqlParameterSource params = new MapSqlParameterSource().addValue("uuid", uuid);
        return jdbcTemplate.query(sql, params, new ComputerRowMapper())
                .stream().findFirst();
    }

    @Override
    public Optional<Computer> findByDeviceId(String deviceId) {
        String sql = "SELECT * FROM computers WHERE device_id = :deviceId AND is_deleted = false";
        MapSqlParameterSource params = new MapSqlParameterSource().addValue("deviceId", deviceId);
        return jdbcTemplate.query(sql, params, new ComputerRowMapper())
                .stream().findFirst();
    }

    @Transactional
    @Override
    public int update(String uuid, Computer computer) {
        String sql = "UPDATE computers SET device_id = :deviceId, hostname = :hostname, ip_address = :ipAddress, " +
                "os_version = :osVersion, antivirus_status = :antivirusStatus, firewall_status = :firewallStatus, " +
                "logged_in_user = :loggedInUser, last_update_check = :lastUpdateCheck, is_active = :isActive, " +
                "updated_at = CURRENT_TIMESTAMP WHERE uuid = :uuid AND is_deleted = false";
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("uuid", uuid)
                .addValue("deviceId", computer.getDeviceId())
                .addValue("hostname", computer.getHostname())
                .addValue("ipAddress", computer.getIpAddress())
                .addValue("osVersion", computer.getOsVersion())
                .addValue("antivirusStatus", computer.getAntivirusStatus())
                .addValue("firewallStatus", computer.getFirewallStatus())
                .addValue("loggedInUser", computer.getLoggedInUser())
                .addValue("lastUpdateCheck", computer.getLastUpdateCheck())
                .addValue("isActive", computer.isActive());
        return jdbcTemplate.update(sql, params);
    }

    @Transactional
    @Override
    public int softDelete(String uuid) {
        String sql = "UPDATE computers SET is_deleted = true, updated_at = CURRENT_TIMESTAMP WHERE uuid = :uuid";
        MapSqlParameterSource params = new MapSqlParameterSource().addValue("uuid", uuid);
        return jdbcTemplate.update(sql, params);
    }

    @Transactional
    @Override
    public int deactivate(String uuid) {
        String sql = "UPDATE computers SET is_active = false, updated_at = CURRENT_TIMESTAMP WHERE uuid = :uuid AND is_deleted = false";
        MapSqlParameterSource params = new MapSqlParameterSource().addValue("uuid", uuid);
        return jdbcTemplate.update(sql, params);
    }

    @Transactional
    @Override
    public int activate(String uuid) {
        String sql = "UPDATE computers SET is_active = true, updated_at = CURRENT_TIMESTAMP WHERE uuid = :uuid AND is_deleted = false";
        MapSqlParameterSource params = new MapSqlParameterSource().addValue("uuid", uuid);
        return jdbcTemplate.update(sql, params);
    }
}