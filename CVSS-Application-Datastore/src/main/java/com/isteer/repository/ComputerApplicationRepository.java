package com.isteer.repository;


import com.isteer.entity.ComputerApplication;
import com.isteer.repository.dao.ComputerApplicationRepositoryDao;
import com.isteer.util.ComputerApplicationRowMapper;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Repository
public class ComputerApplicationRepository implements ComputerApplicationRepositoryDao {
    private final NamedParameterJdbcTemplate jdbcTemplate;

    public ComputerApplicationRepository(NamedParameterJdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Transactional
    @Override
    public int save(ComputerApplication computerApplication) {
        String sql = "INSERT INTO computer_applications (uuid, computer_uuid, application_uuid, installed_date, is_deleted, created_at) " +
                "VALUES (:uuid, :computerUuid, :applicationUuid, :installedDate, :isDeleted, :createdAt)";
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("uuid", computerApplication.getUuid())
                .addValue("computerUuid", computerApplication.getComputerUuid())
                .addValue("applicationUuid", computerApplication.getApplicationUuid())
                .addValue("installedDate", computerApplication.getInstalledDate())
                .addValue("isDeleted", computerApplication.isDeleted())
                .addValue("createdAt", computerApplication.getCreatedAt());
        return jdbcTemplate.update(sql, params);
    }

    @Override
    public Optional<ComputerApplication> findByComputerAndApplicationUuid(String computerUuid, String applicationUuid) {
        String sql = "SELECT * FROM computer_applications WHERE computer_uuid = :computerUuid AND application_uuid = :applicationUuid AND is_deleted = false";
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("computerUuid", computerUuid)
                .addValue("applicationUuid", applicationUuid);
        return jdbcTemplate.query(sql, params, new ComputerApplicationRowMapper())
                .stream().findFirst();
    }

    @Transactional
    @Override
    public int softDelete(String uuid) {
        String sql = "UPDATE computer_applications SET is_deleted = true, updated_at = CURRENT_TIMESTAMP WHERE uuid = :uuid";
        MapSqlParameterSource params = new MapSqlParameterSource().addValue("uuid", uuid);
        return jdbcTemplate.update(sql, params);
    }
}
