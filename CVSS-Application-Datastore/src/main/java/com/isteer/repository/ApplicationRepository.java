package com.isteer.repository;

import com.isteer.entity.Application;
import com.isteer.repository.dao.ApplicationRepositoryDao;
import com.isteer.util.ApplicationRowMapper;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import java.util.List;
import java.util.Optional;

@Repository
public class ApplicationRepository implements ApplicationRepositoryDao {
    private final NamedParameterJdbcTemplate jdbcTemplate;

    public ApplicationRepository(NamedParameterJdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @Transactional
    @Override
    public int save(Application application) {
        String sql = "INSERT INTO applications (uuid, name, version, vendor_name, installed_date, is_deleted, created_at) " +
                "VALUES (:uuid, :name, :version, :vendorName, :installedDate, :isDeleted, :createdAt)";
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("uuid", application.getUuid())
                .addValue("name", application.getName())
                .addValue("version", application.getVersion())
                .addValue("vendorName", application.getVendorName())
                .addValue("installedDate", application.getInstalledDate())
                .addValue("isDeleted", application.isDeleted())
                .addValue("createdAt", application.getCreatedAt());
        return jdbcTemplate.update(sql, params);
    }

    @Override
    public List<Application> findAll() {
        String sql = "SELECT * FROM applications WHERE is_deleted = false";
        return jdbcTemplate.query(sql, new ApplicationRowMapper());
    }

    @Override
    public Optional<Application> findByUuid(String uuid) {
        String sql = "SELECT * FROM applications WHERE uuid = :uuid AND is_deleted = false";
        MapSqlParameterSource params = new MapSqlParameterSource().addValue("uuid", uuid);
        return jdbcTemplate.query(sql, params, new ApplicationRowMapper())
                .stream().findFirst();
    }

    @Override
    public Optional<Application> findByNameVersionVendor(String name, String version, String vendorName) {
        String sql = "SELECT * FROM applications WHERE name = :name AND version = :version AND vendor_name = :vendorName AND is_deleted = false";
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("name", name)
                .addValue("version", version)
                .addValue("vendorName", vendorName);
        return jdbcTemplate.query(sql, params, new ApplicationRowMapper())
                .stream().findFirst();
    }

    @Transactional
    @Override
    public int update(String uuid, Application application) {
        String sql = "UPDATE applications SET name = :name, version = :version, vendor_name = :vendorName, " +
                "installed_date = :installedDate, updated_at = CURRENT_TIMESTAMP WHERE uuid = :uuid AND is_deleted = false";
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("uuid", uuid)
                .addValue("name", application.getName())
                .addValue("version", application.getVersion())
                .addValue("vendorName", application.getVendorName())
                .addValue("installedDate", application.getInstalledDate());
        return jdbcTemplate.update(sql, params);
    }

    @Transactional
    @Override
    public int softDelete(String uuid) {
        String sql = "UPDATE applications SET is_deleted = true, updated_at = CURRENT_TIMESTAMP WHERE uuid = :uuid";
        MapSqlParameterSource params = new MapSqlParameterSource().addValue("uuid", uuid);
        return jdbcTemplate.update(sql, params);
    }

    @Transactional
    @Override
    public int softDeleteByNameAndVendor(String name, String vendorName, String excludeVersion) {
        String sql = "UPDATE applications SET is_deleted = true, updated_at = CURRENT_TIMESTAMP " +
                "WHERE name = :name AND vendor_name = :vendorName AND version != :excludeVersion AND is_deleted = false";
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("name", name)
                .addValue("vendorName", vendorName)
                .addValue("excludeVersion", excludeVersion);
        return jdbcTemplate.update(sql, params);
    }
}