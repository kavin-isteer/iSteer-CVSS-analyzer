package com.isteer.repository;

import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import com.isteer.entity.Application;
import com.isteer.repository.dao.ApplicationRepositoryDao;
import com.isteer.util.RowMapperUtil;

@Repository
public class ApplicationRepository implements ApplicationRepositoryDao {
	  private static final Logger logger = LoggerFactory.getLogger(ApplicationRepository.class);

	    @Autowired
	    private NamedParameterJdbcTemplate jdbcTemplate;

	    @Override
	    public int save(Application application) {
	        String sql = "INSERT INTO applications (uuid, name, version, vendor_name) " +
	                "VALUES (:uuid, :name, :version, :vendorName)";
	        MapSqlParameterSource params = new MapSqlParameterSource()
	                .addValue("uuid", application.getUuid())
	                .addValue("name", application.getName())
	                .addValue("version", application.getVersion())
	                .addValue("vendorName", application.getVendorName());
	        logger.debug("Saving application with UUID: {}", application.getUuid());
	        return jdbcTemplate.update(sql, params);
	    }

	    @Override
	    public Optional<Application> findByNameVersionVendor(String name, String version, String vendorName) {
	        String sql = "SELECT * FROM applications WHERE name = :name AND version = :version AND vendor_name = :vendorName";
	        MapSqlParameterSource params = new MapSqlParameterSource()
	                .addValue("name", name)
	                .addValue("version", version)
	                .addValue("vendorName", vendorName);
	        try {
	            Application application = jdbcTemplate.queryForObject(sql, params, RowMapperUtil::mapApplicationRow);
	            return Optional.ofNullable(application);
	        } catch (Exception e) {
	            logger.debug("No application found for name: {}, version: {}, vendor: {}", name, version, vendorName);
	            return Optional.empty();
	        }
	    }

	    @Override
	    public Optional<Application> findByComputerUuidAndNameVendor(String computerUuid, String name, String vendorName) {
	        String sql = "SELECT a.* FROM applications a " +
	                "JOIN computer_applications ca ON a.uuid = ca.application_uuid " +
	                "WHERE ca.computer_uuid = :computerUuid AND a.name = :name AND a.vendor_name = :vendorName " +
	                "AND ca.is_deleted = false";
	        MapSqlParameterSource params = new MapSqlParameterSource()
	                .addValue("computerUuid", computerUuid)
	                .addValue("name", name)
	                .addValue("vendorName", vendorName);
	        try {
	            Application application = jdbcTemplate.queryForObject(sql, params, RowMapperUtil::mapApplicationRow);
	            return Optional.ofNullable(application);
	        } catch (Exception e) {
	            logger.debug("No application found for computer UUID: {}, name: {}, vendor: {}", computerUuid, name, vendorName);
	            return Optional.empty();
	        }
	    }

	    @Override
	    public List<Application> findByComputerUuid(String computerUuid) {
	        String sql = "SELECT a.* FROM applications a " +
	                "JOIN computer_applications ca ON a.uuid = ca.application_uuid " +
	                "JOIN computers c ON ca.computer_uuid = c.uuid " +
	                "WHERE c.uuid = :computerUuid AND c.is_deleted = false AND ca.is_deleted = false";
	        MapSqlParameterSource params = new MapSqlParameterSource("computerUuid", computerUuid);
	        return jdbcTemplate.query(sql, params, RowMapperUtil::mapApplicationRow);
	    }

	    @Override
	    public Optional<Application> findByUuidAndIsDeletedFalse(String uuid) {
	        String sql = "SELECT * FROM applications WHERE uuid = :uuid";
	        MapSqlParameterSource params = new MapSqlParameterSource("uuid", uuid);
	        try {
	            Application application = jdbcTemplate.queryForObject(sql, params, RowMapperUtil::mapApplicationRow);
	            return Optional.ofNullable(application);
	        } catch (Exception e) {
	            logger.debug("No application found for UUID: {}", uuid);
	            return Optional.empty();
	        }
	    }

	  }
