package com.isteer.cvssapplication.datastore.dao.impl;

import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import com.isteer.cvssapplication.datastore.dao.ApplicationDao;
import com.isteer.cvssapplication.datastore.dao.rowmapper.RowMapper;
import com.isteer.cvssapplication.datastore.entity.Application;


@Repository
public class ApplicationDaoImpl implements ApplicationDao {
	  private static final Logger logger = LoggerFactory.getLogger(ApplicationDaoImpl.class);

	    @Autowired
	    private NamedParameterJdbcTemplate jdbcTemplate;

	    @Override
	    public int save(Application application) {
	        String sql = "INSERT INTO applications (uuid, name, version, vendor_name, created_at) " +
	                "VALUES (:uuid, :name, :version, :vendorName, :createdAt)";
	        MapSqlParameterSource params = new MapSqlParameterSource()
	                .addValue("uuid", application.getUuid())
	                .addValue("name", application.getName())
	                .addValue("version", application.getVersion())
	                .addValue("vendorName", application.getVendorName())
	                .addValue("createdAt", application.getCreatedAt());
	        logger.debug("Saving application with UUID: {}", application.getUuid());
	        return jdbcTemplate.update(sql, params);
	    }

	    @Override
	    public Optional<Application> findByNameVersionVendor(String name, String version, String vendorName) {
	        String sql = "SELECT * FROM applications " +
                    "WHERE name = :name " +
                    "AND (version = :version OR (version IS NULL AND :version IS NULL)) " +
                    "AND (vendor_name = :vendorName OR (vendor_name IS NULL AND :vendorName IS NULL)) ";
	        MapSqlParameterSource params = new MapSqlParameterSource()
	                .addValue("name", name)
	                .addValue("version", version)
	                .addValue("vendorName", vendorName);
	        try {
	            Application application = jdbcTemplate.queryForObject(sql, params, RowMapper::mapApplicationRow);
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
	                "WHERE ca.computer_uuid = :computerUuid " +
	                "AND a.name = :name " +
	                "AND (a.vendor_name = :vendorName OR (a.vendor_name IS NULL AND :vendorName IS NULL)) " +
	                "AND ca.is_deleted = false";
	        MapSqlParameterSource params = new MapSqlParameterSource()
	                .addValue("computerUuid", computerUuid)
	                .addValue("name", name)
	                .addValue("vendorName", vendorName);
	        try {
	            Application application = jdbcTemplate.queryForObject(sql, params, RowMapper::mapApplicationRow);
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
	        return jdbcTemplate.query(sql, params, RowMapper::mapApplicationRow);
	    }

	    @Override
	    public Optional<Application> findByUuidAndIsDeletedFalse(String uuid) {
	        String sql = "SELECT * FROM applications WHERE uuid = :uuid";
	        MapSqlParameterSource params = new MapSqlParameterSource("uuid", uuid);
	        try {
	            Application application = jdbcTemplate.queryForObject(sql, params, RowMapper::mapApplicationRow);
	            return Optional.ofNullable(application);
	        } catch (Exception e) {
	            logger.debug("No application found for UUID: {}", uuid);
	            return Optional.empty();
	        }
	    }

	  }
