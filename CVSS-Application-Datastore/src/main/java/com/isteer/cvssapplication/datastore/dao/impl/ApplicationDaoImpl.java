package com.isteer.cvssapplication.datastore.dao.impl;

import java.sql.Timestamp;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import com.isteer.cvssapplication.datastore.dao.ApplicationDao;
import com.isteer.cvssapplication.datastore.dao.rowmapper.ApplicationRowMapper;
import com.isteer.cvssapplication.datastore.dao.rowmapper.RowMapper;
import com.isteer.cvssapplication.datastore.dto.SoftwareDTO;
import com.isteer.cvssapplication.datastore.entity.Application;

@Repository
public class ApplicationDaoImpl implements ApplicationDao {
	private static final Logger logger = LoggerFactory.getLogger(ApplicationDaoImpl.class);

	@Autowired
	private NamedParameterJdbcTemplate jdbcTemplate;
	
	@Autowired
	private JdbcTemplate template;
	
	@Override
	public int save(Application application) {
		String sql = "INSERT INTO applications (uuid, name, version, vendor_name, created_at) "
				+ "VALUES (:uuid, :name, :version, :vendorName, :createdAt)";
		MapSqlParameterSource params = new MapSqlParameterSource().addValue("uuid", application.getUuid())
				.addValue("name", application.getName()).addValue("version", application.getVersion())
				.addValue("vendorName", application.getVendorName()).addValue("createdAt", application.getCreatedAt());
		logger.debug("Saving application with UUID: {}", application.getUuid());
		return jdbcTemplate.update(sql, params);
	}

	@Override
	public Optional<Application> findByNameVersionVendor(String name, String version, String vendorName) {
		String sql = "SELECT * FROM applications " + "WHERE name = :name "
				+ "AND (version = :version OR (version IS NULL AND :version IS NULL)) "
				+ "AND (vendor_name = :vendorName OR (vendor_name IS NULL AND :vendorName IS NULL)) ";
		MapSqlParameterSource params = new MapSqlParameterSource().addValue("name", name).addValue("version", version)
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
		String sql = "SELECT a.* FROM applications a "
				+ "JOIN computer_applications ca ON a.uuid = ca.application_uuid "
				+ "WHERE ca.computer_uuid = :computerUuid " + "AND a.name = :name "
				+ "AND (a.vendor_name = :vendorName OR (a.vendor_name IS NULL AND :vendorName IS NULL)) "
				+ "AND ca.is_deleted = false";
		MapSqlParameterSource params = new MapSqlParameterSource().addValue("computerUuid", computerUuid)
				.addValue("name", name).addValue("vendorName", vendorName);
		try {
			Application application = jdbcTemplate.queryForObject(sql, params, RowMapper::mapApplicationRow);
			return Optional.ofNullable(application);
		} catch (Exception e) {
			logger.debug("No application found for computer UUID: {}, name: {}, vendor: {}", computerUuid, name,
					vendorName);
			return Optional.empty();
		}
	}


	
	 @Override
	    public List<Application> findByComputerUuid(String computerUuid, Boolean status) {
	        String sql = "SELECT a.*, ca.installed_date FROM applications a "
	                + "JOIN computer_applications ca ON a.uuid = ca.application_uuid "
	                + "JOIN computers c ON ca.computer_uuid = c.uuid "
	                + "WHERE c.uuid = :computerUuid AND c.is_deleted = false";
	        
	        if (status != null) {
	            sql += " AND ca.is_deleted = :isDeleted";
	        }
	        
	        MapSqlParameterSource params = new MapSqlParameterSource("computerUuid", computerUuid);
	        if (status != null) {
	            params.addValue("isDeleted", status);
	        }
	        
	        return jdbcTemplate.query(sql, params, RowMapper::mapApplicationRow);
	    }

	@Override
	public Optional<Application> findByUuidAndIsDeletedFalse(String uuid) {
		String sql = "SELECT * FROM applications WHERE uuid = :uuid AND is_deleted = false";
		MapSqlParameterSource params = new MapSqlParameterSource("uuid", uuid);
		try {
			Application application = jdbcTemplate.queryForObject(sql, params, RowMapper::mapApplicationRow);
			return Optional.ofNullable(application);
		} catch (Exception e) {
			logger.debug("No application found for UUID: {}", uuid);
			return Optional.empty();
		}
	}
	 

	@Override
	public Map<Application, Boolean> isRecordExists(List<SoftwareDTO> applications) {
		Map<Application, Boolean> result = new HashMap<>();
		String sql = "SELECT id, uuid, name, version, vendor_name, created_at FROM applications WHERE (name,version,vendor_name) IN (:name,:version,:vendor)";
		for(SoftwareDTO app:applications) {
			MapSqlParameterSource params = new MapSqlParameterSource();
			params.addValue("name", app.getName());
			params.addValue("version", app.getVersion());
			params.addValue("vendor", app.getVendorName());
			try {
			Application appFromDb = jdbcTemplate.queryForObject(sql, params, RowMapper::mapApplicationRow);
			result.put(appFromDb, true);
			}catch (Exception e) {
				Application wrkApp = new Application();
				wrkApp.setName(app.getName());
				wrkApp.setVendorName(app.getVendorName());
				wrkApp.setVersion(app.getVersion());
				wrkApp.setInstalledDate(app.getInstalledDate());
			result.put(wrkApp, false);
			}
		}
		return result;
	}
	
	@Override
	public Map<Application, Boolean> isRecordExists1(List<SoftwareDTO> applications) {
		 Map<Application, Boolean> result = new LinkedHashMap<>();
		    
		    if (applications.isEmpty()) {
		        return result;
		    }

		    // Create temporary table
		    template.execute("CREATE TEMPORARY TABLE IF NOT EXISTS temp_apps_to_check (" +
		        "name VARCHAR(255), " +
		        "version VARCHAR(255), " +
		        "vendor_name VARCHAR(255))");

		    // Clear previous data
		    template.execute("TRUNCATE TABLE temp_apps_to_check");

		    // Batch insert all applications to check
		    template.batchUpdate(
		        "INSERT INTO temp_apps_to_check (name, version, vendor_name) VALUES (?, ?, ?)",
		        applications.stream()
		            .map(app -> new Object[]{app.getName(), app.getVersion(), app.getVendorName()})
		            .collect(Collectors.toList())
		    );

		    
		    List<Map<String, Object>> rows = template.queryForList(
		        "SELECT a.id, a.uuid, t.name, t.version, t.vendor_name, " +
		        "a.created_at, CASE WHEN a.id IS NULL THEN FALSE ELSE TRUE END AS exists_flag " +
		        "FROM temp_apps_to_check t " +
		        "LEFT JOIN applications a ON " +
		        "a.name = t.name AND a.version = t.version AND a.vendor_name = t.vendor_name"
		    );

		 // Process results
		    for (Map<String, Object> row : rows) {
		        Application app = new Application();
		        app.setId(row.get("id") != null ? ((Number)row.get("id")).longValue() : null);
		        app.setUuid((String)row.get("uuid"));
		        app.setName((String)row.get("name"));
		        app.setVersion((String)row.get("version"));
		        app.setVendorName((String)row.get("vendor_name"));
//		        Timestamp createdAt = (Timestamp)row.get("created_at") != null ? (Timestamp)row.get("created_at") : null;
		        app.setCreatedAt(row.get("created_at") != null ? ((Timestamp)row.get("created_at")).toLocalDateTime() : null);
		        
		        Long exists = (Long)row.get("exists_flag");
		        //FIXME: This should be Boolean, but the query returns Long. Dont do like this.
		        result.put(app, Boolean.valueOf(exists.toString()));
		    }
		    
		    // Clean up
		    template.execute("DROP TEMPORARY TABLE IF EXISTS temp_apps_to_check");

		    return result;
	}

	@Override
	public int[] batchSave(List<Application> applications) {
		String sql = "INSERT INTO applications (uuid, name, version, vendor_name, created_at) "
				+ "VALUES (:uuid, :name, :version, :vendorName, :createdAt)";
		List<MapSqlParameterSource> paramsList = applications.stream()
				.map(app -> new MapSqlParameterSource().addValue("uuid", app.getUuid()).addValue("name", app.getName())
						.addValue("version", app.getVersion()).addValue("vendorName", app.getVendorName())
						.addValue("createdAt", app.getCreatedAt()))
				.collect(Collectors.toList());
		logger.debug("Batch saving {} applications", applications.size());
		return jdbcTemplate.batchUpdate(sql, paramsList.toArray(new MapSqlParameterSource[0]));
	}

	@Override
	public List<Application> findAllApplications() {
		String query = "SELECT id, uuid, name, version, vendor_name, created_at FROM applications";
		logger.debug("Fetching all applications");
		List<Application> applications = jdbcTemplate.query(query, new ApplicationRowMapper());
		logger.debug("Found {} applications", applications.size());
		return applications;
	}

	 @Override
	    public Optional<Application> findByApplicationUuid(String uuid) {
	        String sql = "SELECT a.*, MIN(ca.installed_date) as installed_date " +
	                     "FROM applications a " +
	                     "LEFT JOIN computer_applications ca ON a.uuid = ca.application_uuid " +
	                     "WHERE a.uuid = :uuid " +
	                     "GROUP BY a.id, a.uuid, a.name, a.version, a.vendor_name, a.created_at";
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
