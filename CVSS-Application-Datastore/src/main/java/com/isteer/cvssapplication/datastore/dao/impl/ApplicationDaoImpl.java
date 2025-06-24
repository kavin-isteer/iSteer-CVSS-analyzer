package com.isteer.cvssapplication.datastore.dao.impl;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import com.isteer.cvssapplication.datastore.dao.ApplicationDao;
import com.isteer.cvssapplication.datastore.dao.rowmapper.RowMapper;
import com.isteer.cvssapplication.datastore.dto.SoftwareDTO;
import com.isteer.cvssapplication.datastore.entity.Application;

@Repository
public class ApplicationDaoImpl implements ApplicationDao {
	private static final Logger logger = LoggerFactory.getLogger(ApplicationDaoImpl.class);

	@Autowired
	private NamedParameterJdbcTemplate jdbcTemplate;

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
	public List<Application> findByComputerUuid(String computerUuid) {
		String sql = "SELECT a.* FROM applications a "
				+ "JOIN computer_applications ca ON a.uuid = ca.application_uuid "
				+ "JOIN computers c ON ca.computer_uuid = c.uuid "
				+ "WHERE c.uuid = :computerUuid AND c.is_deleted = false AND ca.is_deleted = false";
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

	@Override
	public Map<String, Application> isRecordExists(List<SoftwareDTO> applications) {
		return null;
	}
	
	public Map<String, Application> isRecordExists1(List<SoftwareDTO> applications) {
		logger.debug("Checking existence of {} applications in a single query", applications.size());
		Map<String, Application> result = new HashMap<>();
		// Initialize map with all applications set to null (non-existing)
		applications.forEach(software -> {
			String version = software.getVersion() == null ? "" : software.getVersion();
			String vendorName = software.getVendorName() == null ? "" : software.getVendorName();
			String key = software.getName() + "|" + version + "|" + vendorName;
			result.put(key, null);
		});

		// Prepare parameters for IN clause
		List<String> names = new ArrayList<>();
		List<String> versions = new ArrayList<>();
		List<String> vendorNames = new ArrayList<>();
		for (SoftwareDTO software : applications) {
			names.add(software.getName());
			versions.add(software.getVersion() == null ? "" : software.getVersion());
			vendorNames.add(software.getVendorName() == null ? "" : software.getVendorName());
		}

		String sql = "SELECT uuid, name, version, vendor_name, created_at " + "FROM applications "
				+ "WHERE (name, COALESCE(version, ''), COALESCE(vendor_name, '')) IN (:values)";
		MapSqlParameterSource params = new MapSqlParameterSource();
		List<List<String>> valueTuples = new ArrayList<>();
		for (int i = 0; i < applications.size(); i++) {
			valueTuples.add(List.of(names.get(i), versions.get(i), vendorNames.get(i)));
		}
		params.addValue("values", valueTuples);
		
		List<Application> existingApps = jdbcTemplate.query(sql, params, RowMapper::mapApplicationRow);
		existingApps.forEach(app -> {
			String key = app.getName() + "|" + (app.getVersion() == null ? "" : app.getVersion()) + "|"
					+ (app.getVendorName() == null ? "" : app.getVendorName());
			result.put(key, app);
		});
	


		logger.debug("Found {} existing applications", existingApps.size());
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
}
