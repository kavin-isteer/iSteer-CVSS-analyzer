package com.isteer.cvssapplication.datastore.dao.impl;

import java.sql.Timestamp;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.DataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import com.isteer.cvssapplication.datastore.dao.ApplicationDao;
import com.isteer.cvssapplication.datastore.dao.rowmapper.ApplicationRowMapper;
import com.isteer.cvssapplication.datastore.dao.rowmapper.ApplicationWithVulnerabilitiesExtractor;
import com.isteer.cvssapplication.datastore.dto.SoftwareDTO;
import com.isteer.cvssapplication.datastore.entity.Application;
import com.isteer.cvssapplication.datastore.enums.CVSSEnum;
import com.isteer.cvssapplication.datastore.exception.BussinessException;

@Repository
public class ApplicationDaoImpl implements ApplicationDao {
	private static final Logger logger = LoggerFactory.getLogger(ApplicationDaoImpl.class);

	@Autowired
	private NamedParameterJdbcTemplate jdbcTemplate;

	@Autowired
	private JdbcTemplate template;

	@Override
	public List<Application> findByComputerUuid(String computerUuid, Boolean status) {
		String sql = """
				    SELECT
				        a.id,
				        a.uuid,
				        a.name,
				        a.version,
				        a.vendor_name,
				        a.created_at,
				        ca.installed_date,
				        ca.updated_at AS ca_updated_at,
				        ca.is_deleted AS ca_is_deleted,
				        v.id AS v_id,
				        v.uuid AS v_uuid,
				        v.cve_id,
				        v.severity,
				        v.description,
				        v.vector_string,
				        v.source_identifier,
				        v.cvss_score,
				        v.cvss_version,
				        v.created_at AS v_created_at,
				        v.is_deleted AS v_is_deleted,
				        acnd.cpe_name
				    FROM applications a
				    JOIN computer_applications ca ON a.uuid = ca.application_uuid
				    JOIN computers c ON ca.computer_uuid = c.uuid
				    LEFT JOIN application_vulnerabilities av ON a.uuid = av.application_uuid
				    LEFT JOIN vulnerabilities v ON av.vulnerability_uuid = v.uuid AND v.is_deleted = false
				    LEFT JOIN application_cpe_name_details acnd ON a.uuid = acnd.application_uuid
				    WHERE c.uuid = :computerUuid AND c.is_deleted = false
				""";

		MapSqlParameterSource params = new MapSqlParameterSource();
		params.addValue("computerUuid", computerUuid);

		if (status != null) {
			sql += " AND ca.is_deleted = :isDeleted";
			params.addValue("isDeleted", status);
		}

		try {
			List<Application> applications = jdbcTemplate.query(sql, params,
					new ApplicationWithVulnerabilitiesExtractor());
			if (applications.isEmpty()) {
				// Check if the computer exists by querying the computers table
				String checkComputerSql = "SELECT COUNT(*) FROM computers WHERE uuid = :computerUuid AND is_deleted = false";
				Integer count = jdbcTemplate.queryForObject(checkComputerSql, params, Integer.class);
				if (count == null || count == 0) {
					logger.warn("Computer not found or deleted for UUID: {}", computerUuid);
					throw new BussinessException(CVSSEnum.COMPUTER_NOT_FOUND);
				}
			}
			return applications;
		} catch (DataAccessException e) {
			logger.warn("Computer not found or deleted for UUID: {}", computerUuid);
			throw new BussinessException(CVSSEnum.COMPUTER_NOT_FOUND);
		}
	}

	@Override
	public Map<Application, Boolean> isRecordExists1(List<SoftwareDTO> applications) {
		Map<Application, Boolean> result = new LinkedHashMap<>();

		if (applications.isEmpty()) {
			return result;
		}

		// Create temporary table
		template.execute("CREATE TEMPORARY TABLE IF NOT EXISTS temp_apps_to_check (" + "name VARCHAR(255), "
				+ "version VARCHAR(255), " + "vendor_name VARCHAR(255))");

		// Clear previous data
		template.execute("TRUNCATE TABLE temp_apps_to_check");

		// Batch insert all applications to check
		template.batchUpdate("INSERT INTO temp_apps_to_check (name, version, vendor_name) VALUES (?, ?, ?)",
				applications.stream().map(app -> new Object[] { app.getName(), app.getVersion(), app.getVendorName() })
						.collect(Collectors.toList()));

		List<Map<String, Object>> rows = template.queryForList("SELECT a.id, a.uuid, t.name, t.version, t.vendor_name, "
				+ "a.created_at, CASE WHEN a.id IS NULL THEN FALSE ELSE TRUE END AS exists_flag "
				+ "FROM temp_apps_to_check t " + "LEFT JOIN applications a ON "
				+ "a.name = t.name AND a.version = t.version AND a.vendor_name = t.vendor_name");

		// Process results
		for (Map<String, Object> row : rows) {
			Application app = new Application();
			app.setId(row.get("id") != null ? ((Number) row.get("id")).longValue() : null);
			app.setUuid((String) row.get("uuid"));
			app.setName((String) row.get("name"));
			app.setVersion((String) row.get("version"));
			app.setVendorName((String) row.get("vendor_name"));
//		        Timestamp createdAt = (Timestamp)row.get("created_at") != null ? (Timestamp)row.get("created_at") : null;
			app.setCreatedAt(
					row.get("created_at") != null ? ((Timestamp) row.get("created_at")).toLocalDateTime() : null);

			Long exists = (Long) row.get("exists_flag");
			// FIXME: This should be Boolean, but the query returns Long. Dont do like this.
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
		String sql = "SELECT a.id, a.uuid, a.name, a.version, a.vendor_name, a.created_at FROM applications a WHERE a.uuid = :uuid";
		MapSqlParameterSource params = new MapSqlParameterSource("uuid", uuid);
		try {
			Application application = jdbcTemplate.queryForObject(sql, params, new ApplicationRowMapper());
			return Optional.ofNullable(application);
		} catch (Exception e) {
			logger.debug("No application found for UUID: {}", uuid);
			return Optional.empty();
		}
	}

	@Override
	public List<Application> findAllUnresolvedCpeApplications() {
		String sql = "SELECT a.id, a.uuid, a.name, a.version, a.vendor_name, a.created_at FROM applications a JOIN application_cpe_name_details acnd ON a.uuid = acnd.application_uuid WHERE acnd.is_resolved_cpe = false";
		logger.debug("Fetching all unresolved CPE applications");
		List<Application> applications = jdbcTemplate.query(sql, new ApplicationRowMapper());
		logger.debug("Found {} unresolved CPE applications", applications.size());
		return applications;
	}

}
