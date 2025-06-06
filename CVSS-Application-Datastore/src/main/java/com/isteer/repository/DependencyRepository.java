package com.isteer.repository;

import java.util.List;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.dao.EmptyResultDataAccessException;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;

import com.isteer.entity.Dependency;
import com.isteer.repository.dao.DependencyRepositoryDao;
import com.isteer.util.DependencyResultSetExtractor;
import com.isteer.util.DependencyRowMapper;

@Repository
public class DependencyRepository implements DependencyRepositoryDao {

    // Injecting NamedParameterJdbcTemplate to execute SQL queries with named parameters
    @Autowired
    NamedParameterJdbcTemplate jdbcTemplate;

    @Transactional
    @Override
    public int save(Dependency dependency) {
        // Validate if the application and computer associated with the dependency are active
        String validateSql = """
            SELECT COUNT(*)
            FROM applications a
            JOIN computers c ON a.computer_uuid = c.uuid
            WHERE a.uuid = :applicationUuid
              AND a.status = TRUE
              AND c.status = TRUE AND c.is_active = TRUE
        """;

        // Setting the parameter for the validation query
        MapSqlParameterSource validateParams = new MapSqlParameterSource()
                .addValue("applicationUuid", dependency.getApplicationUuid());

        // Execute the validation query and retrieve the count
        Integer count = jdbcTemplate.queryForObject(validateSql, validateParams, Integer.class);

        // If the count is 0 or null, return -4 indicating the application or computer is not active
        if (count == null || count == 0) {
            return -4;
        }

        // Insert the dependency into the database
        String sql = """
            INSERT INTO dependencies (uuid, application_uuid, name, version, group_id, artifact_id)
            VALUES (:uuid, :applicationId, :name, :version, :groupId, :artifactId)
        """;

        // Generate a new UUID for the dependency
        dependency.setUuid(UUID.randomUUID().toString());

        // Set the parameters for the insert query
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("uuid", dependency.getUuid())
                .addValue("applicationId", dependency.getApplicationUuid())
                .addValue("name", dependency.getName())
                .addValue("version", dependency.getVersion())
                .addValue("groupId", dependency.getGroupId())
                .addValue("artifactId", dependency.getArtifactId());

        // Execute the insert query and return the number of rows affected
        return jdbcTemplate.update(sql, params);
    }

    @Override
    public List<Dependency> findAll() {
        // SQL query to fetch all active dependencies along with their associated applications and computers
    	String sql = """
      SELECT dependencies.id AS dependency_id, dependencies.uuid AS dependency_uuid, dependencies.application_uuid,
    		          dependencies.name, dependencies.version, dependencies.group_id, dependencies.artifact_id,
    		           dependencies.status AS dependency_status, dependencies.created_at AS dependency_created_at,
    		           dependencies.updated_at AS dependency_updated_at
    		    FROM dependencies
    		    JOIN applications ON dependencies.application_uuid = applications.uuid AND applications.status = TRUE
    		    JOIN computers ON applications.computer_uuid = computers.uuid AND computers.status = TRUE
    		     AND computers.is_active = TRUE
    		    WHERE dependencies.status = TRUE
    		""";
        // Execute the query and map the result to a list of Dependency objects using DependencyRowMapper
        return jdbcTemplate.query(sql, new DependencyRowMapper());
    }

    @Override
    public Dependency findByUuid(String uuid) {
        // SQL query to fetch a dependency by its UUID if it is active
    	String sql = """
    		    SELECT id AS dependency_id,
    		           uuid AS dependency_uuid, application_uuid, name, version, group_id, artifact_id,
    		           status AS dependency_status, created_at AS dependency_created_at, 
    		           updated_at AS dependency_updated_at FROM dependencies WHERE uuid = :uuid AND status = TRUE
    		""";

        // Set the parameter for the query
        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("uuid", uuid);

        try {
            // Execute the query and map the result to a Dependency object using DependencyRowMapper
            return jdbcTemplate.queryForObject(sql, params, new DependencyRowMapper());
        } catch (EmptyResultDataAccessException e) {
            // Return null if no result is found
            return null;
        }
    }

    @Override
    public Dependency findByDependencyUuid(String uuid) {
        // SQL query to fetch a dependency along with its associated vulnerabilities by its UUID
    	String sql = """
    		    SELECT d.id AS dep_id, d.uuid AS dep_uuid, d.application_uuid AS dep_application_uuid,
    		           d.name AS dep_name, d.version AS dep_version, d.group_id AS dep_group_id,
    		           d.artifact_id AS dep_artifact_id, d.status AS dep_status,
    		           d.created_at AS dep_created_at, d.updated_at AS dep_updated_at,
    		           v.id AS vuln_id, v.uuid AS vuln_uuid, v.cve_id AS vuln_cve_id, v.severity AS vuln_severity,
    		           v.description AS vuln_description, v.cvss_score AS vuln_cvss_score,
    		           v.published_date AS vuln_published_date, v.status AS vuln_status,
    		           v.created_at AS vuln_created_at, v.updated_at AS vuln_updated_at
    		    FROM dependencies d
    		    LEFT JOIN vulnerabilities v ON v.dependency_uuid = d.uuid AND v.status = TRUE
    		    WHERE d.uuid = :uuid AND d.status = TRUE
    		""";

        // Set the parameter for the query
        MapSqlParameterSource params = new MapSqlParameterSource().addValue("uuid", uuid);

        try {
            // Execute the query and map the result using DependencyResultSetExtractor
            return jdbcTemplate.query(sql, params, new DependencyResultSetExtractor());
        } catch (EmptyResultDataAccessException e) {
            // Return null if no result is found
            return null;
        }
    }

    @Transactional
    @Override
    public int update(String uuid, Dependency dependency) {
        // SQL query to update a dependency's details by its UUID
    	String sql = """
    		    UPDATE dependencies
    		    SET name = :name, version = :version,
    		        group_id = :groupId, artifact_id = :artifactId
    		    WHERE uuid = :uuid
    		""";

        // Set the parameters for the update query
        MapSqlParameterSource params = new MapSqlParameterSource().addValue("name", dependency.getName())
                .addValue("version", dependency.getVersion()).addValue("groupId", dependency.getGroupId())
                .addValue("artifactId", dependency.getArtifactId()).addValue("updatedAt", dependency.getUpdatedAt())
                .addValue("uuid", uuid);

        // Execute the update query and return the number of rows affected
        return jdbcTemplate.update(sql, params);
    }

    @Transactional
    @Override
    public int softDelete(String uuid) {
        // SQL query to perform a soft delete by setting the status to false
    	String sql = """
    		    UPDATE dependencies
    		    SET status = FALSE, updated_at = CURRENT_TIMESTAMP
    		    WHERE uuid = :uuid AND status = TRUE
    		""";

        // Set the parameter for the query
        MapSqlParameterSource params = new MapSqlParameterSource().addValue("uuid", uuid);

        // Execute the update query and return the number of rows affected
        return jdbcTemplate.update(sql, params);
    }
}
