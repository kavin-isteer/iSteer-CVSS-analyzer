package com.isteer.util;

import java.sql.ResultSet;
import java.sql.SQLException;

import org.springframework.jdbc.core.RowMapper;

import com.isteer.entity.Dependency;

// Implements the RowMapper interface to map rows of a ResultSet to Dependency objects
public class DependencyRowMapper implements RowMapper<Dependency> {

    @Override
    public Dependency mapRow(ResultSet rs, int rowNum) throws SQLException {
        // Create a new Dependency object to hold the mapped data
        Dependency dependency = new Dependency();

        // Map the "dependency_id" column from the ResultSet to the id field of the Dependency object
        dependency.setId(rs.getLong("dependency_id"));

        // Map the "dependency_uuid" column to the uuid field
        dependency.setUuid(rs.getString("dependency_uuid"));

        // Map the "application_uuid" column to the applicationUuid field
        dependency.setApplicationUuid(rs.getString("application_uuid"));

        // Map the "name" column to the name field
        dependency.setName(rs.getString("name"));

        // Map the "version" column to the version field
        dependency.setVersion(rs.getString("version"));

        // Map the "group_id" column to the groupId field
        dependency.setGroupId(rs.getString("group_id"));

        // Map the "artifact_id" column to the artifactId field
        dependency.setArtifactId(rs.getString("artifact_id"));

        // Map the "dependency_status" column to the status field as a boolean
        dependency.setStatus(rs.getBoolean("dependency_status"));

        // Map the "dependency_created_at" column to the createdAt field, converting it to LocalDateTime
        dependency.setCreatedAt(rs.getTimestamp("dependency_created_at").toLocalDateTime());

        // Map the "dependency_updated_at" column to the updatedAt field, converting it to LocalDateTime
        // If the column value is null, set updatedAt to null
        dependency.setUpdatedAt(
                rs.getTimestamp("dependency_updated_at") != null ? rs.getTimestamp("dependency_updated_at").toLocalDateTime() : null);

        // Return the fully populated Dependency object
        return dependency;
    }
}
