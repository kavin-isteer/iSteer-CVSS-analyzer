package com.isteer.util;

import java.sql.ResultSet;
import java.sql.SQLException;

import org.springframework.jdbc.core.RowMapper;

import com.isteer.entity.Application;

// This class implements the RowMapper interface to map rows of a ResultSet to Application objects.
public class ApplicationRowMapper implements RowMapper<Application> {

    @Override
    public Application mapRow(ResultSet rs, int rowNum) throws SQLException {
        // Create a new Application object to hold the mapped data.
        Application application = new Application();

        // Map the "id" column from the ResultSet to the Application object's id field.
        application.setId(rs.getLong("id"));

        // Map the "uuid" column from the ResultSet to the Application object's uuid field.
        application.setUuid(rs.getString("uuid"));

        // Map the "computer_uuid" column from the ResultSet to the Application object's computerUuid field.
        application.setComputerUuid(rs.getString("computer_uuid"));

        // Map the "name" column from the ResultSet to the Application object's name field.
        application.setName(rs.getString("name"));

        // Map the "version" column from the ResultSet to the Application object's version field.
        application.setVersion(rs.getString("version"));

        // Map the "vendor" column from the ResultSet to the Application object's vendor field.
        application.setVendor(rs.getString("vendor"));

        // Map the "install_date" column from the ResultSet to the Application object's installedDate field.
        // Convert the SQL Date to LocalDate if the column value is not null.
        application.setInstalledDate(rs.getDate("install_date") != null ? rs.getDate("install_date").toLocalDate() : null);

        // Map the "status" column from the ResultSet to the Application object's status field.
        application.setStatus(rs.getBoolean("status"));

        // Map the "created_at" column from the ResultSet to the Application object's createdAt field.
        // Convert the SQL Timestamp to LocalDateTime.
        application.setCreatedAt(rs.getTimestamp("created_at").toLocalDateTime());

        // Map the "updated_at" column from the ResultSet to the Application object's updatedAt field.
        // Convert the SQL Timestamp to LocalDateTime if the column value is not null.
        application.setUpdatedAt(rs.getTimestamp("updated_at") != null ? rs.getTimestamp("updated_at").toLocalDateTime() : null);

        // Return the fully populated Application object.
        return application;
    }
}
