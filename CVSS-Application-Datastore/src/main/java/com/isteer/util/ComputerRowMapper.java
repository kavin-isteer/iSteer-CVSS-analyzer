package com.isteer.util;

import java.sql.ResultSet;
import java.sql.SQLException;

import org.springframework.jdbc.core.RowMapper;

import com.isteer.entity.Computer;

// Implementation of RowMapper interface to map rows of a ResultSet to Computer objects
public class ComputerRowMapper implements RowMapper<Computer> {

    @Override
    public Computer mapRow(ResultSet rs, int rowNum) throws SQLException {
        // Create a new instance of the Computer entity
        Computer computer = new Computer();
        
        // Map the 'id' column from the ResultSet to the Computer object's 'id' field
        computer.setId(rs.getLong("id"));
        
        // Map the 'uuid' column from the ResultSet to the Computer object's 'uuid' field
        computer.setUuid(rs.getString("uuid"));
        
        // Map the 'ip_address' column from the ResultSet to the Computer object's 'ipAddress' field
        computer.setIpAddress(rs.getString("ip_address"));
        
        // Map the 'hostName' column from the ResultSet to the Computer object's 'hostName' field
        computer.setHostName(rs.getString("hostName"));
        
        // Map the 'os_name' column from the ResultSet to the Computer object's 'osName' field
        computer.setOsName(rs.getString("os_name"));
        
        // Map the 'os_version' column from the ResultSet to the Computer object's 'osVersion' field
        computer.setOsVersion(rs.getString("os_version"));
        
        // Map the 'location' column from the ResultSet to the Computer object's 'location' field
        computer.setLocation(rs.getString("location"));
        
        // Map the 'is_active' column from the ResultSet to the Computer object's 'active' field
        computer.setActive(rs.getBoolean("is_active"));
        
        // Map the 'status' column from the ResultSet to the Computer object's 'status' field
        computer.setStatus(rs.getBoolean("status"));
        
        // Map the 'created_at' column from the ResultSet to the Computer object's 'createdAt' field
        // Convert the SQL Timestamp to LocalDateTime for proper handling in Java
        computer.setCreatedAt(rs.getTimestamp("created_at").toLocalDateTime());
        
        // Map the 'updated_at' column from the ResultSet to the Computer object's 'updatedAt' field
        // Check if the 'updated_at' column is not null before converting to LocalDateTime
        computer.setUpdatedAt(rs.getTimestamp("updated_at") != null ?
                rs.getTimestamp("updated_at").toLocalDateTime() : null);
        
        // Return the fully mapped Computer object
        return computer;
    }
}
