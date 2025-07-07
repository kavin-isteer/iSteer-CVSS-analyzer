package com.isteer.cvssapplication.datastore.dao.rowmapper;

import java.sql.ResultSet;
import java.sql.SQLException;

import com.isteer.cvssapplication.datastore.dto.ComputerApplicationDTO;
import com.isteer.cvssapplication.datastore.entity.Application;
import com.isteer.cvssapplication.datastore.entity.Computer;
import com.isteer.cvssapplication.datastore.entity.ComputerApplication;

public class RowMapper {

    public static Computer mapComputerRow(ResultSet rs, int rowNum) throws SQLException {
        Computer computer = new Computer();
        computer.setId(rs.getLong("id"));
        computer.setUuid(rs.getString("uuid"));
        computer.setDeviceId(rs.getString("device_id"));
        computer.setMachineName(rs.getString("hostname"));
        computer.setIpAddress(rs.getString("ip_address"));
        computer.setOsVersion(rs.getString("os_version"));
        computer.setAntivirusStatus(rs.getString("antivirus_status"));
        computer.setFirewallStatus(rs.getString("firewall_status"));
        computer.setLoggedInUser(rs.getString("logged_in_user"));
        computer.setLastUpdateCheck(rs.getTimestamp("last_update_check") != null ?
                rs.getTimestamp("last_update_check").toLocalDateTime() : null);
        computer.setTimestamp(rs.getTimestamp("timestamp").toLocalDateTime());
        computer.setDeleted(rs.getBoolean("is_deleted"));
        computer.setActive(rs.getBoolean("is_active"));
        computer.setCreatedAt(rs.getTimestamp("created_at").toLocalDateTime());
        computer.setUpdatedAt(rs.getTimestamp("updated_at") != null ?
                rs.getTimestamp("updated_at").toLocalDateTime() : null);
        return computer;
    }

    public static Application mapApplicationRow(ResultSet rs, int rowNum) throws SQLException {
        Application application = new Application();
        application.setId(rs.getLong("id"));
        application.setUuid(rs.getString("uuid"));
        application.setSoftwareName(rs.getString("name"));
        application.setSoftwareVersion(rs.getString("version"));
        application.setVendorName(rs.getString("vendor_name"));
        application.setInstalledDate(rs.getTimestamp("installed_date") != null ?
                rs.getTimestamp("installed_date").toLocalDateTime() : null);
        application.setCreatedAt(rs.getTimestamp("created_at").toLocalDateTime());
        application.setUpdatedAt(rs.getTimestamp("updated_at") != null ?
				rs.getTimestamp("updated_at").toLocalDateTime() : null);
        application.setDeleted(rs.getBoolean("is_deleted"));
        return application;
    }

    public static ComputerApplication mapComputerApplicationRow(ResultSet rs, int rowNum) throws SQLException {
        ComputerApplication ca = new ComputerApplication();
        ca.setId(rs.getLong("id"));
        ca.setUuid(rs.getString("uuid"));
        ca.setComputerUuid(rs.getString("computer_uuid"));
        ca.setApplicationUuid(rs.getString("application_uuid"));
        ca.setInstalledDate(rs.getTimestamp("installed_date") != null ?
				rs.getTimestamp("installed_date").toLocalDateTime() : null);
        ca.setDeleted(rs.getBoolean("is_deleted"));
        ca.setCreatedAt(rs.getTimestamp("created_at").toLocalDateTime());
        ca.setUpdatedAt(rs.getTimestamp("updated_at") != null ?
                rs.getTimestamp("updated_at").toLocalDateTime() : null);
        return ca;
    }
    
    public static ComputerApplicationDTO mapComputerApplicationDetailsRow(ResultSet rs, int rowNum) throws SQLException {
    	ComputerApplicationDTO dto = new ComputerApplicationDTO();
    	dto.setUuid(rs.getString("uuid"));
    	dto.setComputerUuid(rs.getString("computer_uuid"));
    	dto.setApplicationUuid(rs.getString("application_uuid"));
    	dto.setInstalledDate(rs.getTimestamp("installed_date") != null ? rs.getTimestamp("installed_date").toLocalDateTime() : null);
    	dto.setDeleted(rs.getBoolean("is_deleted"));
    	dto.setApplicationName(rs.getString("name"));
    	dto.setApplicationVersion(rs.getString("version"));
    	dto.setApplicationVendorName(rs.getString("vendor_name"));
    	return dto;
    }
}