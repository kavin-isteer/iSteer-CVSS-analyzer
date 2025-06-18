package com.isteer.util;

import com.isteer.entity.Computer;
import org.springframework.jdbc.core.RowMapper;
import java.sql.ResultSet;
import java.sql.SQLException;

public class ComputerRowMapper implements RowMapper<Computer> {
    @Override
    public Computer mapRow(ResultSet rs, int rowNum) throws SQLException {
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
}