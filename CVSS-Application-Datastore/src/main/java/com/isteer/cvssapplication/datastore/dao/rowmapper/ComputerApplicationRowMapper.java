package com.isteer.cvssapplication.datastore.dao.rowmapper;

import java.sql.ResultSet;
import java.sql.SQLException;

import org.springframework.jdbc.core.RowMapper;

import com.isteer.cvssapplication.datastore.entity.ComputerApplication;

public class ComputerApplicationRowMapper implements RowMapper<ComputerApplication> {
    @Override
    public ComputerApplication mapRow(ResultSet rs, int rowNum) throws SQLException {
        ComputerApplication computerApplication = new ComputerApplication();
        computerApplication.setId(rs.getLong("id"));
        computerApplication.setUuid(rs.getString("uuid"));
        computerApplication.setComputerUuid(rs.getString("computer_uuid"));
        computerApplication.setApplicationUuid(rs.getString("application_uuid"));
        computerApplication.setInstalledDate(rs.getTimestamp("installed_date").toLocalDateTime());
        computerApplication.setDeleted(rs.getBoolean("is_deleted"));
        computerApplication.setCreatedAt(rs.getTimestamp("created_at").toLocalDateTime());
        computerApplication.setUpdatedAt(rs.getTimestamp("updated_at") != null ?
                rs.getTimestamp("updated_at").toLocalDateTime() : null);
        return computerApplication;
    }
}
