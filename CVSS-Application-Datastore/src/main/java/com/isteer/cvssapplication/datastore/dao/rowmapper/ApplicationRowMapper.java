package com.isteer.cvssapplication.datastore.dao.rowmapper;

import java.sql.ResultSet;
import java.sql.SQLException;

import org.springframework.jdbc.core.RowMapper;

import com.isteer.cvssapplication.datastore.entity.Application;

public class ApplicationRowMapper implements RowMapper<Application> {
    @Override
    public Application mapRow(ResultSet rs, int rowNum) throws SQLException {
        Application application = new Application();
        application.setId(rs.getLong("id"));
        application.setUuid(rs.getString("uuid"));
        application.setName(rs.getString("name"));
        application.setVersion(rs.getString("version"));
        application.setVendorName(rs.getString("vendor_name"));
//       application.setInstalledDate(rs.getTimestamp("installed_date") != null ?
//                rs.getTimestamp("installed_date").toLocalDateTime() : null);
        application.setCreatedAt(rs.getTimestamp("created_at").toLocalDateTime());
        return application;
    }
}