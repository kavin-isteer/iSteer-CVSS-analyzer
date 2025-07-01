package com.isteer.cvssapplication.datastore.dao.impl;

import java.time.LocalDateTime;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import com.isteer.cvssapplication.datastore.dao.ComputerApplicationDao;
import com.isteer.cvssapplication.datastore.dao.rowmapper.RowMapper;
import com.isteer.cvssapplication.datastore.dto.ComputerApplicationDTO;
import com.isteer.cvssapplication.datastore.entity.ComputerApplication;

@Repository
public class ComputerApplicationDaoImpl implements ComputerApplicationDao {
	 private static final Logger logger = LoggerFactory.getLogger(ComputerApplicationDaoImpl.class);

	    @Autowired
	    private NamedParameterJdbcTemplate jdbcTemplate;

	    @Override
	    public int save(ComputerApplication ca) {
	        String sql = "INSERT INTO computer_applications (uuid, computer_uuid, application_uuid, installed_date, is_deleted, created_at) " +
	                "VALUES (:uuid, :computerUuid, :applicationUuid, :installedDate, :isDeleted, :createdAt)";
	        MapSqlParameterSource params = new MapSqlParameterSource()
	                .addValue("uuid", ca.getUuid())
	                .addValue("computerUuid", ca.getComputerUuid())
	                .addValue("applicationUuid", ca.getApplicationUuid())
	                .addValue("installedDate", ca.getInstalledDate())
	                .addValue("isDeleted", ca.isDeleted())
	                .addValue("createdAt", ca.getCreatedAt());
	        logger.debug("Saving computer-application mapping with UUID: {}", ca.getUuid());
	        return jdbcTemplate.update(sql, params);
	    }

   
	    @Override
	    public int softDeleteByComputerAndApplicationUuid(String uuid) {
	        String sql = "UPDATE computer_applications SET is_deleted = true, updated_at = CURRENT_TIMESTAMP " +
	                "WHERE uuid = :uuid AND is_deleted = false";
	        MapSqlParameterSource params = new MapSqlParameterSource()
	                .addValue("uuid", uuid);
	        int updated = jdbcTemplate.update(sql, params);
	        logger.debug("Soft deleted the mapping for UUID: {}, updated rows: {}", uuid, updated);
	        return updated;
	    }

	    @Override
	    public List<ComputerApplicationDTO> findByComputerUuid(String computerUuid) {
	        String sql = "SELECT ca.uuid, ca.computer_uuid, ca.application_uuid, ca.installed_date, ca.is_deleted, a.name, a.version, a.vendor_name FROM computer_applications ca JOIN applications a ON ca.application_uuid = a.uuid WHERE ca.computer_uuid = :computerUuid ORDER BY ca.installed_date DESC";
	        MapSqlParameterSource params = new MapSqlParameterSource("computerUuid", computerUuid);
	        return jdbcTemplate.query(sql, params, RowMapper::mapComputerApplicationDetailsRow);
	    }

		
		@Override
		public int reactivateByComputerAndApplicationUuid(String mappingUuid, LocalDateTime installedDate) {
			  String sql = "UPDATE computer_applications SET is_deleted = false, installed_date = :installedDate, updated_at = :updatedAt WHERE uuid = :uuid";
			  MapSqlParameterSource params = new MapSqlParameterSource()
					  .addValue("uuid", mappingUuid)
					  .addValue("installedDate", installedDate)
					  .addValue("updatedAt", LocalDateTime.now());
			  System.out.println(installedDate);
			  logger.debug("Reactivating mapping for UUID: {}", mappingUuid);
			  int updatedRows = jdbcTemplate.update(sql, params);
			  if (updatedRows > 0) {
				  logger.info("Successfully reactivated mapping with uuid {}", mappingUuid);
				  return 1; // Success
			  } else {
				  logger.warn("No mapping found to reactivate for UUID: {}", mappingUuid);
				  return -1; // No rows updated
			  }
		}



		
		@Override
	    public int updateInstalledDate(String uuid, LocalDateTime installedDate) {
	        String sql = "UPDATE computer_applications SET installed_date = :installedDate, updated_at = :updatedAt WHERE uuid = :uuid";
	        MapSqlParameterSource params = new MapSqlParameterSource()
	                .addValue("uuid", uuid)
	                .addValue("installedDate", installedDate)
	                .addValue("updatedAt", LocalDateTime.now());
	        logger.debug("Updating installed_date for computer application mapping with UUID: {}", uuid);
	        return jdbcTemplate.update(sql, params);
	    }
		
		
		 @Override
		    public int softDeleteByComputerUuid(String computerUuid) {    
			 String sql = """
					    UPDATE computer_applications ca
					    JOIN computers c ON ca.computer_uuid = c.uuid
					    JOIN applications a ON ca.application_uuid = a.uuid
					    SET ca.is_deleted = true, ca.updated_at = :updatedAt
					    WHERE c.uuid = :computerUuid
					      AND ca.is_deleted = false
					""";

        MapSqlParameterSource params = new MapSqlParameterSource()
                .addValue("computerUuid", computerUuid)
                .addValue("updatedAt", LocalDateTime.now());
        logger.debug("Soft deleting mappings for computer UUID: {} using JOINs", computerUuid);
        return jdbcTemplate.update(sql, params);
		    }

	    // Added: Revert soft delete for all mappings for a computer UUID
	    @Override
	    public int revertSoftDeleteByComputerUuid(String computerUuid) {
	        String sql = "UPDATE computer_applications SET is_deleted = false, updated_at = :updatedAt WHERE computer_uuid = :computerUuid AND is_deleted = true";
	        MapSqlParameterSource params = new MapSqlParameterSource()
	                .addValue("computerUuid", computerUuid)
	                .addValue("updatedAt", LocalDateTime.now());
	        logger.debug("Reverting soft delete for all mappings for computer UUID: {}", computerUuid);
	        return jdbcTemplate.update(sql, params);
	    }

		
}