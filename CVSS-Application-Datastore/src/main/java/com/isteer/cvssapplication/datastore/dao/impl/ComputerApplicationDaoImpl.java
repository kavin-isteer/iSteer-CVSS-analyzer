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

//	    @Override   // not used
//	    public Optional<ComputerApplication> findByComputerAndApplicationUuid(String computerUuid, String applicationUuid) {
//	        String sql = "SELECT * FROM computer_applications WHERE computer_uuid = :computerUuid AND application_uuid = :applicationUuid ";
//	        MapSqlParameterSource params = new MapSqlParameterSource()
//	                .addValue("computerUuid", computerUuid)
//	                .addValue("applicationUuid", applicationUuid);
//	        try {
//	            ComputerApplication ca = jdbcTemplate.queryForObject(sql, params, RowMapper::mapComputerApplicationRow);
//	            return Optional.ofNullable(ca);
//	        } catch (Exception e) {
//	            logger.debug("No mapping found for computer UUID: {}, application UUID: {}", computerUuid, applicationUuid);
//	            return Optional.empty();
//	        }
//	    }

	    @Override
	    public int softDeleteByComputerAndApplicationUuid(String computerUuid, String applicationUuid) {
	        String sql = "UPDATE computer_applications SET is_deleted = true, updated_at = CURRENT_TIMESTAMP " +
	                "WHERE computer_uuid = :computerUuid AND application_uuid = :applicationUuid AND is_deleted = false";
	        MapSqlParameterSource params = new MapSqlParameterSource()
	                .addValue("computerUuid", computerUuid)
	                .addValue("applicationUuid", applicationUuid);
	        int updated = jdbcTemplate.update(sql, params);
	        logger.debug("Soft deleted mapping for computer UUID: {}, application UUID: {}, updated rows: {}", computerUuid, applicationUuid, updated);
	        return updated;
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

//		@Override // not used
//		public int update(ComputerApplication mapping) {
//			 String sql = "UPDATE computer_applications SET installed_date = :installedDate, updated_at = :updatedAt WHERE uuid = :uuid AND is_deleted = false";
//			 MapSqlParameterSource params = new MapSqlParameterSource()
//					.addValue("uuid", mapping.getUuid())
//					.addValue("installedDate", mapping.getInstalledDate())
//					.addValue("updatedAt", mapping.getUpdatedAt());
//			 logger.debug("Updating computer-application mapping with UUID: {}", mapping.getUuid());
//			 int updatedRows = jdbcTemplate.update(sql, params);
//			 if (updatedRows > 0) {
//				 logger.info("Successfully updated mapping for UUID: {}", mapping.getUuid());
//				 return 1; // Success
//			 } else {
//				 logger.warn("No mapping found to update for UUID: {}", mapping.getUuid());
//				 return -1; // No rows updated
//			 }
//		}

		@Override
		public int reactivateByComputerAndApplicationUuid(String computerUuid, String applicationUuid,
				LocalDateTime installedDate) {
			  String sql = "UPDATE computer_applications SET is_deleted = false, installed_date = :installedDate, updated_at = :updatedAt WHERE computer_uuid = :computerUuid AND application_uuid = :applicationUuid";
			  MapSqlParameterSource params = new MapSqlParameterSource()
					  .addValue("computerUuid", computerUuid)
					  .addValue("applicationUuid", applicationUuid)
					  .addValue("installedDate", installedDate)
					  .addValue("updatedAt", LocalDateTime.now());
			  logger.debug("Reactivating mapping for computer UUID: {}, application UUID: {}", computerUuid, applicationUuid);
			  int updatedRows = jdbcTemplate.update(sql, params);
			  if (updatedRows > 0) {
				  logger.info("Successfully reactivated mapping for computer UUID: {}, application UUID: {}", computerUuid, applicationUuid);
				  return 1; // Success
			  } else {
				  logger.warn("No mapping found to reactivate for computer UUID: {}, application UUID: {}", computerUuid, applicationUuid);
				  return -1; // No rows updated
			  }
		}
		
		@Override
		public int reactivateByComputerAndApplicationUuid(String uuid, LocalDateTime installedDate) {
			  String sql = "UPDATE computer_applications SET is_deleted = false, installed_date = :installedDate, updated_at = :updatedAt WHERE uuid = :uuid";
			  MapSqlParameterSource params = new MapSqlParameterSource()
					  .addValue("uuid", uuid)
					  .addValue("installedDate", installedDate)
					  .addValue("updatedAt", LocalDateTime.now());
			  System.out.println(installedDate);
			  logger.debug("Reactivating mapping for UUID: {}", uuid);
			  int updatedRows = jdbcTemplate.update(sql, params);
			  if (updatedRows > 0) {
				  logger.info("Successfully reactivated mapping with uuid {}", uuid);
				  return 1; // Success
			  } else {
				  logger.warn("No mapping found to reactivate for UUID: {}", uuid);
				  return -1; // No rows updated
			  }
		}

		@Override
		public int updateInstalledDate(String computerUuid, String applicationUuid, LocalDateTime installedDate) {
			String sql = "UPDATE computer_applications SET installed_date = :installedDate, updated_at = :updatedAt WHERE computer_uuid = :computerUuid AND application_uuid = :applicationUuid AND is_deleted = false";
			MapSqlParameterSource params = new MapSqlParameterSource()
					.addValue("computerUuid", computerUuid)
					.addValue("applicationUuid", applicationUuid)
					.addValue("installedDate", installedDate)
					.addValue("updatedAt", LocalDateTime.now());
			logger.debug("Updating installed date for mapping with computer UUID: {}, application UUID: {}", computerUuid, applicationUuid);
			int updatedRows = jdbcTemplate.update(sql, params);
			if (updatedRows > 0) {
				logger.info("Successfully updated installed date for mapping with computer UUID: {}, application UUID: {}", computerUuid, applicationUuid);
				return 1; // Success
			} else {
				logger.warn("No mapping found to update installed date for computer UUID: {}, application UUID: {}", computerUuid, applicationUuid);
				return -1; // No rows updated
			}
		}

//		@Override  // not used
//		public int[] batchMapApplicaitonAndComputer(List<Application> applications, String computerUuid) {
//			String query = "INSERT INTO computer_applications (uuid, computer_uuid, application_uuid, installed_date, is_deleted, created_at) "
//					+ "VALUES (:uuid, :computer, :application, :installedDate, :isDeleted, :createdAt)";
//	    	List<MapSqlParameterSource> paramsList = applications.stream()
//	    			.map(app -> new MapSqlParameterSource()
//	    			.addValue("uuid", UUIDUtil.generateUUID())
//	    			.addValue("computer", computerUuid)
//		    		.addValue("application", app.getUuid())
//		    		.addValue("installedDate", app.getInstalledDate())
//		    		.addValue("isDeleted", false)
//		    		.addValue("createdAt", LocalDateTime.now()))
//		    			.collect(Collectors.toList());
//	    	
//	    	logger.debug("Batch mapping {} applications to computer UUID: {}", applications.size(), computerUuid);
//	    	
//	    	int[] updateCounts = jdbcTemplate.batchUpdate(query, paramsList.toArray(new MapSqlParameterSource[0]));
//	    	
//	    	logger.info("Batch mapping completed with {} applications mapped to computer UUID: {}", updateCounts.length, computerUuid);
//	    	return updateCounts;
//	    			
//		}
		
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
	        String sql = "UPDATE computer_applications SET is_deleted = true, updated_at = :updatedAt WHERE computer_uuid = :computerUuid AND is_deleted = false";
	        MapSqlParameterSource params = new MapSqlParameterSource()
	                .addValue("computerUuid", computerUuid)
	                .addValue("updatedAt", LocalDateTime.now());
	        logger.debug("Soft deleting all mappings for computer UUID: {}", computerUuid);
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