package com.isteer.repository;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.namedparam.MapSqlParameterSource;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;
import org.springframework.stereotype.Repository;

import com.isteer.entity.ComputerApplication;
import com.isteer.repository.dao.ComputerApplicationRepositoryDao;
import com.isteer.util.RowMapperUtil;

@Repository
public class ComputerApplicationRepository implements ComputerApplicationRepositoryDao {
	 private static final Logger logger = LoggerFactory.getLogger(ComputerApplicationRepository.class);

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
	    public Optional<ComputerApplication> findByComputerAndApplicationUuid(String computerUuid, String applicationUuid) {
	        String sql = "SELECT * FROM computer_applications WHERE computer_uuid = :computerUuid AND application_uuid = :applicationUuid ";
	        MapSqlParameterSource params = new MapSqlParameterSource()
	                .addValue("computerUuid", computerUuid)
	                .addValue("applicationUuid", applicationUuid);
	        try {
	            ComputerApplication ca = jdbcTemplate.queryForObject(sql, params, RowMapperUtil::mapComputerApplicationRow);
	            return Optional.ofNullable(ca);
	        } catch (Exception e) {
	            logger.debug("No mapping found for computer UUID: {}, application UUID: {}", computerUuid, applicationUuid);
	            return Optional.empty();
	        }
	    }

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
	    public List<ComputerApplication> findByComputerUuid(String computerUuid) {
	        String sql = "SELECT * FROM computer_applications WHERE computer_uuid = :computerUuid AND is_deleted = false";
	        MapSqlParameterSource params = new MapSqlParameterSource("computerUuid", computerUuid);
	        return jdbcTemplate.query(sql, params, RowMapperUtil::mapComputerApplicationRow);
	    }

		@Override
		public int update(ComputerApplication mapping) {
			 String sql = "UPDATE computer_applications SET installed_date = :installedDate, updated_at = :updatedAt WHERE uuid = :uuid AND is_deleted = false";
			 MapSqlParameterSource params = new MapSqlParameterSource()
					.addValue("uuid", mapping.getUuid())
					.addValue("installedDate", mapping.getInstalledDate())
					.addValue("updatedAt", mapping.getUpdatedAt());
			 logger.debug("Updating computer-application mapping with UUID: {}", mapping.getUuid());
			 int updatedRows = jdbcTemplate.update(sql, params);
			 if (updatedRows > 0) {
				 logger.info("Successfully updated mapping for UUID: {}", mapping.getUuid());
				 return 1; // Success
			 } else {
				 logger.warn("No mapping found to update for UUID: {}", mapping.getUuid());
				 return -1; // No rows updated
			 }
		}

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
		
}