package com.isteer.repository.dao;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import com.isteer.entity.ComputerApplication;

public interface ComputerApplicationRepositoryDao {
	 int save(ComputerApplication ca);
	    Optional<ComputerApplication> findByComputerAndApplicationUuid(String computerUuid, String applicationUuid);
	    int softDeleteByComputerAndApplicationUuid(String computerUuid, String applicationUuid);
	    List<ComputerApplication> findByComputerUuid(String computerUuid);
		int update(ComputerApplication mapping);
		int reactivateByComputerAndApplicationUuid(String computerUuid, String applicationUuid,
				LocalDateTime installedDate);
		int updateInstalledDate(String computerUuid, String applicationUuid, LocalDateTime installedDate);
}