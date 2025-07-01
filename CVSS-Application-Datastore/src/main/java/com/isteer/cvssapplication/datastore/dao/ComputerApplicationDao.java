package com.isteer.cvssapplication.datastore.dao;

import java.time.LocalDateTime;
import java.util.List;

import com.isteer.cvssapplication.datastore.dto.ComputerApplicationDTO;
import com.isteer.cvssapplication.datastore.entity.ComputerApplication;

public interface ComputerApplicationDao {
	int save(ComputerApplication ca);

	List<ComputerApplicationDTO> findByComputerUuid(String computerUuid);

	int softDeleteByComputerAndApplicationUuid(String uuid);

	int reactivateByComputerAndApplicationUuid(String uuid, LocalDateTime installedDate);

	int updateInstalledDate(String uuid, LocalDateTime installedDate);

	int revertSoftDeleteByComputerUuid(String computerUuid);

	int softDeleteByComputerUuid(String uuid);
}