package com.isteer.cvssapplication.datastore.dao;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import com.isteer.cvssapplication.datastore.dto.ComputerApplicationDTO;
import com.isteer.cvssapplication.datastore.entity.Application;
import com.isteer.cvssapplication.datastore.entity.ComputerApplication;

public interface ComputerApplicationDao {
	 int save(ComputerApplication ca);
//	    Optional<ComputerApplication> findByComputerAndApplicationUuid(String computerUuid, String applicationUuid);
	    int softDeleteByComputerAndApplicationUuid(String computerUuid, String applicationUuid);
	    List<ComputerApplicationDTO> findByComputerUuid(String computerUuid);
//		int update(ComputerApplication mapping);
		int reactivateByComputerAndApplicationUuid(String computerUuid, String applicationUuid,
				LocalDateTime installedDate);
		int updateInstalledDate(String computerUuid, String applicationUuid, LocalDateTime installedDate);
//		int[] batchMapApplicaitonAndComputer(List<Application> applications, String computerUuid);
		int softDeleteByComputerAndApplicationUuid(String uuid);
		int reactivateByComputerAndApplicationUuid(String uuid, LocalDateTime installedDate);
		  int updateInstalledDate(String uuid, LocalDateTime installedDate);
		  
		  int softDeleteByComputerUuid(String computerUuid);
		    int revertSoftDeleteByComputerUuid(String computerUuid);
			int softDeleteApplicationByComputerUuid(String uuid);
}