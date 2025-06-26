package com.isteer.cvssapplication.datastore.dao;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.isteer.cvssapplication.datastore.dto.SoftwareDTO;
import com.isteer.cvssapplication.datastore.entity.Application;

public interface ApplicationDao {
	  int save(Application application);
	    Optional<Application> findByNameVersionVendor(String name, String version, String vendorName);
//	    List<Application> findByComputerUuid(String computerUuid);
	    Optional<Application> findByUuidAndIsDeletedFalse(String uuid);
		Optional<Application> findByComputerUuidAndNameVendor(String computerUuid, String name, String vendorName);
		Map<Application, Boolean> isRecordExists(List<SoftwareDTO> applications);
		int[] batchSave(List<Application> applications);
		Map<Application, Boolean> isRecordExists1(List<SoftwareDTO> applications);
		List<Application> findAllApplications();
		List<Application> findByComputerUuid(String computerUuid, Boolean status);
//		Optional<Application> findByComputerUuidAndIsDeletedFalse(String computerUuid);	
		Optional<Application> findByApplicationUuid(String uuid);
		
}
