package com.isteer.cvssapplication.datastore.dao;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.isteer.cvssapplication.datastore.dto.SoftwareDTO;
import com.isteer.cvssapplication.datastore.entity.Application;

public interface ApplicationDao {


	int[] batchSave(List<Application> applications);

	Map<Application, Boolean> isRecordExists1(List<SoftwareDTO> applications);

	List<Application> findAllApplications();

	List<Application> findByComputerUuid(String computerUuid, Boolean status);

	Optional<Application> findByApplicationUuid(String uuid);

	List<Application> findAllUnresolvedCpeApplications();

	List<Application> findUnresolvedCpeApplicationsByComputerUuid(String uuid);

}
