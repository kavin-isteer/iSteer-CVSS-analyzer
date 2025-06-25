package com.isteer.cvssapplication.datastore.service;

import java.time.LocalDateTime;
import java.util.List;

import com.isteer.cvssapplication.datastore.entity.Application;

public interface ComputerApplicationService {
  

//	int createComputerApplication(String computerUuid, String applicationUuid, LocalDateTime installedDate);

	int softDeleteMapping(String computerUuid, String applicationUuid);

	int reactivateMapping(String computerUuid, String applicationUuid, LocalDateTime installedDate);

	int updateMapping(String computerUuid, String applicationUuid, LocalDateTime installedDate);

	void sampleService(List<Application> application);


}
