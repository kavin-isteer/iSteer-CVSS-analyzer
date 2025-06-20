package com.isteer.service.impl;

import java.time.LocalDateTime;
import java.util.Optional;

import com.isteer.entity.Application;
import com.isteer.entity.ComputerApplication;

public interface ComputerApplicationServiceImpl {
  

	int createComputerApplication(String computerUuid, String applicationUuid, LocalDateTime installedDate);

	int softDeleteMapping(String computerUuid, String applicationUuid);

	int reactivateMapping(String computerUuid, String applicationUuid, LocalDateTime installedDate);

	int updateMapping(String computerUuid, String applicationUuid, LocalDateTime installedDate);

	void sampleService(Application application);


}
