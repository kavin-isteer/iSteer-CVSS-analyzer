package com.isteer.service.dao;

import java.time.LocalDateTime;
import java.util.Optional;

import com.isteer.entity.ComputerApplication;

public interface ComputerApplicationServiceDao {
  

	int createComputerApplication(String computerUuid, String applicationUuid, LocalDateTime installedDate);

	int softDeleteMapping(String computerUuid, String applicationUuid);

	int reactivateMapping(String computerUuid, String applicationUuid, LocalDateTime installedDate);

	int updateMapping(String computerUuid, String applicationUuid, LocalDateTime installedDate);


}
