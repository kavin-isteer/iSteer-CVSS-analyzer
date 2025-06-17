package com.isteer.service.dao;

import java.util.List;
import java.util.Optional;

import com.isteer.dto.ComputerPayloadDTO.SoftwareDTO;
import com.isteer.entity.Application;

public interface ApplicationServiceDao {
	 
	 
//		int createApplication(SoftwareDTO software, String computerUuid);

		Application getApplicationByUuid(String uuid);

		List<Application> getApplicationsByComputerUuid(String computerUuid);

		int createOrUpdateApplication(SoftwareDTO software, String computerUuid);

}
