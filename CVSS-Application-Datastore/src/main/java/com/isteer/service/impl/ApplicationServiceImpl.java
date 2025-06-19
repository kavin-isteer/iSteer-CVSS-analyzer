package com.isteer.service.impl;

import java.util.List;

import com.isteer.dto.SoftwareDTO;
import com.isteer.entity.Application;

public interface ApplicationServiceImpl {
	 
	 
//		int createApplication(SoftwareDTO software, String computerUuid);

		Application getApplicationByUuid(String uuid);

		List<Application> getApplicationsByComputerUuid(String computerUuid);

		int createOrUpdateApplication(SoftwareDTO software, String computerUuid);

}
