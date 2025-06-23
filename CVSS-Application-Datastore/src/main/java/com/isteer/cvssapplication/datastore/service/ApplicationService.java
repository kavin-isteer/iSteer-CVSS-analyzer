package com.isteer.cvssapplication.datastore.service;

import java.util.List;

import com.isteer.cvssapplication.datastore.dto.SoftwareDTO;
import com.isteer.cvssapplication.datastore.entity.Application;

public interface ApplicationService {
	 
	 
//		int createApplication(SoftwareDTO software, String computerUuid);

		Application getApplicationByUuid(String uuid);

		List<Application> getApplicationsByComputerUuid(String computerUuid);

		int createOrUpdateApplication(List<SoftwareDTO> list, String computerUuid);

		int createOrUpdateApplication(SoftwareDTO software, String computerUuid);

}
