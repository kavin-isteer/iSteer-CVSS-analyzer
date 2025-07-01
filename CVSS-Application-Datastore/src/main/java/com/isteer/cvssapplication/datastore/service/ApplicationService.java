package com.isteer.cvssapplication.datastore.service;

import java.util.List;

import com.isteer.cvssapplication.datastore.dto.SoftwareDTO;
import com.isteer.cvssapplication.datastore.entity.Application;
import com.isteer.cvssapplication.datastore.entity.Vulnerability;

import jakarta.validation.constraints.NotBlank;

public interface ApplicationService {
	 


		int createOrUpdateApplication(List<SoftwareDTO> list, String computerUuid);

		int createOrUpdateApplication(SoftwareDTO software, String computerUuid);
		
		List<Application> getAllApplications();

		List<Application> getApplicationsByComputerUuid(String computerUuid, Boolean status);


		List<Vulnerability> getVulnerabilitiesByApplicationUuid( String uuid);




}
