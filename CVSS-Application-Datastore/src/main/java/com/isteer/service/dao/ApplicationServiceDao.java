package com.isteer.service.dao;

import com.isteer.entity.Application;

public interface ApplicationServiceDao {
	  Application createApplication(Application application, String computerUuid);
	    void softDeletePreviousVersions(String name, String vendorName, String version);

}
