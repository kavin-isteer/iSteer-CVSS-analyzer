package com.isteer.repository.dao;

import java.util.List;
import java.util.Optional;

import com.isteer.entity.Application;

public interface ApplicationRepositoryDao {
	  int save(Application application);
	    List<Application> findAll();
	    Optional<Application> findByUuid(String uuid);
	    Optional<Application> findByNameVersionVendor(String name, String version, String vendorName);
	    int update(String uuid, Application application);
	    int softDelete(String uuid);
	    int softDeleteByNameAndVendor(String name, String vendorName, String excludeVersion);
}
