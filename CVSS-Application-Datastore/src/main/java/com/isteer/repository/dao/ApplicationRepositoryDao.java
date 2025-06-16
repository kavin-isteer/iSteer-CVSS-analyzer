package com.isteer.repository.dao;

import java.util.List;
import java.util.Optional;

import com.isteer.entity.Application;

public interface ApplicationRepositoryDao {
	  int save(Application application);
	    Optional<Application> findByNameVersionVendor(String name, String version, String vendorName);
	    List<Application> findByComputerUuid(String computerUuid);
	    Optional<Application> findByUuidAndIsDeletedFalse(String uuid);
		Optional<Application> findByComputerUuidAndNameVendor(String computerUuid, String name, String vendorName);}
