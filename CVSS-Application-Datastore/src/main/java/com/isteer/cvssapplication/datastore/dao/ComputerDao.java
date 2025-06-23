package com.isteer.cvssapplication.datastore.dao;

import java.util.List;
import java.util.Optional;

import com.isteer.cvssapplication.datastore.entity.Computer;

public interface ComputerDao {
	
	 int save(Computer computer);
	    int update(Computer computer);
	    Optional<Computer> findByDeviceIdAndIsDeletedFalse(String deviceId);
	    Optional<Computer> findByUuidAndIsDeletedFalse(String uuid);
	    List<Computer> findAllComputers();

}
