package com.isteer.repository.dao;

import java.util.List;
import java.util.Optional;

import com.isteer.entity.Computer;

public interface ComputerRepositoryDao {
	
	 int save(Computer computer);
	    int update(Computer computer);
	    Optional<Computer> findByDeviceIdAndIsDeletedFalse(String deviceId);
	    Optional<Computer> findByUuidAndIsDeletedFalse(String uuid);
	    List<Computer> findAllComputers();

}
