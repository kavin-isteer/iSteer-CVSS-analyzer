package com.isteer.repository.dao;

import java.util.List;
import java.util.Optional;

import com.isteer.entity.Computer;

public interface ComputerRepositoryDao {
	
	 int save(Computer computer);
	    List<Computer> findAll();
	    Optional<Computer> findByUuid(String uuid);
	    Optional<Computer> findByDeviceId(String deviceId);
	    int update(String uuid, Computer computer);
	    int softDelete(String uuid);
	    int deactivate(String uuid);
	    int activate(String uuid);
	

}
