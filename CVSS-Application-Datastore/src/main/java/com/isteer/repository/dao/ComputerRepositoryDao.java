package com.isteer.repository.dao;

import java.util.List;

import com.isteer.entity.Computer;

public interface ComputerRepositoryDao {
	
	public int save(Computer computer);
	public List<Computer> findAll();
	public Computer findByUuid(String uuid);
	public Computer computerByUuid(String uuid);
	public int update(String uuid, Computer computer);
	public int softDelete(String uuid);
	public int deactivate(String uuid);
	public int activateComputer(String uuid);
	

}
