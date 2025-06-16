package com.isteer.service.dao;

import java.util.List;
import java.util.Optional;

import com.isteer.dto.ComputerPayloadDTO;
import com.isteer.entity.Computer;

public interface ComputerServiceDao {
	  int createComputer(ComputerPayloadDTO payload);


	Computer getComputerByUuid(String uuid);

	List<Computer> getAllComputers();
	}


