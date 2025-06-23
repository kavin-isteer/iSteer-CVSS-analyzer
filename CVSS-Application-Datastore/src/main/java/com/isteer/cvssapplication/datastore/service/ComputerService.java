package com.isteer.cvssapplication.datastore.service;

import java.util.List;

import com.isteer.cvssapplication.datastore.dto.ComputerDetailsResponseDTO;
import com.isteer.cvssapplication.datastore.dto.ComputerPayloadDTO;
import com.isteer.cvssapplication.datastore.entity.Computer;

public interface ComputerService {
	  int createComputer(ComputerPayloadDTO payload);

	  ComputerDetailsResponseDTO getComputerDetailsByUuid(String uuid);
	Computer getComputerByUuid(String uuid);

	List<Computer> getAllComputers();
	}


