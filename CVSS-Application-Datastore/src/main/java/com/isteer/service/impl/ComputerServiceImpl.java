package com.isteer.service.impl;

import java.util.List;
import java.util.Optional;

import com.isteer.dto.ComputerDetailsResponseDTO;
import com.isteer.dto.ComputerPayloadDTO;
import com.isteer.entity.Computer;

public interface ComputerServiceImpl {
	  int createComputer(ComputerPayloadDTO payload);

	  ComputerDetailsResponseDTO getComputerDetailsByUuid(String uuid);
	Computer getComputerByUuid(String uuid);

	List<Computer> getAllComputers();
	}


