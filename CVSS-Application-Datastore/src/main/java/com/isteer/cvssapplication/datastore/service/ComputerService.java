package com.isteer.cvssapplication.datastore.service;

import java.util.List;

import com.isteer.cvssapplication.datastore.dto.ComputerDetailsResponseDTO;
import com.isteer.cvssapplication.datastore.dto.ComputerPayloadDTO;
import com.isteer.cvssapplication.datastore.entity.Computer;

public interface ComputerService {
	  int createComputer(ComputerPayloadDTO payload);

	  ComputerDetailsResponseDTO getComputerDetailsByUuid(String uuid);
	Computer getComputerByUuid(String uuid);

	List<Computer> getAllPresentComputers();
	 int softDeleteComputer(String uuid);
	    int revertSoftDeleteComputer(String uuid);
	    int activateComputer(String uuid);
	    int deactivateComputer(String uuid);
	    List<Computer> getComputersByDeletionStatus(Boolean isDeleted);
	    List<Computer> getComputersByActivationStatus(Boolean isActive);

		List<Computer> getAllDeletedComputers();
	}


