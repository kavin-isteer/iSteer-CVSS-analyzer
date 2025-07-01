package com.isteer.cvssapplication.datastore.dao;

import java.util.List;
import java.util.Optional;

import com.isteer.cvssapplication.datastore.dto.ComputerDetailsResponseDTO;
import com.isteer.cvssapplication.datastore.entity.Computer;

public interface ComputerDao {

	int save(Computer computer);

	int update(Computer computer);

	Optional<Computer> findByDeviceIdAndIsDeletedFalse(String deviceId);

	List<Computer> findAllPresentComputers();

	Optional<Computer> findByUuid(String uuid);

	int updateDeletionStatus(Computer computer);

	int updateActivationStatus(Computer computer);

	List<Computer> findByDeletionStatus(Boolean isDeleted);

	List<Computer> findByActivationStatus(Boolean isActive);

	List<Computer> findAllDeletedComputers();

	ComputerDetailsResponseDTO findDetailsByUuid(String uuid);
}
