package com.isteer.repository.dao;

import java.util.Optional;

import com.isteer.entity.ComputerApplication;

public interface ComputerApplicationRepositoryDao {
	   int save(ComputerApplication computerApplication);
	    Optional<ComputerApplication> findByComputerAndApplicationUuid(String computerUuid, String applicationUuid);
	    int softDelete(String uuid);

}
