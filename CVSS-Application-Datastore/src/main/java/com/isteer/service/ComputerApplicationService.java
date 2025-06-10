package com.isteer.service;

import com.isteer.entity.ComputerApplication;
import com.isteer.enums.CVSSEnum;
import com.isteer.exception.BussinessException;
import com.isteer.repository.dao.ComputerApplicationRepositoryDao;
import com.isteer.service.dao.ComputerApplicationServiceDao;
import com.isteer.util.StatusMessageUtil;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class ComputerApplicationService implements ComputerApplicationServiceDao {
    private final ComputerApplicationRepositoryDao computerApplicationRepository;

    public ComputerApplicationService(ComputerApplicationRepositoryDao computerApplicationRepository) {
        this.computerApplicationRepository = computerApplicationRepository;
    }

    @Transactional
    @Override
    public void createComputerApplication(ComputerApplication computerApplication) {
        try {
            // Check if mapping exists
            computerApplicationRepository.findByComputerAndApplicationUuid(
                    computerApplication.getComputerUuid(), computerApplication.getApplicationUuid())
                    .ifPresent(ca -> {
                        throw new BussinessException(CVSSEnum.COMPUTER_APPLICATION_EXISTS.getStatusCode(),
                                StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_APPLICATION_EXISTS));
                    });

            int rows = computerApplicationRepository.save(computerApplication);
            if (rows != 1) {
            	throw new BussinessException(CVSSEnum.COMPUTER_APPLICATION_EXISTS.getStatusCode(),
                        StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_APPLICATION_EXISTS));
            }
        } catch (DataIntegrityViolationException e) {
            if (e.getMessage().contains("computer_applications_computer_uuid_application_uuid_uindex")) {
            	throw new BussinessException(CVSSEnum.COMPUTER_APPLICATION_EXISTS.getStatusCode(),
                        StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_APPLICATION_EXISTS));
            }
            throw new BussinessException(CVSSEnum.Internal_Server_Error.getStatusCode(),
                    StatusMessageUtil.getMessage(CVSSEnum.Internal_Server_Error));
        }
    }
}
