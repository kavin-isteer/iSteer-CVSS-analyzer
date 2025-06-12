package com.isteer.controller;

import com.isteer.dto.ComputerPayloadDTO;
import com.isteer.dto.StatusMessageDto;
import com.isteer.enums.CVSSEnum;
import com.isteer.exception.BussinessException;
import com.isteer.service.dao.ComputerServiceDao;
import com.isteer.util.StatusMessageUtil;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/computers")
public class ComputerController {

    private final ComputerServiceDao computerService;

    public ComputerController(ComputerServiceDao computerService) {
        this.computerService = computerService;
    }

    @PostMapping
    public ResponseEntity<?> createComputer(@RequestBody ComputerPayloadDTO payload) {
        try {
            int result = computerService.createComputer(payload);
            return ResponseEntity.status(HttpStatus.OK).body(
                    new StatusMessageDto(CVSSEnum.COMPUTER_ADD.getStatusCode(),
                            StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_ADD)));
        } catch (BussinessException e) {
            return new ResponseEntity<>(e.getMessage(), HttpStatus.BAD_REQUEST);
        } catch (Exception e) {
            return new ResponseEntity<>("An unexpected error occurred: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}