package com.isteer.cvssapplication.datastore.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.isteer.cvssanalyser.core.DependencyHintService;
import com.isteer.cvssanalyser.core.model.DependencyModel;
@RestController
@RequestMapping("/api")
public class DependencyHintController {
	/**
	 * Add GAV dependency hint for a dependency to correct false positives and false
	 * negatives.
	 * 
	 * @param cpeName    Correct CPE Name for the dependency.
	 * @param dependency dependency object to which the hint needs to be updated.
	 * @return status of the hint updation.
	 */
	@PostMapping("/hint/addDependencyHint")
	public ResponseEntity<Object> addDependencyHint(@RequestParam String cpeName,
			@RequestBody DependencyModel dependency) {
		DependencyHintService hintService = new DependencyHintService();
		int status = hintService.addGAVDependencyHint(cpeName, dependency);
		String statusMessage = "";
		switch (status) {
		case 1: {
			statusMessage = "Hint added Successfully!!";
			break;
		}
		case -1: {
			statusMessage = "CPE name is not valid!!";
			break;
		}
		case -2: {
			statusMessage = "Error whlie adding product hint!!";
			break;
		}
		case -3: {
			statusMessage = "Error whlie adding vendor hint!!";
			break;
		}
		default: {
			statusMessage = "Error whlie adding dependnecy hint!!";
			break;
		}
		}
		Map<String, String> responseMessage = new HashMap<>();
		responseMessage.put("Status", statusMessage);
		return new ResponseEntity<>(responseMessage, HttpStatus.OK);
	}
}
