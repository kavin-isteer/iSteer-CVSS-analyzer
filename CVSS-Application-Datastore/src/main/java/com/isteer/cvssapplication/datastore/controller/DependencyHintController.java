package com.isteer.cvssapplication.datastore.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.isteer.cvssanalyser.core.DependencyHintService;
import com.isteer.cvssanalyser.core.dto.DependencyHintDto;
import com.isteer.cvssanalyser.core.model.ApplicationModel;
import com.isteer.cvssanalyser.core.model.DependencyModel;

@RestController
@RequestMapping("/api")
public class DependencyHintController {
	DependencyHintService hintService = new DependencyHintService();

	/**
	 * Add GAV dependency hint for a dependency to correct false positives and false
	 * negatives.
	 * 
	 * @param cpeName    Correct CPE Name for the dependency.
	 * @param dependency dependency object to which the hint needs to be updated.
	 * @return status of the hint updation.
	 */
	@PostMapping("/hint/GAV/addHint")
	public ResponseEntity<Object> addDependencyHint(@RequestParam String cpeName,
			@RequestBody DependencyModel dependency) {
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
			statusMessage = "Error while adding product hint!!";
			break;
		}
		case -3: {
			statusMessage = "Error while adding vendor hint!!";
			break;
		}
		default: {
			statusMessage = "Error while adding dependnecy hint!!";
			break;
		}
		}
		Map<String, String> responseMessage = new HashMap<>();
		responseMessage.put("Status", statusMessage);
		return new ResponseEntity<>(responseMessage, HttpStatus.OK);
	}

	@PostMapping("/hint/{evidenceType}/addHint")
	public ResponseEntity<Object> addDependencyHint(@RequestBody DependencyHintDto hintDto,
			@PathVariable String evidenceType) {

		int status;
		String statusMessage = "";
		Map<String, String> responseMessage = new HashMap<>();
		if (evidenceType.equals("manifest")) {
			status = hintService.addManifestDependencyHint(hintDto);
			switch (status) {
			case 1: {
				statusMessage = "Hint added Successfully!!";
				break;
			}
			case -1: {
				responseMessage.put("Status", "CPE name is not valid!!");
				return new ResponseEntity<>(responseMessage, HttpStatus.OK);
			}
			case -2: {
				responseMessage.put("Status", "Hint type is not valid!!");
				return new ResponseEntity<>(responseMessage, HttpStatus.OK);
			}
			case -3: {
				responseMessage.put("Status", "vendor standardised name does not match with provided CPE name.");
				return new ResponseEntity<>(responseMessage, HttpStatus.OK);
			}
			case -4: {
				responseMessage.put("Status", "product standardised name does not match with provided CPE name.");
				return new ResponseEntity<>(responseMessage, HttpStatus.OK);
			}
			case -5: {	
				responseMessage.put("Status", "Improper payload!!");
				return new ResponseEntity<>(responseMessage, HttpStatus.OK);
			}
			case -6: {
				responseMessage.put("Status", "Unknown error. Hint not saved!!");
				return new ResponseEntity<>(responseMessage, HttpStatus.OK);
			}
			}
		} else {
			return new ResponseEntity<>(HttpStatus.BAD_REQUEST);
		}

		responseMessage.put("Status", statusMessage);
		return new ResponseEntity<>(responseMessage, HttpStatus.OK);
	}
	
	@PostMapping("/hint/application/addHint")
	public ResponseEntity<?> addApplicationHint(@RequestParam String cpeName, @RequestBody ApplicationModel application) {
		int status = hintService.addApplicationHint(cpeName, application);
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
			statusMessage = "Error while adding product hint!!";
			break;
		}
		case -3: {
			statusMessage = "Error while adding vendor hint!!";
			break;
		}
		default: {
			statusMessage = "Error while adding dependnecy hint!!";
			break;
		}
		}
		Map<String, String> responseMessage = new HashMap<>();
		responseMessage.put("Status", statusMessage);
		return new ResponseEntity<>(responseMessage, HttpStatus.OK);

	}
}
