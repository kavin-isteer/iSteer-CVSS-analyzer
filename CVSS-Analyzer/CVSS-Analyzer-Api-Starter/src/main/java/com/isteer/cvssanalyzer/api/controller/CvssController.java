package com.isteer.cvssanalyzer.api.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.isteer.cvssanalyzer.api.service.CvssService;

@RestController
@RequestMapping("/cvss")
public class CvssController {
	private CvssService service;

	public CvssController(CvssService cvssService) {
		this.service = cvssService;
	}
	
	@GetMapping("/getVulnerabilities")
	public ResponseEntity<Object> getAllVulnerabilities() {
//		try {
			return ResponseEntity.ok(service.getAllVulnerabilities());
//		} catch (IOException e) {
			// TODO Auto-generated catch block
//			e.printStackTrace();
//			return ResponseEntity.status(500).body("Internal Server Error");
//		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
//			e.printStackTrace();
//			return ResponseEntity.status(500).body("Internal Server Error");
//		}
	}
	
	@GetMapping("/search/cveId")
	public ResponseEntity<Object> getVulnerabilitiesByCveId(@RequestParam String cveId) {
		return ResponseEntity.ok(service.getVulnerabilitiesByCveId(cveId));
	}
	
	@GetMapping("/search/keywords")
	public ResponseEntity<Object> getVulnerabilitiesByKeywords(@RequestParam String keywords) {
		return ResponseEntity.ok(service.getVulnerabilitiesByKeywords(keywords));
	}
	
	@GetMapping("/search/cpe")
	public ResponseEntity<Object> getVulnerabilitiesByCpe(@RequestParam String cpe) {
		return ResponseEntity.ok(service.getVulnerabilitiesByCpe(cpe));
	}
	
}
