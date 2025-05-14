package com.isteer.cvssanalyzer.api.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import com.isteer.cvssanalyser.core.Engine;
import com.isteer.cvssanalyzer.api.service.CvssService;

@RestController
@RequestMapping("/cvss")
public class CvssController {
	private CvssService service;

	public CvssController(CvssService cvssService) {
		this.service = cvssService;
	}
	
	@GetMapping("/getVulnerabilities")
	public SseEmitter getVulnerabilities() {
		SseEmitter emitter = new SseEmitter(0L);
		new Thread(() -> {
			try {
				service.getAllVulnerabilities(emitter);
			} catch (Exception e) {
				emitter.completeWithError(e);
			} finally {
				emitter.complete();
			}
		}).start();
		return emitter;
	}
	
	@GetMapping("/vulnerabilities")
	public ResponseEntity<Object> getAllVulnerabilities() {
			return ResponseEntity.ok(Engine.dependencies);
	}
	
	@GetMapping("/search/cve/cveId")
	public ResponseEntity<Object> getVulnerabilitiesByCveId(@RequestParam String cveId) {
		return ResponseEntity.ok(service.getVulnerabilitiesByCveId(cveId));
	}
	
	@GetMapping("/search/cve/keywords")
	public ResponseEntity<Object> getVulnerabilitiesByKeywords(@RequestParam String keywords) {
		return ResponseEntity.ok(service.getVulnerabilitiesByKeywords(keywords));
	}
	
	@GetMapping("/search/cve/cpeName")
	public ResponseEntity<Object> getVulnerabilitiesByCpe(@RequestParam String cpe) {
		return ResponseEntity.ok(service.getVulnerabilitiesByCpe(cpe));
	}
	
	@GetMapping("/search/cpe/matchingCpeName")
	public ResponseEntity<Object> getCpeNameList(@RequestParam String cpeName) {
		return ResponseEntity.ok(service.getCpeNameList(cpeName));
	}
	
	@GetMapping("/search/cpe/keyword")
	public ResponseEntity<Object> getCpeNameListByKeyword(@RequestParam String keyword) {
		return ResponseEntity.ok(service.getCpeNameListByKeywords(keyword));
	}
	
}
