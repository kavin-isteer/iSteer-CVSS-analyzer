package com.isteer.cvssanalyzer.api.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import com.isteer.cvssanalyser.core.DependencyHintService;
import com.isteer.cvssanalyser.core.Engine;
import com.isteer.cvssanalyser.core.enums.EngineMode;
import com.isteer.cvssanalyser.core.exception.NvdApiException;
import com.isteer.cvssanalyser.core.logging.Slf4jEngineLogger;
import com.isteer.cvssanalyser.core.model.DependencyModel;
import com.isteer.cvssanalyzer.api.service.CvssService;

@RestController
@RequestMapping("/cvss")
public class CvssController {
	private CvssService service;

	public CvssController(CvssService cvssService) {
		this.service = cvssService;
	}

	/**
	 * Starts a vulnerability analysis process and streams updates to the client
	 * using Server-Sent Events (SSE). The analysis is performed in a separate
	 * thread to avoid blocking the request thread.
	 *
	 * @return SseEmitter to stream analysis progress and final message.
	 */

	// FIXME: Check if it will raise any issues by using new thread and handle multi
	// threading issues.
	@GetMapping("/getVulnerabilities")
	public SseEmitter getVulnerabilities() {
		SseEmitter emitter = new SseEmitter(0L);
		new Thread(() -> {
			try {
				Engine.withLogger(new Slf4jEngineLogger());
				Engine.analyze(EngineMode.POM, emitter);
				Engine.doFuzzySearchAndGetLikelyCpes();
				emitter.send(SseEmitter.event().data("Analysis completed"));
			} catch (Exception e) {
				emitter.completeWithError(e);
			} finally {
				emitter.complete();
			}
		}).start();
		return emitter;
	}

	/**
	 * Returns the list of all analyzed dependencies and their vulnerabilities.
	 *
	 * @return ResponseEntity containing the analysis results.
	 */
	@GetMapping("/vulnerabilities")
	public ResponseEntity<Object> getAllVulnerabilities() {
		return ResponseEntity.ok(Engine.dependencies);
	}

	/**
	 * Fetches vulnerability details for a specific CVE ID from the NVD API.
	 *
	 * @param cveId The CVE ID to search for (e.g., "CVE-2021-44228").
	 * @return ResponseEntity with vulnerability details or error message.
	 */
	@GetMapping("/search/cve/cveId")
	public ResponseEntity<Object> getVulnerabilitiesByCveId(@RequestParam String cveId) {
		try {
			Object result = service.getVulnerabilitiesByCveId(cveId);
			return ResponseEntity.ok(result);
		} catch (NvdApiException ex) {
			return ResponseEntity.status(ex.getStatusCode()).body(ex.getMessage());
		}
	}

	/**
	 * Searches for vulnerabilities using keywords (e.g., software name or version).
	 *
	 * @param keywords The keywords to search for.
	 * @return ResponseEntity with search results or error message.
	 */
	@GetMapping("/search/cve/keyword")
	public ResponseEntity<Object> getVulnerabilitiesByKeywords(@RequestParam String keywords) {
		try {
			Object result = service.getVulnerabilitiesByKeywords(keywords);
			return ResponseEntity.ok(result);
		} catch (NvdApiException ex) {
			return ResponseEntity.status(ex.getStatusCode()).body(ex.getMessage());
		}
	}

	/**
	 * Searches for vulnerabilities related to a specific CPE name.
	 *
	 * @param cpe The full CPE name to search for (e.g.,
	 *            "cpe:2.3:a:apache:log4j:2.14.1").
	 * @return ResponseEntity with vulnerability data or error.
	 */
	@GetMapping("/search/cve/cpeName")
	public ResponseEntity<Object> getVulnerabilitiesByCpe(@RequestParam String cpe) {
		try {
			Object result = service.getVulnerabilitiesByCpe(cpe);
			return ResponseEntity.ok(result);
		} catch (NvdApiException ex) {
			return ResponseEntity.status(ex.getStatusCode()).body(ex.getMessage());
		}
	}

	/**
	 * Returns a list of matching CPE names based on a partial CPE name query.
	 *
	 * @param cpeName Partial or full CPE name to match.
	 * @return ResponseEntity with a list of matching CPE names or error.
	 */
	@GetMapping("/search/cpe/matchingCpeName")
	public ResponseEntity<Object> getCpeNameList(@RequestParam String cpeName) {
		try {
			Object result = service.getCpeNameList(cpeName);
			return ResponseEntity.ok(result);
		} catch (NvdApiException ex) {
			return ResponseEntity.status(ex.getStatusCode()).body(ex.getMessage());
		}
	}

	/**
	 * Searches for CPE names based on a keyword (e.g., product or vendor name).
	 *
	 * @param keyword The keyword to search for.
	 * @return ResponseEntity with matching CPE names or error.
	 */
	@GetMapping("/search/cpe/keyword")
	public ResponseEntity<Object> getCpeNameListByKeyword(@RequestParam String keyword) {
		try {
			Object result = service.getCpeNameListByKeywords(keyword);
			return ResponseEntity.ok(result);
		} catch (NvdApiException ex) {
			return ResponseEntity.status(ex.getStatusCode()).body(ex.getMessage());
		}
	}

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

	@PostMapping("/upload/pom")
	public SseEmitter uploadPomFileForAnalysis(@RequestParam("file") MultipartFile file) {
		SseEmitter emitter = new SseEmitter(0L);
		new Thread(()->{try {
			Engine.readAndAnalyzeUploadedPomFile(file, emitter);
		} finally {
			emitter.complete();
		}}).start();
		return emitter;
	}
}
