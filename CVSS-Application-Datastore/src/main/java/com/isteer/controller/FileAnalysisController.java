package com.isteer.controller;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import com.isteer.cvssanalyser.core.Engine;
import com.isteer.service.FileAnalysisService;

@RestController
@RequestMapping("/api/file")
public class FileAnalysisController {
	@Autowired
	FileAnalysisService service;
	/**
	 * Handles the upload of a file for dependency analysis based on the file type (e.g., Maven or Node).
	 * <p>
	 * This method accepts a multipart file and its type, processes it, and returns a unique job ID
	 * if the analysis starts successfully. In case of errors or invalid file types, it returns an error message.
	 * 
	 * @param fileType    the type of the uploaded file (e.g., "pom", "package.json", etc.). Required.
	 * @param uploadedFile the multipart file uploaded for analysis. Required.
	 * @return a ResponseEntity containing:
	 *         - a JSON object with the generated {@code jobId} on success,
	 *         - or a JSON object with an {@code error} message if the file type is invalid or an error occurred.
	 */
	@PostMapping("/upload")
	public ResponseEntity<?> uploadNodePackageFileForAnalysis(
			@RequestParam(value="fileType",required = true)String fileType,
			@RequestParam(value="file", required=true) MultipartFile uploadedFile) {
		
		Map<String,String> jobIdResponse = new HashMap<>();
		Map<String,String> errorResponse = new HashMap<>();
		String jobId="";
		try {
			jobId = service.doAnalysisForUploadedFile(fileType, uploadedFile);
			if(jobId.equals("INVALID_FILE_TYPE")) {
				errorResponse.put("error", "Invalid file type!!");
				return ResponseEntity.ok(errorResponse);
			}else if(jobId.equals("ERROR")) {
				errorResponse.put("error", "Error while analysing uploaded file!!");
				return ResponseEntity.ok(errorResponse);
			}
			jobIdResponse.put("jobId", jobId);
		} catch (IOException e) {
			errorResponse.put("error", "Unknown Error!");
			return ResponseEntity.ok(errorResponse);
		}
		return ResponseEntity.ok(jobIdResponse);
	}
	
	/**
	 * Subscribes the client to server-sent events (SSE) for a specific job ID.
	 * <p>
	 * This endpoint allows the frontend to receive real-time analysis updates for the job initiated
	 * via file upload. It returns an {@link SseEmitter} tied to the given job ID.
	 * 
	 * @param jobId the ID of the analysis job to subscribe to.
	 * @return a ResponseEntity containing the {@link SseEmitter} for streaming job status events,
	 *         or a 404 Not Found response if the job ID does not exist or has expired.
	 */
	@GetMapping("/events/status/{jobId}")
	public ResponseEntity<SseEmitter> subscribeToJob(@PathVariable String jobId) {
	    SseEmitter emitter = service.getEventStatus(jobId);
	    if (emitter == null) {
	        return ResponseEntity.notFound().build();
	    }
	    return ResponseEntity.ok(emitter);
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
}
