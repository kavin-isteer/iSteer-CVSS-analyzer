package com.isteer.service;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;


@Service
public class FileAnalysisService {
	@Autowired
	JobTrackerService jobTracker;
	
	@Autowired
	UploadFileAnalysisService fileAnalysisService;
	
	 public String doAnalysisForUploadedFile(String fileType, MultipartFile uploadedFile) throws IOException {
	    	String response="ERROR";
	    	if(fileType.equals("POM")) {
	    		response=fileAnalysisService.doPomFileAnalysis(uploadedFile);
	    	}else if(fileType.equals("PACKAGE_JSON")) {
	    		String packageJsonContents=null;
	    		if (uploadedFile != null && !uploadedFile.isEmpty()) {
			        packageJsonContents = new String(uploadedFile.getBytes(), StandardCharsets.UTF_8);
			    }
	    		if(packageJsonContents!=null) {
	    			response=fileAnalysisService.doNodePackageAnalysis(packageJsonContents, null);
	    		}
	    	}else if(fileType.equals("PACKAGE_LOCK_JSON")) {
	    		String packageLockJsonContents=null;
	    		if (uploadedFile != null && !uploadedFile.isEmpty()) {
	    			packageLockJsonContents = new String(uploadedFile.getBytes(), StandardCharsets.UTF_8);
			    }
	    		if(packageLockJsonContents!=null) {
	    			response=fileAnalysisService.doNodePackageAnalysis(null, packageLockJsonContents);
	    		}
	    	}else {
	    		response = "INVALID_FILE_TYPE";
	    	}
	    	return response;
	    }
	    
	    public SseEmitter getEventStatus(String jobId) {
	    	return jobTracker.get(jobId);
	    }
}
