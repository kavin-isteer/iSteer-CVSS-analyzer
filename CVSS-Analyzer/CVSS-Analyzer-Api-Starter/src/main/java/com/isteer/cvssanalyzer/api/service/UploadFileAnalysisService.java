package com.isteer.cvssanalyzer.api.service;

import java.util.UUID;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import com.isteer.cvssanalyser.core.Engine;

@Service
public class UploadFileAnalysisService {
	@Autowired
	JobTrackerService jobTracker;
	public String doPomFileAnalysis(MultipartFile uploadFile) {
		String jobId = UUID.randomUUID().toString();
	    SseEmitter emitter = new SseEmitter(0L);
	    
	    jobTracker.register(jobId, emitter);
		new Thread(()->{try {
			Engine.readAndAnalyzeUploadedPomFile(uploadFile, emitter);
		} finally {
			jobTracker.complete(jobId);
		}}).start();
		return jobId;
	}
	
	public String doNodePackageAnalysis(String packageJsonContents, String packageLockJsonContents) {
		String jobId = UUID.randomUUID().toString();
	    SseEmitter emitter = new SseEmitter(0L);
	    
	    jobTracker.register(jobId, emitter);  
		new Thread(() -> {
		        try {
		            Engine.readAndAnalyzeUploadedNodePackageFile(packageJsonContents, packageLockJsonContents, emitter);
		        } finally {
		        	jobTracker.complete(jobId);
		        }
		    }).start();
		return jobId;
	}
}
