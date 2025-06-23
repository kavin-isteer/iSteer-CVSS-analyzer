package com.isteer.cvssapplication.datastore.service.impl;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.util.UUID;

import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.codehaus.plexus.util.xml.pull.XmlPullParserException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import com.isteer.cvssanalyser.core.Engine;

@Service
public class UploadFileAnalysisService {
	@Autowired
	JobTrackerService jobTracker;

	public String doPomFileAnalysis(MultipartFile uploadFile) throws IOException {
		MavenXpp3Reader reader = new MavenXpp3Reader();
		Model model = null;

		try (Reader fileReader = new InputStreamReader(new ByteArrayInputStream(uploadFile.getBytes()))) {
			model = reader.read(fileReader);
		} catch (XmlPullParserException e) {
			return "INVALID_POM_FILE";
		}
		
		if (model == null) {
			Engine.logger.error("Could not parse POM model from the uploaded file.");
			return "INVALID_POM_FILE";
		}
		
		String jobId = UUID.randomUUID().toString();
		SseEmitter emitter = new SseEmitter(0L);
		byte[] fileContents = uploadFile.getBytes();
		jobTracker.register(jobId, emitter);
		new Thread(() -> {
			try {
				Engine.readAndAnalyzeUploadedPomFile(fileContents, emitter);
			} finally {
				jobTracker.complete(jobId);
			}
		}).start();
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
