package com.isteer.cvssanalyzer.api.service;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import org.springframework.stereotype.Service;

import com.isteer.cvssanalyser.core.DependencyTreeResolver;
import com.isteer.cvssanalyser.core.cveclient.CveClient;

@Service
public class CvssService {
	private CveClient cveClient;
	
	public CvssService(CveClient cveClient) {
		this.cveClient = cveClient;
	}
	
	public CvssService() {
		// TODO Auto-generated constructor stub
	}
	
	public List<String> dummyValues() throws IOException, InterruptedException{
		DependencyTreeResolver treeResolver = new DependencyTreeResolver();
		Path projectRoot = Paths.get(System.getProperty("user.dir"));
		 File projectDir = new File("."); // current directory
		return treeResolver.fetchDependencies(projectDir);
	}

	public Object getAllVulnerabilities() {
		return cveClient.getAllVulnerabilities(null);
	}
	
}
