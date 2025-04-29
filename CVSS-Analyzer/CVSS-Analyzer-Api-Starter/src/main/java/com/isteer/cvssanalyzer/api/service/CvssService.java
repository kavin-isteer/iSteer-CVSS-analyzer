package com.isteer.cvssanalyzer.api.service;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.isteer.cvssanalyser.core.DependencyTreeResolver;
import com.isteer.cvssanalyser.core.cveclient.CveClient;

@Service
public class CvssService {
	
    private final String BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    private String apiKey = "ca987215-dbe8-42f0-a656-e5da368c3c70";
	
	public List<String> dummyValues() throws IOException, InterruptedException{
		DependencyTreeResolver treeResolver = new DependencyTreeResolver();
		Path projectRoot = Paths.get(System.getProperty("user.dir"));
		 File projectDir = new File("."); // current directory
		return treeResolver.fetchDependencies(projectDir);
	}

	public Object getAllVulnerabilities() {
		CveClient cveClient = new CveClient();
		return cveClient.getAllVulnerabilities(null);
	}
	
	public Object getVulnerabilitiesByCveId(String cveId) {
		RestTemplate restTemplate = new RestTemplate();
		HttpEntity<String> entity = getHeaders();
		String url = String.format("%s?cveId=%s", BASE_URL, cveId);
		Object response = restTemplate.getForObject(url, Object.class, entity);
		return response;
	}
	
	public Object getVulnerabilitiesByKeywords(String keywords) {
		RestTemplate restTemplate = new RestTemplate();
		HttpEntity<String> entity = getHeaders();
		String url = String.format("%s?keywordSearch=%s", BASE_URL, keywords);
		Object response = restTemplate.getForObject(url, Object.class, entity);
		return response;
	}
	
	public Object getVulnerabilitiesByCpe(String cpe) {
		RestTemplate restTemplate = new RestTemplate();
		HttpEntity<String> entity = getHeaders();
		String url = String.format("%s?cpeName=%s", BASE_URL, cpe);
		Object response = restTemplate.getForObject(url, Object.class, entity);
		return response;
	}
	
	public HttpEntity<String> getHeaders() {
		HttpHeaders headers = new HttpHeaders();
		headers.set("apiKey", apiKey);
		return new HttpEntity<>(headers);
	}
}
