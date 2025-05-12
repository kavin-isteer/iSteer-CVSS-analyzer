package com.isteer.cvssanalyzer.api.service;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import com.isteer.cvssanalyser.core.Engine;
import com.isteer.cvssanalyser.core.cveclient.CveClient;
import com.isteer.cvssanalyser.core.enums.EngineMode;

@Service
public class CvssService {
	
    private final String CVE_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    private final String CPE_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cpematch/2.0";
    private String apiKey = "ca987215-dbe8-42f0-a656-e5da368c3c70";

	public SseEmitter getAllVulnerabilities(SseEmitter emitter) {
		new Engine().analyze(EngineMode.POM, emitter);
		return emitter;
	}
	
	public Object getVulnerabilitiesByCveId(String cveId) {
		RestTemplate restTemplate = new RestTemplate();
		CveClient cveClient = new CveClient();
		HttpEntity<String> entity = getHeaders();
		String url = String.format("%s?cveId=%s", CVE_API_BASE_URL, cveId);
		ResponseEntity<Object> response = restTemplate.exchange(url, HttpMethod.GET, entity, Object.class);
		Object cveApiResponse = response.getBody();
		 return cveClient.parseCveApiResponse(cveApiResponse);
	}
	
	public Object getVulnerabilitiesByKeywords(String keywords) {
		RestTemplate restTemplate = new RestTemplate();
		CveClient cveClient = new CveClient();
		HttpEntity<String> entity = getHeaders();
		String url = String.format("%s?keywordSearch=%s", CVE_API_BASE_URL, keywords);
		ResponseEntity<Object> response = restTemplate.exchange(url, HttpMethod.GET, entity, Object.class);
		Object cveApiResponse = response.getBody();
		 return cveClient.parseCveApiResponse(cveApiResponse);
	}
	
	public Object getVulnerabilitiesByCpe(String cpe) {
		RestTemplate restTemplate = new RestTemplate();
		CveClient cveClient = new CveClient();
		HttpEntity<String> entity = getHeaders();
		String url = String.format("%s?cpeName=%s", CVE_API_BASE_URL, cpe);
		ResponseEntity<Object> response = restTemplate.exchange(url, HttpMethod.GET, entity, Object.class);
		Object cveApiResponse = response.getBody();
		 return cveClient.parseCveApiResponse(cveApiResponse);
	}
	
	public Object getCpeNameList(String cpeName) {
		RestTemplate restTemplate = new RestTemplate();
		CveClient cveClient = new CveClient();
		HttpEntity<String> entity = getHeaders();
		String url = String.format("%s?matchStringSearch=%s", CPE_API_BASE_URL, cpeName);
		ResponseEntity<Object> response = restTemplate.exchange(url, HttpMethod.GET, entity, Object.class);
		Object cpeApiResponse = response.getBody();
		return cveClient.parseCpeApiResponse(cpeApiResponse);
	}
	
	public HttpEntity<String> getHeaders() {
		HttpHeaders headers = new HttpHeaders();
		headers.set("apiKey", apiKey);
		return new HttpEntity<>(headers);
	}
}
