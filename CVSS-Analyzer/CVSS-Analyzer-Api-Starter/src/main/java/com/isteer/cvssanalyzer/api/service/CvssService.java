package com.isteer.cvssanalyzer.api.service;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import com.isteer.cvssanalyser.core.cveclient.CveClient;

@Service
public class CvssService {
	
    private final String BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    private String apiKey = "ca987215-dbe8-42f0-a656-e5da368c3c70";

	public Object getAllVulnerabilities() {
		CveClient cveClient = new CveClient();
		return cveClient.getAllVulnerabilities(null);
	}
	
	public Object getVulnerabilitiesByCveId(String cveId) {
		RestTemplate restTemplate = new RestTemplate();
		CveClient cveClient = new CveClient();
		HttpEntity<String> entity = getHeaders();
		String url = String.format("%s?cveId=%s", BASE_URL, cveId);
		ResponseEntity<Object> response = restTemplate.exchange(url, HttpMethod.GET, entity, Object.class);
		Object cveApiResponse = response.getBody();
		 return cveClient.parseCveApiResponse(cveApiResponse);
	}
	
	public Object getVulnerabilitiesByKeywords(String keywords) {
		RestTemplate restTemplate = new RestTemplate();
		CveClient cveClient = new CveClient();
		HttpEntity<String> entity = getHeaders();
		String url = String.format("%s?keywordSearch=%s", BASE_URL, keywords);
		ResponseEntity<Object> response = restTemplate.exchange(url, HttpMethod.GET, entity, Object.class);
		Object cveApiResponse = response.getBody();
		 return cveClient.parseCveApiResponse(cveApiResponse);
	}
	
	public Object getVulnerabilitiesByCpe(String cpe) {
		RestTemplate restTemplate = new RestTemplate();
		CveClient cveClient = new CveClient();
		HttpEntity<String> entity = getHeaders();
		String url = String.format("%s?cpeName=%s", BASE_URL, cpe);
		ResponseEntity<Object> response = restTemplate.exchange(url, HttpMethod.GET, entity, Object.class);
		Object cveApiResponse = response.getBody();
		 return cveClient.parseCveApiResponse(cveApiResponse);
	}
	
	public HttpEntity<String> getHeaders() {
		HttpHeaders headers = new HttpHeaders();
		headers.set("apiKey", apiKey);
		return new HttpEntity<>(headers);
	}
}
