package com.isteer.cvssanalyser.core.cveclient;

import java.util.ArrayList;
import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.web.client.RestTemplate;

public class CveClient {
	
	private static final String BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
	private static String apiKey = "ca987215-dbe8-42f0-a656-e5da368c3c70";
	
	public Object getAllVulnerabilities(Object cpeNames) {
		Object response = null;
		List<String> cpeNameList = new ArrayList<>();
		cpeNameList.add("cpe:2.3:a:fasterxml:jackson-databind:2.13.3:*:*:*:*:*:*:*");
	for(String cpeName : (List<String>)cpeNameList) {
		RestTemplate restTemplate = new RestTemplate();
		HttpHeaders headers = new HttpHeaders();
		headers.set("apiKey", apiKey);
		HttpEntity<String> entity = new HttpEntity<>(headers);
		String url = String.format("%s?cpeName=%s", BASE_URL, cpeName);
		response = restTemplate.getForObject(url, Object.class, entity);
	}
	return response;
	}
}
