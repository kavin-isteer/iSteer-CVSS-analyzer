package com.isteer.cvssanalyzer.api.service;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpStatusCodeException;
import org.springframework.web.client.RestTemplate;

import com.isteer.cvssanalyser.core.cveclient.CveClient;
import com.isteer.cvssanalyser.core.exception.NvdApiException;

@Service
public class CvssService {

    private final String CVE_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
    private final String CPE_API_BASE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0";
    private String apiKey = "ca987215-dbe8-42f0-a656-e5da368c3c70";

    public Object getVulnerabilitiesByCveId(String cveId) throws NvdApiException {
        try {
            RestTemplate restTemplate = new RestTemplate();
            CveClient cveClient = new CveClient();
            HttpEntity<String> entity = getHeaders();
            String url = String.format("%s?cveId=%s", CVE_API_BASE_URL, cveId);
            ResponseEntity<Object> response = restTemplate.exchange(url, HttpMethod.GET, entity, Object.class);

            if (!response.getStatusCode().is2xxSuccessful()) {
                throw new NvdApiException("NVD API returned non-success status", response.getStatusCode().value());
            }
            return cveClient.parseCveApiResponse(response.getBody());

        } catch (HttpStatusCodeException ex) {
            throw new NvdApiException(ex.getResponseBodyAsString(), ex.getStatusCode().value());
        } catch (Exception ex) {
            throw new NvdApiException(ex.getMessage(), 500);
        }
    }

    public Object getVulnerabilitiesByKeywords(String keywords) throws NvdApiException {
        try {
            RestTemplate restTemplate = new RestTemplate();
            CveClient cveClient = new CveClient();
            HttpEntity<String> entity = getHeaders();
            String url = String.format("%s?keywordSearch=%s", CVE_API_BASE_URL, keywords);
            ResponseEntity<Object> response = restTemplate.exchange(url, HttpMethod.GET, entity, Object.class);

            if (!response.getStatusCode().is2xxSuccessful()) {
                throw new NvdApiException("NVD API returned non-success status", response.getStatusCode().value());
            }
            return cveClient.parseCveApiResponse(response.getBody());

        } catch (HttpStatusCodeException ex) {
            throw new NvdApiException(ex.getResponseBodyAsString(), ex.getStatusCode().value());
        } catch (Exception ex) {
            throw new NvdApiException(ex.getMessage(), 500);
        }
    }

    public Object getVulnerabilitiesByCpe(String cpe) throws NvdApiException {
        try {
            RestTemplate restTemplate = new RestTemplate();
            CveClient cveClient = new CveClient();
            HttpEntity<String> entity = getHeaders();
            String url = String.format("%s?cpeName=%s", CVE_API_BASE_URL, cpe);
            ResponseEntity<Object> response = restTemplate.exchange(url, HttpMethod.GET, entity, Object.class);

            if (!response.getStatusCode().is2xxSuccessful()) {
                throw new NvdApiException("NVD API returned non-success status", response.getStatusCode().value());
            }
            return cveClient.parseCveApiResponse(response.getBody());

        } catch (HttpStatusCodeException ex) {
            throw new NvdApiException(ex.getResponseBodyAsString(), ex.getStatusCode().value());
        } catch (Exception ex) {
            throw new NvdApiException(ex.getMessage(), 500);
        }
    }

    public Object getCpeNameList(String cpeName) throws NvdApiException {
        try {
            RestTemplate restTemplate = new RestTemplate();
            CveClient cveClient = new CveClient();
            HttpEntity<String> entity = getHeaders();
            String url = String.format("%s?cpeMatchString=%s", CPE_API_BASE_URL, cpeName);
            ResponseEntity<Object> response = restTemplate.exchange(url, HttpMethod.GET, entity, Object.class);

            if (!response.getStatusCode().is2xxSuccessful()) {
                throw new NvdApiException("NVD API returned non-success status", response.getStatusCode().value());
            }
            return cveClient.parseCpeApiResponse(response.getBody());

        } catch (HttpStatusCodeException ex) {
            throw new NvdApiException(ex.getResponseBodyAsString(), ex.getStatusCode().value());
        } catch (Exception ex) {
            throw new NvdApiException(ex.getMessage(), 500);
        }
    }

    public Object getCpeNameListByKeywords(String keywords) throws NvdApiException {
        try {
            RestTemplate restTemplate = new RestTemplate();
            CveClient cveClient = new CveClient();
            HttpEntity<String> entity = getHeaders();
            String url = String.format("%s?keywordSearch=%s", CPE_API_BASE_URL, keywords);
            ResponseEntity<Object> response = restTemplate.exchange(url, HttpMethod.GET, entity, Object.class);

            if (!response.getStatusCode().is2xxSuccessful()) {
                throw new NvdApiException("NVD API returned non-success status", response.getStatusCode().value());
            }
            return cveClient.parseCpeApiResponse(response.getBody());

        } catch (HttpStatusCodeException ex) {
            throw new NvdApiException(ex.getResponseBodyAsString(), ex.getStatusCode().value());
        } catch (Exception ex) {
            throw new NvdApiException(ex.getMessage(), 500);
        }
    }

    private HttpEntity<String> getHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("apiKey", apiKey);
        return new HttpEntity<>(headers);
    }
}
