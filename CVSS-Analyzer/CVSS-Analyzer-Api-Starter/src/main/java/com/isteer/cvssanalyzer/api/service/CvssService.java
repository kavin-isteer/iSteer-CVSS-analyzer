package com.isteer.cvssanalyzer.api.service;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

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
    
    /**
     * Fetches vulnerability details for a given CVE ID.
     *
     * @param cveId The CVE ID to search for (e.g., "CVE-2021-44228")
     * @return Parsed CVE data for the given CVE ID.
     * @throws NvdApiException if the API call fails or returns an error.
     */
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
    
    /**
     * Searches for CVE vulnerabilities using a keyword (e.g., product name or version).
     *
     * @param keywords The search keyword(s).
     * @return Parsed CVE data matching the keywords.
     * @throws NvdApiException if the API call fails or returns an error.
     */
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
    
    /**
     * Retrieves vulnerabilities based on a specific CPE name.
     *
     * @param cpe The full CPE name (e.g., "cpe:2.3:a:apache:log4j:2.14.1").
     * @return Parsed CVE data for the specified CPE.
     * @throws NvdApiException if the API call fails or returns an error.
     */
    public Object getVulnerabilitiesByCpe(String cpe) throws NvdApiException {
        try {
            RestTemplate restTemplate = new RestTemplate();
            CveClient cveClient = new CveClient();
            HttpEntity<String> entity = getHeaders();
            String encodedCpe = URLEncoder.encode(cpe, StandardCharsets.UTF_8.toString());
            String url = String.format("%s?cpeName=%s", CVE_API_BASE_URL, encodedCpe);
            URI uri = new URI(url);
            ResponseEntity<Object> response = restTemplate.exchange(uri, HttpMethod.GET, entity, Object.class);

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
    
    /**
     * Retrieves a list of CPE names that match the given string.
     *
     * @param cpeName A partial or full CPE name string.
     * @return Parsed list of matching CPE names.
     * @throws NvdApiException if the API call fails or returns an error.
     */
    public Object getCpeNameList(String cpeName) throws NvdApiException {
        try {
            RestTemplate restTemplate = new RestTemplate();
            CveClient cveClient = new CveClient();
            HttpEntity<String> entity = getHeaders();
            String encodedCpe = URLEncoder.encode(cpeName, StandardCharsets.UTF_8.toString());
            String url = String.format("%s?cpeMatchString=%s", CPE_API_BASE_URL, encodedCpe);
            URI uri = new URI(url);
            ResponseEntity<Object> response = restTemplate.exchange(uri, HttpMethod.GET, entity, Object.class);

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
    
    /**
     * Retrieves a list of CPE names based on a keyword search.
     *
     * @param keywords The keyword to search CPEs (e.g., "log4j").
     * @return Parsed list of matching CPE names.
     * @throws NvdApiException if the API call fails or returns an error.
     */
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
    
    /**
     * Constructs an HttpEntity with headers including the NVD API key for authenticated requests.
     *
     * @return HttpEntity with the API key header.
     */
    private HttpEntity<String> getHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("apiKey", apiKey);
        return new HttpEntity<>(headers);
    }
}
