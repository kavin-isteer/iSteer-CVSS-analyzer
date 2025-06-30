package com.isteer.cvssanalyser.core.cveclient;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.isteer.cvssanalyser.core.Engine;
import com.isteer.cvssanalyser.core.exception.NvdApiException;
import com.isteer.cvssanalyser.core.model.CPENameModel;
import com.isteer.cvssanalyser.core.model.DependencyModel;
import com.isteer.cvssanalyser.core.model.VulnerabilityAffectedProductModel;
import com.isteer.cvssanalyser.core.model.VulnerabilityCvssMetricsModel;
import com.isteer.cvssanalyser.core.model.VulnerabilityDetailsModel;
import com.isteer.cvssanalyser.core.model.VulnerabilityModel;
import com.isteer.cvssanalyser.core.model.VulnerabilityReferenceModel;
import com.jayway.jsonpath.JsonPath;

public class CveClient {

	private static final String CVE_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
	private static final String CPE_BASE_URL = "https://services.nvd.nist.gov/rest/json/cpes/2.0";
	private static final String API_KEY = "ca987215-dbe8-42f0-a656-e5da368c3c70";
	
	/**
     * Fetches and attaches vulnerability data for a given dependency based on its CPE enumeration.
     *
     * @param dependency The dependency model containing CPE info.
     * @return The updated dependency model with vulnerabilities, if any.
     */
	public DependencyModel fetchVulnerabilitiesForDependency(DependencyModel dependency) {
		if (dependency == null || dependency.getCpeEnumeration() == null) {
			// No dependency or CPE info available; return as is or null
			return dependency;
		}

		CPENameModel cpeNameModel = dependency.getCpeEnumeration();
		String cpeName = cpeNameModel.getCPE23Uri();
		if (cpeName == null || cpeName.isEmpty()) {
			return dependency;
		}

		List<CPENameModel> likelyCPEs = new ArrayList<>();
		Object cveApiResponse = null;
		Object cpeApiResponse = null;

		RestTemplate restTemplate = new RestTemplate();
		HttpHeaders headers = new HttpHeaders();
		headers.set("apiKey", API_KEY);
		HttpEntity<String> entity = new HttpEntity<>(headers);

		try {
			String encodedCpe = URLEncoder.encode(cpeName, StandardCharsets.UTF_8.toString());
			String cveUrl = String.format("%s?cpeName=%s", CVE_BASE_URL, encodedCpe);
			URI uri = new URI(cveUrl);
			ResponseEntity<Object> cveResponse = restTemplate.exchange(uri, HttpMethod.GET, entity, Object.class);
			if (cveResponse != null && cveResponse.getStatusCode().is2xxSuccessful()) {
				cveApiResponse = cveResponse.getBody();
				if (cveApiResponse != null) {
					VulnerabilityModel parsedVulnerability = new VulnerabilityModel();
					parsedVulnerability.setVulnerabilities(parseCveApiResponse(cveApiResponse));
					for (VulnerabilityDetailsModel vulnerabilityDetail : parsedVulnerability.getVulnerabilities()) {
						dependency.addVulnerabilities(vulnerabilityDetail);
					}
					dependency.getCpeEnumeration().setValidCpe(true);
				} else {
					throw new NvdApiException("CVE API failed", cveResponse.getStatusCode().value());
				}
			}
		} catch (RestClientException e) {
			throw new NvdApiException("CVE API error: " + e.getMessage(), 500);
		} catch (UnsupportedEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (URISyntaxException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		return dependency;
	}
	
	/**
     * Parses the CPE API response and converts it into a list of {@link CPENameModel}.
     *
     * @param cpeApiResponse The raw JSON response from the NVD CPE API.
     * @return A list of CPE name models.
     */
	public List<CPENameModel> parseCpeApiResponse(Object cpeApiResponse) {
		List<CPENameModel> cpeNames = new ArrayList<>();
		ObjectMapper objectMapper = new ObjectMapper();

		try {
			String jsonResponse = objectMapper.writeValueAsString(cpeApiResponse);
			List<Object> cpeItems = JsonPath.read(jsonResponse, "$.products[*].cpe");
			if (cpeItems != null && !cpeItems.isEmpty()) {
				for (Object cpeItem : cpeItems) {
					CPENameModel cpeName = new CPENameModel();
					String cpeNameStr = JsonPath.read(cpeItem, "$.cpeName").toString();
					if (cpeNameStr != null && !cpeNameStr.isEmpty()) {
						String[] cpeNameUri = cpeNameStr.split(":");
						if (cpeNameUri.length >= 7) {
							cpeName.setVendor(cpeNameUri[3]);
							cpeName.setProduct(cpeNameUri[4]);
							cpeName.setVersion(cpeNameUri[5]);
							cpeName.setUpdate(cpeNameUri[6]);
							cpeName.setValidCpe(true);
							cpeNames.add(cpeName);
						}
					}
				}
			}
		} catch (Exception e) {
			System.err.println("Error parsing CPE API response: " + e.getMessage());
		}
		return cpeNames;
	}
	
	/**
     * Parses the CVE API response into a list of {@link VulnerabilityDetailsModel}.
     *
     * @param cveApiResponse The raw JSON response from the NVD CVE API.
     * @return A list of vulnerability detail models.
     */
	public List<VulnerabilityDetailsModel> parseCveApiResponse(Object cveApiResponse) {
		List<VulnerabilityDetailsModel> vulnerabilityDetails = new ArrayList<>();
		ObjectMapper objectMapper = new ObjectMapper();

		try {
			String jsonResponse = objectMapper.writeValueAsString(cveApiResponse);
			List<Object> cveItems = JsonPath.read(jsonResponse, "$.vulnerabilities[*]");

			if (cveItems != null && !cveItems.isEmpty()) {
				for (Object cveItem : cveItems) {
					VulnerabilityDetailsModel vulnerabilityDetail = new VulnerabilityDetailsModel();
					vulnerabilityDetail.setCveId(JsonPath.read(cveItem, "$.cve.id"));
					vulnerabilityDetail.setCveDescription(JsonPath.read(cveItem, "$.cve.descriptions[0].value"));
					vulnerabilityDetail.setSourceIdentifier(JsonPath.read(cveItem, "$.cve.sourceIdentifier"));

					Map<String, Object> cvssMetricsMap = JsonPath.read(cveItem, "$.cve.metrics");
					if (cvssMetricsMap != null) {
						vulnerabilityDetail.setCvssMetrics(processCvssMetrics(cvssMetricsMap));
					}

					List<Object> affectedProducts = JsonPath.read(cveItem, "$.cve.configurations[*].nodes[*].cpeMatch");
					if (affectedProducts != null) {
						vulnerabilityDetail.setAffectedProducts(processAffectedProducts(affectedProducts));
					}

					List<Object> references = JsonPath.read(cveItem, "$.cve.references[*]");
					if (references != null) {
						vulnerabilityDetail.setReferences(processReferences(references));
					}

					vulnerabilityDetails.add(vulnerabilityDetail);
				}
			}
		} catch (Exception e) {
			System.err.println("Error parsing CVE API response: " + e.getMessage());
		}
		return vulnerabilityDetails;
	}
	
	/**
     * Processes CVSS metrics of a vulnerability from the parsed metrics map.
     *
     * @param metricMap The metrics section from the CVE API.
     * @return A list of parsed CVSS metric models.
     */
	private List<VulnerabilityCvssMetricsModel> processCvssMetrics(Map<String, Object> metricMap) {
		String[] metricTypes = { "cvssMetricV31", "cvssMetricV4", "cvssMetricV2" };
		List<VulnerabilityCvssMetricsModel> parsedCvssMetrics = new ArrayList<>();
		try {
			for (String metricType : metricTypes) {
				if (metricMap != null && metricMap.containsKey(metricType)) {
					List<Object> cvssMetrics = (List<Object>) metricMap.get(metricType);
					if (cvssMetrics != null) {
						for (Object cvssMetric : cvssMetrics) {
							String cvssMetricType = JsonPath.read(cvssMetric, "$.type");
							if ("Primary".equals(cvssMetricType)) {
								VulnerabilityCvssMetricsModel cvssMetricModel = new VulnerabilityCvssMetricsModel();
								cvssMetricModel.setVersion(JsonPath.read(cvssMetric, "$.cvssData.version"));
								cvssMetricModel.setBaseScore(JsonPath.read(cvssMetric, "$.cvssData.baseScore"));
								cvssMetricModel.setVectorString(JsonPath.read(cvssMetric, "$.cvssData.vectorString"));

								if ("cvssMetricV2".equals(metricType)) {
									cvssMetricModel.setBaseSeverity(JsonPath.read(cvssMetric, "$.baseSeverity"));
									cvssMetricModel.setAttackVector(JsonPath.read(cvssMetric, "$.cvssData.accessVector"));
									cvssMetricModel.setAttackComplexity(JsonPath.read(cvssMetric, "$.cvssData.accessComplexity"));
									cvssMetricModel.setPrivilegesRequired(JsonPath.read(cvssMetric, "$.cvssData.authentication"));
								} else {
									cvssMetricModel.setBaseSeverity(JsonPath.read(cvssMetric, "$.cvssData.baseSeverity"));
									cvssMetricModel.setAttackVector(JsonPath.read(cvssMetric, "$.cvssData.attackVector"));
									cvssMetricModel.setAttackComplexity(JsonPath.read(cvssMetric, "$.cvssData.attackComplexity"));
									cvssMetricModel.setPrivilegesRequired(JsonPath.read(cvssMetric, "$.cvssData.privilegesRequired"));
									cvssMetricModel.setUserInteraction(JsonPath.read(cvssMetric, "$.cvssData.userInteraction"));
									cvssMetricModel.setScope(JsonPath.read(cvssMetric, "$.cvssData.scope"));
								}

								cvssMetricModel.setConfidentiality(JsonPath.read(cvssMetric, "$.cvssData.confidentialityImpact"));
								cvssMetricModel.setIntegrity(JsonPath.read(cvssMetric, "$.cvssData.integrityImpact"));
								cvssMetricModel.setAvailability(JsonPath.read(cvssMetric, "$.cvssData.availabilityImpact"));
								cvssMetricModel.setExploitabilityScore(JsonPath.read(cvssMetric, "$.exploitabilityScore"));
								cvssMetricModel.setImpactScore(JsonPath.read(cvssMetric, "$.impactScore"));
								parsedCvssMetrics.add(cvssMetricModel);
							}
						}
					}
				}
			}
		} catch (Exception e) {
			System.err.println("Error processing CVSS metrics: " + e.getMessage());
		}
		return parsedCvssMetrics;
	}
	
	/**
     * Processes affected product configurations from a list of CPE match entries.
     *
     * @param configurations List of CPE match JSON entries.
     * @return List of affected product models.
     */
	public List<VulnerabilityAffectedProductModel> processAffectedProducts(List<Object> configurations) {
		List<VulnerabilityAffectedProductModel> affectedProducts = new ArrayList<>();

		try {
			if (configurations != null) {
				for (Object cpeMatchList : configurations) {
					if (cpeMatchList instanceof List) {
						List<?> cpeMatches = (List<?>) cpeMatchList;
						for (Object cpeMatch : cpeMatches) {
							VulnerabilityAffectedProductModel product = new VulnerabilityAffectedProductModel();
							product.setCpeName(JsonPath.read(cpeMatch, "$.criteria"));
							String cpeMatchStr = JsonPath.read(cpeMatch, "$").toString();

							if (cpeMatchStr.contains("versionStartIncluding")) {
								product.setVersionStartIncluding(JsonPath.read(cpeMatch, "$.versionStartIncluding"));
							}
							if (cpeMatchStr.contains("versionStartExcluding")) {
								product.setVersionStartExcluding(JsonPath.read(cpeMatch, "$.versionStartExcluding"));
							}
							if (cpeMatchStr.contains("versionEndIncluding")) {
								product.setVersionEndIncluding(JsonPath.read(cpeMatch, "$.versionEndIncluding"));
							}
							if (cpeMatchStr.contains("versionEndExcluding")) {
								product.setVersionEndExcluding(JsonPath.read(cpeMatch, "$.versionEndExcluding"));
							}

							affectedProducts.add(product);
						}
					}
				}
			}
		} catch (Exception e) {
			System.err.println("Error processing affected products: " + e.getMessage());
		}

		return affectedProducts;
	}
	
	 /**
     * Processes reference URLs and tags related to a CVE vulnerability.
     *
     * @param references List of reference JSON objects.
     * @return List of parsed reference models.
     */
	private List<VulnerabilityReferenceModel> processReferences(List<Object> references) {
		List<VulnerabilityReferenceModel> mitigationReferences = new ArrayList<>();
		try {
			if (references != null) {
				for (Object reference : references) {
					VulnerabilityReferenceModel mitigationReference = new VulnerabilityReferenceModel();
					mitigationReference.setReferenceUrl(JsonPath.read(reference, "$.url"));
					String referenceStr = JsonPath.read(reference, "$").toString();
					if (referenceStr.contains("tags")) {
						mitigationReference.setReferenceTags(JsonPath.read(reference, "$.tags[*]"));
					}
					mitigationReferences.add(mitigationReference);
				}
			}
		} catch (Exception e) {
			System.err.println("Error processing references: " + e.getMessage());
		}

		return mitigationReferences;
	}
}
