package com.isteer.cvssanalyser.core.cveclient;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.isteer.cvssanalyser.core.model.CPENameModel;
import com.isteer.cvssanalyser.core.model.DependencyModel;
import com.isteer.cvssanalyser.core.model.VulnerabilityAffectedProductModel;
import com.isteer.cvssanalyser.core.model.VulnerabilityCvssMetricsModel;
import com.isteer.cvssanalyser.core.model.VulnerabilityModel;
import com.isteer.cvssanalyser.core.model.VulnerabilityReferenceModel;
import com.isteer.cvssanalyser.core.model.VulnerabilityDetailsModel;
import com.jayway.jsonpath.JsonPath;

public class CveClient {

	private static final String BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0";
	private static final String API_KEY = "ca987215-dbe8-42f0-a656-e5da368c3c70";

	public List<VulnerabilityModel> getAllVulnerabilities(String cpeName) {
		List<VulnerabilityModel> vulnerabilities = new ArrayList<>();

		RestTemplate restTemplate = new RestTemplate();
		HttpHeaders headers = new HttpHeaders();
		headers.set("apiKey", API_KEY);
		HttpEntity<String> entity = new HttpEntity<>(headers);

		String url = String.format("%s?cpeName=%s", BASE_URL, cpeName);
		ResponseEntity<Object> response = restTemplate.exchange(url, HttpMethod.GET, entity, Object.class);
		Object cveApiResponse = response.getBody();

		VulnerabilityModel parsedVulnerability = new VulnerabilityModel();
		parsedVulnerability.setCpeName(cpeName);
		parsedVulnerability.setVulnerabilities(parseCveApiResponse(cveApiResponse));
		vulnerabilities.add(parsedVulnerability);

		return vulnerabilities;
	}

	public List<VulnerabilityDetailsModel> parseCveApiResponse(Object cveApiResponse) {
		List<VulnerabilityDetailsModel> vulnerabilityDetails = new ArrayList<>();
		ObjectMapper objectMapper = new ObjectMapper();

		try {
			String jsonResponse = objectMapper.writeValueAsString(cveApiResponse);
			List<Object> cveItems = JsonPath.read(jsonResponse, "$.vulnerabilities[*]");

			if (cveItems != null) {
				for (Object cveItem : cveItems) {
					VulnerabilityDetailsModel vulnerabilityDetail = new VulnerabilityDetailsModel();
					vulnerabilityDetail.setCveId(JsonPath.read(cveItem, "$.cve.id"));
					vulnerabilityDetail.setCveDescription(JsonPath.read(cveItem, "$.cve.descriptions[0].value"));
					vulnerabilityDetail.setSourceIdentifier(JsonPath.read(cveItem, "$.cve.sourceIdentifier"));

					Map<String, Object> cvssMetricsMap = JsonPath.read(cveItem, "$.cve.metrics");
					vulnerabilityDetail.setCvssMetrics(processCvssMetrics(cvssMetricsMap));

					List<Object> affectedProducts = JsonPath.read(cveItem, "$.cve.configurations[*].nodes[*].cpeMatch");
					vulnerabilityDetail.setAffectedProducts(processAffectedProducts(affectedProducts));

					List<Object> references = JsonPath.read(cveItem, "$.cve.references[*]");
					vulnerabilityDetail.setReferences(processReferences(references));

					vulnerabilityDetails.add(vulnerabilityDetail);
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}
		return vulnerabilityDetails;
	}

	private List<VulnerabilityCvssMetricsModel> processCvssMetrics(Map<String, Object> metricMap) {
		String[] metricTypes = { "cvssMetricV31", "cvssMetricV4", "cvssMetricV2" };
		List<VulnerabilityCvssMetricsModel> parsedCvssMetrics = new ArrayList<>();
		for (String metricType : metricTypes) {
			if (metricMap.containsKey(metricType)) {
				List<Object> cvssMetrics = (List<Object>) metricMap.get(metricType);
				for (Object cvssMetric : cvssMetrics) {
					String cvssMetricType = JsonPath.read(cvssMetric, "$.type");
					if (cvssMetricType.equals("Primary")) {
						VulnerabilityCvssMetricsModel cvssMetricModel = new VulnerabilityCvssMetricsModel();
						cvssMetricModel.setVersion(JsonPath.read(cvssMetric, "$.cvssData.version"));
						cvssMetricModel.setBaseScore(JsonPath.read(cvssMetric, "$.cvssData.baseScore"));
						cvssMetricModel.setVectorString(JsonPath.read(cvssMetric, "$.cvssData.vectorString"));
						if ("cvssMetricV2".equals(metricType)) {
							cvssMetricModel.setBaseSeverity(JsonPath.read(cvssMetric, "$.baseSeverity"));
							cvssMetricModel.setAttackVector(JsonPath.read(cvssMetric, "$.cvssData.accessVector"));
							cvssMetricModel
									.setAttackComplexity(JsonPath.read(cvssMetric, "$.cvssData.accessComplexity"));
							cvssMetricModel
									.setPrivilegesRequired(JsonPath.read(cvssMetric, "$.cvssData.authentication"));
						} else {
							cvssMetricModel.setBaseSeverity(JsonPath.read(cvssMetric, "$.cvssData.baseSeverity"));
							cvssMetricModel.setAttackVector(JsonPath.read(cvssMetric, "$.cvssData.attackVector"));
							cvssMetricModel
									.setAttackComplexity(JsonPath.read(cvssMetric, "$.cvssData.attackComplexity"));
							cvssMetricModel
									.setPrivilegesRequired(JsonPath.read(cvssMetric, "$.cvssData.privilegesRequired"));
							cvssMetricModel.setUserInteraction(JsonPath.read(cvssMetric, "$.cvssData.userInteraction"));
							cvssMetricModel.setScope(JsonPath.read(cvssMetric, "$.cvssData.scope"));
						}
						cvssMetricModel
								.setConfidentiality(JsonPath.read(cvssMetric, "$.cvssData.confidentialityImpact"));
						cvssMetricModel.setIntegrity(JsonPath.read(cvssMetric, "$.cvssData.integrityImpact"));
						cvssMetricModel.setAvailability(JsonPath.read(cvssMetric, "$.cvssData.availabilityImpact"));
						cvssMetricModel.setExploitabilityScore(JsonPath.read(cvssMetric, "$.exploitabilityScore"));
						cvssMetricModel.setImpactScore(JsonPath.read(cvssMetric, "$.impactScore"));
						parsedCvssMetrics.add(cvssMetricModel);
					}
				}
			}
		}
		return parsedCvssMetrics;
	}

	public List<VulnerabilityAffectedProductModel> processAffectedProducts(List<Object> configurations) {
		List<VulnerabilityAffectedProductModel> affectedProducts = new ArrayList<>();

		try {
			for (Object cpeMatchList : configurations) {
				List<Object> cpeMatches = (List<Object>) cpeMatchList;

				for (Object cpeMatch : cpeMatches) {
					VulnerabilityAffectedProductModel product = new VulnerabilityAffectedProductModel();
					product.setCpeName(JsonPath.read(cpeMatch, "$.criteria"));
					if (JsonPath.read(cpeMatch, "$").toString().contains("versionStartIncluding")) {
						product.setVersionStartIncluding(JsonPath.read(cpeMatch, "$.versionStartIncluding"));
					}
					if (JsonPath.read(cpeMatch, "$").toString().contains("versionStartExcluding")) {
						product.setVersionStartExcluding(JsonPath.read(cpeMatch, "$.versionStartExcluding"));
					}
					if (JsonPath.read(cpeMatch, "$").toString().contains("versionEndIncluding")) {
						product.setVersionEndIncluding(JsonPath.read(cpeMatch, "$.versionEndIncluding"));
					}
					if (JsonPath.read(cpeMatch, "$").toString().contains("versionEndExcluding")) {
						product.setVersionEndExcluding(JsonPath.read(cpeMatch, "$.versionEndExcluding"));
					}

					affectedProducts.add(product);
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return affectedProducts;
	}

	private List<VulnerabilityReferenceModel> processReferences(List<Object> references) {
		List<VulnerabilityReferenceModel> mitigationReferences = new ArrayList<>();
		try {
			for (Object reference : references) {
				VulnerabilityReferenceModel mitigationReference = new VulnerabilityReferenceModel();
				mitigationReference.setReferenceUrl(JsonPath.read(reference, "$.url"));
				if (JsonPath.read(reference, "$").toString().contains("tags")) {
					mitigationReference.setReferenceTags(JsonPath.read(reference, "$.tags[*]"));
				}

				mitigationReferences.add(mitigationReference);
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

		return mitigationReferences;
	}

	public DependencyModel fetchVulnerabilitiesForDependency(DependencyModel dependency) {
		if (dependency.getCpeEnumeration() == null) {
			return null;
		}
		CPENameModel cpeNameModel = dependency.getCpeEnumeration();
		String cpeName = cpeNameModel.getCPE23Uri();
		List<VulnerabilityModel> vulnerabilities = getAllVulnerabilities(cpeName);
		List<VulnerabilityDetailsModel> vulnerabilityDetails = vulnerabilities.getFirst().getVulnerabilities();
		for (VulnerabilityDetailsModel vulnerabilityDetail : vulnerabilityDetails) {
			dependency.addVulnerabilities(vulnerabilityDetail);
		}
		return dependency;
	}
}
