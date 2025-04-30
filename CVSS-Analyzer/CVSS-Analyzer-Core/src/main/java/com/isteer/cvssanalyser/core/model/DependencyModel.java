package com.isteer.cvssanalyser.core.model;

import java.util.ArrayList;
import java.util.List;

public class DependencyModel {
	private String dependencyName;
	private List<Evidence> vendorEvidences = new ArrayList<>();
	private List<Evidence> productEvidences = new ArrayList<>();
	private List<Evidence> versionEvidences = new ArrayList<>();
	private boolean normalizationStatus;
	private CPENameModel cpeEnumeration;
	private List<VulnerabilityModel> vulnerabilities = new ArrayList<>();
	private List<CPENameModel> likelyCPEs;
	
	
	public String getDependencyName() {
		return dependencyName;
	}
	public void setDependencyName(String dependencyName) {
		this.dependencyName = dependencyName;
	}
	public List<Evidence> getVendorEvidences() {
		return vendorEvidences;
	}
	public void addVendorEvidence(Evidence vendorEvidence) {
		this.vendorEvidences.add(vendorEvidence);
	}
	public List<Evidence> getProductEvidences() {
		return productEvidences;
	}
	public void addProductEvidences(Evidence productEvidence) {
		this.productEvidences.add(productEvidence);
	}
	public List<Evidence> getVersionEvidences() {
		return versionEvidences;
	}
	public void addVersionEvidences(Evidence versionEvidence) {
		this.versionEvidences.add(versionEvidence);
	}
	public List<VulnerabilityModel> getVulnerabilities() {
		return vulnerabilities;
	}
	public void addVulnerabilities(VulnerabilityModel vulnerability) {
		this.vulnerabilities.add(vulnerability);
	}
	public boolean isNormalizationStatus() {
		return normalizationStatus;
	}
	public void setNormalizationStatus(boolean normalizationStatus) {
		this.normalizationStatus = normalizationStatus;
	}
	public CPENameModel getCpeEnumeration() {
		return cpeEnumeration;
	}
	public void setCpeEnumeration(CPENameModel cpeEnumeration) {
		this.cpeEnumeration = cpeEnumeration;
	}
	public List<CPENameModel> getLikelyCPEs() {
		return likelyCPEs;
	}
	public void addLikelyCPEs(CPENameModel likelyCPE) {
		this.likelyCPEs.add(likelyCPE);
	}
}
