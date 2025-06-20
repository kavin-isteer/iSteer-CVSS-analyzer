package com.isteer.cvssanalyser.core.model;

import java.util.ArrayList;
import java.util.List;

import org.apache.maven.artifact.Artifact;

public class DependencyModel {
	private String dependencyName;
	private Artifact artifact;
	private List<Evidence> vendorEvidences = new ArrayList<>();
	private List<Evidence> productEvidences = new ArrayList<>();
	private List<Evidence> versionEvidences = new ArrayList<>();
	private CPENameModel cpeEnumeration;
	private List<VulnerabilityDetailsModel> vulnerabilities = new ArrayList<>();
	private List<CPENameModel> likelyCPEs=new ArrayList<>();
	
	public DependencyModel() {
		// TODO Auto-generated constructor stub
	}
	public DependencyModel(String gavName) {
		this.dependencyName=gavName;
	}
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
	public List<VulnerabilityDetailsModel> getVulnerabilities() {
		return vulnerabilities;
	}
	public void addVulnerabilities(VulnerabilityDetailsModel vulnerability) {
		this.vulnerabilities.add(vulnerability);
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
	public Artifact getArtifact() {
		return artifact;
	}
	public void setArtifact(Artifact artifact) {
		this.artifact = artifact;
	}
	@Override
	public String toString() {
		return "DependencyModel [dependencyName=" + dependencyName + ", artifact=" + artifact + ", vendorEvidences="
				+ vendorEvidences + ", productEvidences=" + productEvidences + ", versionEvidences=" + versionEvidences
				+ ", cpeEnumeration=" + cpeEnumeration + ", vulnerabilities=" + vulnerabilities + ", likelyCPEs="
				+ likelyCPEs + "]";
	}
	
}
