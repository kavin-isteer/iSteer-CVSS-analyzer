package com.isteer.cvssanalyser.core.dto;

public class DependencyHintDto {
	private String matchKey;
	private String hintType;
	private String standardizedName;
	private String evidenceType;
	private String cpeName;
	
	public String getMatchKey() {
		return matchKey;
	}
	public void setMatchKey(String matchKey) {
		this.matchKey = matchKey;
	}
	public String getHintType() {
		return hintType;
	}
	public void setHintType(String hintType) {
		this.hintType = hintType;
	}
	public String getStandardizedName() {
		return standardizedName;
	}
	public void setStandardizedName(String standardizedName) {
		this.standardizedName = standardizedName;
	}
	public String getEvidenceType() {
		return evidenceType;
	}
	public void setEvidenceType(String evidenceType) {
		this.evidenceType = evidenceType;
	}
	public String getCpeName() {
		return cpeName;
	}
	public void setCpeName(String cpeName) {
		this.cpeName = cpeName;
	}
}
