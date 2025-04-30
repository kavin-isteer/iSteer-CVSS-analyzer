package com.isteer.cvssanalyser.core.model;

import com.isteer.cvssanalyser.core.enums.EvidenceType;

public class Evidence {
	private EvidenceType evidenceType;
	private String evidence;
	
	public EvidenceType getEvidenceType() {
		return evidenceType;
	}
	public void setEvidenceType(EvidenceType evidenceType) {
		this.evidenceType = evidenceType;
	}
	public String getEvidence() {
		return evidence;
	}
	public void setEvidence(String evidence) {
		this.evidence = evidence;
	}
}
