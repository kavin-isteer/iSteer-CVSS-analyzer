package com.isteer.cvssanalyser.core.model;

import com.isteer.cvssanalyser.core.enums.EvidenceType;

public class Evidence {
	private EvidenceType evidenceType;
	private String evidence;
	private String resolvedValue;
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
	public String getResolvedValue() {
		return resolvedValue;
	}
	public void setResolvedValue(String resolvedValue) {
		this.resolvedValue = resolvedValue;
	}
	@Override
	public String toString() {
		return "Evidence [evidenceType=" + evidenceType + ", evidence=" + evidence + ", resolvedValue=" + resolvedValue
				+ "]";
	}
}
