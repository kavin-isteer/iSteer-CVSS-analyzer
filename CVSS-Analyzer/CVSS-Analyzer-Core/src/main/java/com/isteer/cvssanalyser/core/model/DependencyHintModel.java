package com.isteer.cvssanalyser.core.model;

import java.time.LocalDateTime;

import com.isteer.cvssanalyser.core.enums.HintAddedBy;

public class DependencyHintModel {
	private Integer id;
	private String type;
	private String match_key;
	private String standardized_name;
	private String confidence;
	private String description;
	private LocalDateTime createdAt;
	private LocalDateTime updatedAt;
	private String evidenceType;
	private HintAddedBy addedBy;
	public Integer getId() {
		return id;
	}
	public void setId(Integer id) {
		this.id = id;
	}
	public String getType() {
		return type;
	}
	public void setType(String type) {
		this.type = type;
	}
	public String getMatch_key() {
		return match_key;
	}
	public void setMatch_key(String match_key) {
		this.match_key = match_key;
	}
	public String getStandardized_name() {
		return standardized_name;
	}
	public void setStandardized_name(String standardized_name) {
		this.standardized_name = standardized_name;
	}
	public String getConfidence() {
		return confidence;
	}
	public void setConfidence(String confidence) {
		this.confidence = confidence;
	}
	public String getDescription() {
		return description;
	}
	public void setDescription(String description) {
		this.description = description;
	}
	public LocalDateTime getCreatedAt() {
		return createdAt;
	}
	public void setCreatedAt(LocalDateTime createdAt) {
		this.createdAt = createdAt;
	}
	public LocalDateTime getUpdatedAt() {
		return updatedAt;
	}
	public void setUpdatedAt(LocalDateTime updatedAt) {
		this.updatedAt = updatedAt;
	}
	public String getEvidenceType() {
		return evidenceType;
	}
	public void setEvidenceType(String evidenceType) {
		this.evidenceType = evidenceType;
	}
	public HintAddedBy getAddedBy() {
		return addedBy;
	}
	public void setAddedBy(HintAddedBy addedBy) {
		this.addedBy = addedBy;
	}
}
