package com.isteer.cvssapplication.datastore.entity;

import java.time.LocalDateTime;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonFormat;

public class Application {

	private Long id;

	private String uuid;

	private String softwareName;

	private String softwareVersion;

	private String vendorName;

	@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
	private LocalDateTime installedDate;

	@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
	private LocalDateTime createdAt;

	@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
	private LocalDateTime updatedAt;

	private boolean isDeleted;

	private List<Vulnerability> vulnerabilities;

	public Long getId() {
		return id;
	}

	public void setId(Long id) {
		this.id = id;
	}

	public String getUuid() {
		return uuid;
	}

	public void setUuid(String uuid) {
		this.uuid = uuid;
	}

	public String getSoftwareName() {
		return softwareName;
	}

	public void setSoftwareName(String softwareName) {
		this.softwareName = softwareName;
	}

	public String getSoftwareVersion() {
		return softwareVersion;
	}

	public void setSoftwareVersion(String softwareVersion) {
		this.softwareVersion = softwareVersion;
	}

	public String getVendorName() {
		return vendorName;
	}

	public void setVendorName(String vendorName) {
		this.vendorName = vendorName;
	}

	public LocalDateTime getInstalledDate() {
		return installedDate;
	}

	public void setInstalledDate(LocalDateTime installedDate) {
		this.installedDate = installedDate;
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

	public boolean isDeleted() {
		return isDeleted;
	}

	public void setDeleted(boolean isDeleted) {
		this.isDeleted = isDeleted;
	}

	public List<Vulnerability> getVulnerabilities() {
		return vulnerabilities;
	}

	public void setVulnerabilities(List<Vulnerability> vulnerabilities) {
		this.vulnerabilities = vulnerabilities;
	}

	@Override
	public String toString() {
		return "Application [id=" + id + ", uuid=" + uuid + ", softwareName=" + softwareName + ", softwareVersion="
				+ softwareVersion + ", vendorName=" + vendorName + ", installedDate=" + installedDate + ", createdAt="
				+ createdAt + ", updatedAt=" + updatedAt + ", isDeleted=" + isDeleted + ", vulnerabilities="
				+ vulnerabilities + "]";
	}

}