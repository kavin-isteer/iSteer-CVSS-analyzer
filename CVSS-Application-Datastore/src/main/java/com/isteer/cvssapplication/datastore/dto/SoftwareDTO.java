package com.isteer.cvssapplication.datastore.dto;

import java.time.LocalDateTime;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.databind.annotation.JsonDeserialize;
import com.isteer.cvssapplication.datastore.util.CustomLocalDateTimeDeserializer;

import jakarta.validation.constraints.NotBlank;

public class SoftwareDTO {

	@NotBlank(message = "Software name cannot be blank")
	private String softwareName;

	private String softwareVersion;

	private String vendorName;

	@JsonDeserialize(using = CustomLocalDateTimeDeserializer.class)
	@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
	private LocalDateTime installedDate;

	@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
	private LocalDateTime createdAt;

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

	@Override
	public String toString() {
		return "SoftwareDTO [softwareName=" + softwareName + ", softwareVersion=" + softwareVersion + ", vendorName="
				+ vendorName + ", installedDate=" + installedDate + ", createdAt=" + createdAt + "]";
	}

}
