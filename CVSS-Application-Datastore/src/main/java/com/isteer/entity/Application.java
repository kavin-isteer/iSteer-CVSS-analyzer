package com.isteer.entity;

import java.time.LocalDateTime;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonFormat;

import jakarta.validation.constraints.NotBlank;

public class Application {
	private Long id;

	@NotBlank(message = "UUID cannot be blank")
//	@Size(min = 36, max = 36, message = "UUID must be 36 characters")
	private String uuid;

	@NotBlank(message = "Name cannot be blank")
//	@Size(max = 100, message = "Name must be at most 100 characters")
	private String name;

//	@Size(max = 50, message = "Version must be at most 50 characters")
	private String version;

//	@NotBlank(message = "Vendor name cannot be blank")
//	@Size(max = 100, message = "Vendor name must be at most 100 characters")
	private String vendorName;
	public LocalDateTime getInstalledDate() {
		return installedDate;
	}

	public void setInstalledDate(LocalDateTime installedDate) {
		this.installedDate = installedDate;
	}

	@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
	private LocalDateTime createdAt;

	@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
	private LocalDateTime installedDate;

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

	public String getName() {
		return name;
	}

	public void setName(String name) {
		this.name = name;
	}

	public String getVersion() {
		return version;
	}

	public void setVersion(String version) {
		this.version = version;
	}

	public String getVendorName() {
		return vendorName;
	}

	public void setVendorName(String vendorName) {
		this.vendorName = vendorName;
	}

	public LocalDateTime getCreatedAt() {
		return createdAt;
	}

	public void setCreatedAt(LocalDateTime createdAt) {
		this.createdAt = createdAt;
	}

	public List<Vulnerability> getVulnerabilities() {
		return vulnerabilities;
	}

	public void setVulnerabilities(List<Vulnerability> vulnerabilities) {
		this.vulnerabilities = vulnerabilities;
	}

}