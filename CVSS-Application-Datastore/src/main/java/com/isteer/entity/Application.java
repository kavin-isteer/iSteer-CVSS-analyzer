package com.isteer.entity;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;

public class Application {
    private Long id;
    private String uuid;
    @JsonIgnore
    private String computerUuid; // Changed to computerUuid for clarity
    @NotBlank(message = "Application name cannot be blank")
    private String name;
    @NotBlank(message = "Application version cannot be blank")
    private String version;
    @NotBlank(message = "Vendor cannot be blank")
    private String vendor;
    @NotNull(message = "Install date cannot be null")
    private LocalDate installedDate;
    @JsonIgnore
	private boolean status;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private List<Dependency> dependencies; // For hierarchical JSON
    
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
	public String getComputerUuid() {
		return computerUuid;
	}
	public void setComputerUuid(String computerUuid) {
		this.computerUuid = computerUuid;
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
	public String getVendor() {
		return vendor;
	}
	public void setVendor(String vendor) {
		this.vendor = vendor;
	}
	public LocalDate getInstalledDate() {
		return installedDate;
	}
	public void setInstalledDate(LocalDate installedDate) {
		this.installedDate = installedDate;
	}
	public boolean isStatus() {
		return status;
	}
	public void setStatus(boolean status) {
		this.status = status;
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
	public List<Dependency> getDependencies() {
		return dependencies;
	}
	public void setDependencies(List<Dependency> dependencies) {
		this.dependencies = dependencies;
	}

}