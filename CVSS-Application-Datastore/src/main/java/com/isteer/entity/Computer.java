package com.isteer.entity;

import java.time.LocalDateTime;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnore;

import jakarta.validation.constraints.NotBlank;

public class Computer {
    private Long id;
    private String uuid;
    @NotBlank(message = "IP address cannot be blank")
    private String ipAddress;
    @NotBlank(message = "Host name cannot be blank")
    private String hostName;
    @NotBlank(message = "OS name cannot be blank")
    private String osName;
    @NotBlank(message = "OS version cannot be blank")
    private String osVersion;
    @NotBlank(message = "Location cannot be blank")
    private String location;
    private boolean isActive ; 
   @JsonIgnore
    private boolean status;
    private LocalDateTime createdAt;
    private LocalDateTime updatedAt;
    private List<Application> application; // For hierarchical JSON

    // Getters and Setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getUuid() { return uuid; }
    public void setUuid(String uuid) { this.uuid = uuid; }
    public String getIpAddress() { return ipAddress; }
    public void setIpAddress(String ipAddress) { this.ipAddress = ipAddress; }
    public String getHostName() { return hostName; }
    public void setHostName(String hostName) { this.hostName = hostName; }
    public String getOsName() { return osName; }
    public void setOsName(String osName) { this.osName = osName; }
    public String getOsVersion() { return osVersion; }
    public void setOsVersion(String osVersion) { this.osVersion = osVersion; }
    public String getLocation() { return location; }
    public void setLocation(String location) { this.location = location; }
    public boolean isActive() { return isActive; }
    public void setActive(boolean isActive) { this.isActive = isActive; }
    public boolean isStatus() {
		return status;
	}
	public void setStatus(boolean status) {
		this.status = status;
	}
	public LocalDateTime getCreatedAt() { return createdAt; }
    public void setCreatedAt(LocalDateTime createdAt) { this.createdAt = createdAt; }
    public LocalDateTime getUpdatedAt() { return updatedAt; }
    public void setUpdatedAt(LocalDateTime updatedAt) { this.updatedAt = updatedAt; }
    public List<Application> getApplications() { return application; }
    public void setApplications(List<Application> application) { this.application = application; }
}