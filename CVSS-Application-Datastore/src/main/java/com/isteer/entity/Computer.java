package com.isteer.entity;

import java.time.LocalDateTime;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public class Computer {
	  private Long id;
	    
	    @NotBlank(message = "UUID cannot be blank")
	    @Size(min = 36, max = 36, message = "UUID must be 36 characters")
	    private String uuid;
	    
	    @NotBlank(message = "Device ID cannot be blank")
	    @Size(max = 50, message = "Device ID must be at most 50 characters")
	    private String deviceId;
	    
	    @NotBlank(message = "Hostname cannot be blank")
	    @Size(max = 100, message = "Hostname must be at most 100 characters")
	    private String hostname;
	    
	    @NotBlank(message = "IP address cannot be blank")
	    @Pattern(regexp = "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$", 
	            message = "Invalid IPv4 address")
	    private String ipAddress;
	    
	    @NotBlank(message = "OS version cannot be blank")
	    @Size(max = 50, message = "OS version must be at most 50 characters")
	    private String osVersion;
	    
	    @NotBlank(message = "Antivirus status cannot be blank")
	    @Size(max = 20, message = "Antivirus status must be at most 20 characters")
	    private String antivirusStatus;
	    
	    @NotBlank(message = "Firewall status cannot be blank")
	    @Size(max = 20, message = "Firewall status must be at most 20 characters")
	    private String firewallStatus;
	    
	    @NotBlank(message = "Logged-in user cannot be blank")
	    @Size(max = 100, message = "Logged-in user must be at most 100 characters")
	    private String loggedInUser;
	    
	    private LocalDateTime lastUpdateCheck;
	    private boolean isDeleted;
	    private boolean isActive;
	    private LocalDateTime createdAt;
	    private LocalDateTime updatedAt;
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
		public String getDeviceId() {
			return deviceId;
		}
		public void setDeviceId(String deviceId) {
			this.deviceId = deviceId;
		}
		public String getHostname() {
			return hostname;
		}
		public void setHostname(String hostname) {
			this.hostname = hostname;
		}
		public String getIpAddress() {
			return ipAddress;
		}
		public void setIpAddress(String ipAddress) {
			this.ipAddress = ipAddress;
		}
		public String getOsVersion() {
			return osVersion;
		}
		public void setOsVersion(String osVersion) {
			this.osVersion = osVersion;
		}
		public String getAntivirusStatus() {
			return antivirusStatus;
		}
		public void setAntivirusStatus(String antivirusStatus) {
			this.antivirusStatus = antivirusStatus;
		}
		public String getFirewallStatus() {
			return firewallStatus;
		}
		public void setFirewallStatus(String firewallStatus) {
			this.firewallStatus = firewallStatus;
		}
		public String getLoggedInUser() {
			return loggedInUser;
		}
		public void setLoggedInUser(String loggedInUser) {
			this.loggedInUser = loggedInUser;
		}
		public LocalDateTime getLastUpdateCheck() {
			return lastUpdateCheck;
		}
		public void setLastUpdateCheck(LocalDateTime lastUpdateCheck) {
			this.lastUpdateCheck = lastUpdateCheck;
		}
		public boolean isDeleted() {
			return isDeleted;
		}
		public void setDeleted(boolean isDeleted) {
			this.isDeleted = isDeleted;
		}
		public boolean isActive() {
			return isActive;
		}
		public void setActive(boolean isActive) {
			this.isActive = isActive;
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
	    
	   
   }