package com.isteer.dto;

import java.time.LocalDateTime;
import java.util.List;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonProperty;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public class ComputerPayloadDTO {
	 @NotBlank(message = "Device ID cannot be blank")
	    @Size(max = 50, message = "Device ID must be at most 50 characters")
	    private String deviceId;
	    
	    @NotBlank(message = "Machine name cannot be blank")
	    @Size(max = 100, message = "Machine name must be at most 100 characters")
	    private String machineName;
	    
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
	    
	    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss'Z'")
	    private LocalDateTime lastUpdateCheck;
	    
	    @NotEmpty(message = "Installed software cannot be empty")
	    private List<SoftwareDTO> installedSoftware;
	    
	    @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss'Z'")
	    private LocalDateTime timestamp;
	    
	    public static class SoftwareDTO {
			
			 @NotBlank(message = "Software name cannot be blank")
		        @Size(max = 100, message = "Software name must be at most 100 characters")
		        private String name;
		        
		        @Size(max = 50, message = "Software version must be at most 50 characters")
		        private String version;
		        
		        @NotBlank(message = "Vendor name cannot be blank")
		        @Size(max = 100, message = "Vendor name must be at most 100 characters")
		        @JsonProperty("VendorName")
		        private String vendorName;
		        
		        @NotNull(message = "Installed date cannot be null")
		        @JsonFormat(pattern = "yyyy-MM-dd'T'HH:mm:ss")
		        @JsonProperty("InstalledDate")
		        private LocalDateTime installedDate;

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

				public LocalDateTime getInstalledDate() {
					return installedDate;
				}

				public void setInstalledDate(LocalDateTime installedDate) {
					this.installedDate = installedDate;
				}

	    }
		public String getDeviceId() {
			return deviceId;
		}

		public void setDeviceId(String deviceId) {
			this.deviceId = deviceId;
		}

		public String getMachineName() {
			return machineName;
		}

		public void setMachineName(String machineName) {
			this.machineName = machineName;
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

		public List<SoftwareDTO> getInstalledSoftware() {
			return installedSoftware;
		}

		public void setInstalledSoftware(List<SoftwareDTO> installedSoftware) {
			this.installedSoftware = installedSoftware;
		}

		public LocalDateTime getTimestamp() {
			return timestamp;
		}

		public void setTimestamp(LocalDateTime timestamp) {
			this.timestamp = timestamp;
		}
		
		
		


}