package com.isteer.cvssapplication.datastore.entity;

import java.time.LocalDateTime;

import com.fasterxml.jackson.annotation.JsonFormat;

import jakarta.validation.constraints.NotBlank;

public class Computer {
	private Long id;
	private String uuid;

	@NotBlank(message = "Device ID cannot be blank")

	private String deviceId;

	@NotBlank(message = "Machine Name cannot be blank")
	private String machineName;

	@NotBlank(message = "IP address cannot be blank")
	private String ipAddress;

	@NotBlank(message = "OS version cannot be blank")
	private String osVersion;

	@NotBlank(message = "Antivirus status cannot be blank")
	private String antivirusStatus;

	@NotBlank(message = "Firewall status cannot be blank")
	private String firewallStatus;

	@NotBlank(message = "Logged-in user cannot be blank")
	private String loggedInUser;
	@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
	private LocalDateTime lastUpdateCheck;
	@NotBlank(message = "Timestamp cannot be blank")
	@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
	private LocalDateTime timestamp;
	private boolean isDeleted;
	private boolean isActive;
	@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
	private LocalDateTime createdAt;
	@JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss")
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

	public LocalDateTime getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(LocalDateTime timestamp) {
		this.timestamp = timestamp;
	}

}