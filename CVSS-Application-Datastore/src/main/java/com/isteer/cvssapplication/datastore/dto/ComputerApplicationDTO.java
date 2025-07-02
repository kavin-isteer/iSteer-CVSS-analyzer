package com.isteer.cvssapplication.datastore.dto;

import java.time.LocalDateTime;

public class ComputerApplicationDTO {

	private String uuid;
	private String computerUuid;
	private String applicationUuid;
	private LocalDateTime installedDate;
	private boolean isDeleted;
	private String applicationName;
	private String applicationVersion;
	private String applicationVendorName;

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

	public String getApplicationUuid() {
		return applicationUuid;
	}

	public void setApplicationUuid(String applicationUuid) {
		this.applicationUuid = applicationUuid;
	}

	public LocalDateTime getInstalledDate() {
		return installedDate;
	}

	public void setInstalledDate(LocalDateTime installedDate) {
		this.installedDate = installedDate;
	}

	public boolean isDeleted() {
		return isDeleted;
	}

	public void setDeleted(boolean isDeleted) {
		this.isDeleted = isDeleted;
	}

	public String getApplicationName() {
		return applicationName;
	}

	public void setApplicationName(String applicationName) {
		this.applicationName = applicationName;
	}

	public String getApplicationVersion() {
		return applicationVersion;
	}

	public void setApplicationVersion(String applicationVersion) {
		this.applicationVersion = applicationVersion;
	}

	public String getApplicationVendorName() {
		return applicationVendorName;
	}

	public void setApplicationVendorName(String applicationVendorName) {
		this.applicationVendorName = applicationVendorName;
	}

	@Override
	public String toString() {
		return "ComputerApplicationDTO [uuid=" + uuid + ", computerUuid=" + computerUuid + ", applicationUuid="
				+ applicationUuid + ", installedDate=" + installedDate + ", isDeleted=" + isDeleted
				+ ", applicationName=" + applicationName + ", applicationVersion=" + applicationVersion
				+ ", applicationVendorName=" + applicationVendorName + "]";
	}

}
