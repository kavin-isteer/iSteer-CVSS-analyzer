package com.isteer.cvssanalyser.core.model;

import java.time.LocalDateTime;

public class ApplicationModel {
	
	private String applicationName;
	private String applicationVersion;
	private String applicationVendor;
	private LocalDateTime installedDate;
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
	public String getApplicationVendor() {
		return applicationVendor;
	}
	public void setApplicationVendor(String applicationVendor) {
		this.applicationVendor = applicationVendor;
	}
	public LocalDateTime getInstalledDate() {
		return installedDate;
	}
	public void setInstalledDate(LocalDateTime installedDate) {
		this.installedDate = installedDate;
	}
	
	@Override
	public String toString() {
		return "ApplicationModel [applicationName=" + applicationName + ", applicationVersion=" + applicationVersion
				+ ", applicationVendor=" + applicationVendor + ", installedDate=" + installedDate + "]";
	}

}
