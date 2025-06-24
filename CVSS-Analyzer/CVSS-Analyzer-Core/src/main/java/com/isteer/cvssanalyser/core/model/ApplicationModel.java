package com.isteer.cvssanalyser.core.model;

public class ApplicationModel {
	
	private String applicationUuid;
	private String applicationName;
	private String applicationVersion;
	private String applicationVendor;
	private boolean isExists;
	
	public String getApplicationUuid() {
		return applicationUuid;
	}
	public void setApplicationUuid(String applicationUuid) {
		this.applicationUuid = applicationUuid;
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
	public String getApplicationVendor() {
		return applicationVendor;
	}
	public void setApplicationVendor(String applicationVendor) {
		this.applicationVendor = applicationVendor;
	}
	public boolean isExists() {
		return isExists;
	}
	public void setExists(boolean isExists) {
		this.isExists = isExists;
	}
	
	@Override
	public String toString() {
		return "ApplicationModel [applicationUuid=" + applicationUuid + ", applicationName=" + applicationName
				+ ", applicationVersion=" + applicationVersion + ", applicationVendor=" + applicationVendor
				+ ", isExists=" + isExists + "]";
	}
	
}
