package com.isteer.cvssanalyser.core.model;

import java.time.LocalDateTime;

public class CpeEntryModel {
	private Integer entryId;
	private String cpeName;
	private String cpeTitle;
	private String vendor;
	private String product;
	private String version;
	private LocalDateTime updatedDate;
	private boolean isDeprecated;
	public Integer getEntryId() {
		return entryId;
	}
	public void setEntryId(Integer entryId) {
		this.entryId = entryId;
	}
	public String getCpeName() {
		return cpeName;
	}
	public void setCpeName(String cpeName) {
		this.cpeName = cpeName;
	}
	public String getCpeTitle() {
		return cpeTitle;
	}
	public void setCpeTitle(String cpeTitle) {
		this.cpeTitle = cpeTitle;
	}
	public String getVendor() {
		return vendor;
	}
	public void setVendor(String vendor) {
		this.vendor = vendor;
	}
	public String getProduct() {
		return product;
	}
	public void setProduct(String product) {
		this.product = product;
	}
	public String getVersion() {
		return version;
	}
	public void setVersion(String version) {
		this.version = version;
	}
	public LocalDateTime getUpdatedDate() {
		return updatedDate;
	}
	public void setUpdatedDate(LocalDateTime updatedDate) {
		this.updatedDate = updatedDate;
	}
	public boolean isDeprecated() {
		return isDeprecated;
	}
	public void setDeprecated(boolean isDeprecated) {
		this.isDeprecated = isDeprecated;
	}
}
