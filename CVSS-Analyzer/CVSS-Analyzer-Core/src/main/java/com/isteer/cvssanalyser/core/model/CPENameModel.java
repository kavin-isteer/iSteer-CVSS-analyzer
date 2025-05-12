package com.isteer.cvssanalyser.core.model;

public class CPENameModel {
	private static final String CPE23_URI_FORMAT = "cpe:2.3:a:%s:%s:%s:%s:*:*:*:*:*:*";
	private String vendor;
	private String product;
	private String version;
	private String update="*";
	private boolean isValidCpe;
	
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


	
	public String getUpdate() {
		return update;
	}



	public void setUpdate(String update) {
		this.update = update;
	}


	public boolean isValidCpe() {
		return isValidCpe;
	}



	public void setValidCpe(boolean isValidCpe) {
		this.isValidCpe = isValidCpe;
	}



	@Override
	public String toString() {
		return getCPE23Uri();
	}

	public String getCPE23Uri() {
			return String.format(CPE23_URI_FORMAT, this.vendor,this.product,this.version,this.update);
	}
}
