package com.isteer.cvssapplication.datastore.dto;


public class StatusMessageDTO {
	
	private int statusCode;
	private String statusMessage;
	
	public StatusMessageDTO(int statusCode, String statusMessage) {
		super();
		this.statusCode = statusCode;
		this.statusMessage = statusMessage;
	}

	public StatusMessageDTO() {

	}

	public int getStatusCode() {
		return statusCode;
	}

	public void setStatusCode(int statusCode) {
		this.statusCode = statusCode;
	}

	public String getStatusMessage() {
		return statusMessage;
	}

	public void setStatusMessage(String statusMessage) {
		this.statusMessage = statusMessage;
	}
	
	


}
