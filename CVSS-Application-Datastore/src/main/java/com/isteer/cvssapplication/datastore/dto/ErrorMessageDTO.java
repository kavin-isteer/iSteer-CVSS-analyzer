package com.isteer.cvssapplication.datastore.dto;



public class ErrorMessageDTO {
	
	private int errorCode;
	private String errorMessage;
	
	public ErrorMessageDTO() {
		// TODO Auto-generated constructor stub
	}
	public ErrorMessageDTO(int errorCode) {
		this.errorCode = errorCode;
	}
	
	public ErrorMessageDTO(int errorCode, String errorMessage) {
		this.errorCode = errorCode;
		this.errorMessage = errorMessage;
	}
	
	public int getErrorCode() {
		return errorCode;
	}
	public void setErrorCode(int errorCode) {
		this.errorCode = errorCode;
	}
	public String getErrorMessage() {
		return errorMessage;
	}
	public void setErrorMessage(String errorMessage) {
		this.errorMessage = errorMessage;
	}

}
