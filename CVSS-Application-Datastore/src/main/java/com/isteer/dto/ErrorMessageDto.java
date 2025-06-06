package com.isteer.dto;



public class ErrorMessageDto {
	
	private int errorCode;
	private String errorMessage;
	
	public ErrorMessageDto() {
		// TODO Auto-generated constructor stub
	}
	public ErrorMessageDto(int errorCode) {
		this.errorCode = errorCode;
	}
	
	public ErrorMessageDto(int errorCode, String errorMessage) {
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
