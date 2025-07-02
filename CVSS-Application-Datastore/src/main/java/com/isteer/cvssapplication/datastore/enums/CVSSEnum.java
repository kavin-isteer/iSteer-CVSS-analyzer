package com.isteer.cvssapplication.datastore.enums;

public enum CVSSEnum {
	// Computer-related operations
	COMPUTER_ADD(2000, "computer.add"), COMPUTER_UPDATE(2002, "computer.update"),
	COMPUTER_APP_UPDATE(2006, "computer.application.update"), 
	COMPUTER_NOT_FOUND(2004, "computer.notfound"),
	 COMPUTER_WITH_SAME_IP_EXISTS(2005, "computer.duplicate.ip"),
	COMPUTER_DEACTIVATED(2006, "computer.deactivated"), COMPUTER_ALREADY_DELETED(2008, "computer.already.deleted"),
	COMPUTER_ALREADY_ACTIVE(2009, "computer.already.active"), COMPUTER_INACTIVE(5017, "computer.inactive"),
	COMPUTER_DEVICE_ID_EXISTS(2010, "computer.device_id.exists"),
	COMPUTER_PAYLOAD_INVALID(2021, "Invaild.Computer.payload"),

	COMPUTER_SOFT_DELETED(2010, "computer.soft.deleted"),
	COMPUTER_REVERT_SOFT_DELETE(2011, "computer.revert.soft.delete"), COMPUTER_ACTIVATED(2012, "computer.activated"),
	COMPUTER_NOT_DELETED(2015, "computer.not.deleted"),
	COMPUTER_ALREADY_DEACTIVATED(2017, "computer.already.deactivated"), COMPUTER_DELETED(2018, "computer.deleted"),
	INVALID_STATUS(2019, "invalid.status"),

	// Application-related operations
	 APPLICATION_UPDATE(2102, "application.update"),
	 APPLICATION_NOT_FOUND(2104, "application.notfound"),



	// General error codes
	INVALID_INPUT(5008, "invalid.input"), DATA_INTEGRITY_VIOLATION(5009, "data.integrity.violation"),
	VALIDATION_ERROR(5010, "validation.error"), NULL_POINTER_EXCEPTION(5011, "null.pointer.exception"),
	INVALID_SQL_SYNTAX(5012, "invalid.sql.syntax"), ILLEGAL_ARGUMENT(5013, "illegal.argument.exception"),
	Internal_Server_Error(9000, "internal.error"), INVALID_DATE_FORMAT(5014, "invalid.date.format"),
	NO_CHANGES(2033, "no.changes.detected"), APPLICATION_NAME_BLANK(2108, "application.name.blank"),
	DUPLICATE_APPLICATIONS(2109, "duplicate.applications"),;

	private final int statusCode;
	private final String messageKey;

	CVSSEnum(int statusCode, String messageKey) {
		this.statusCode = statusCode;
		this.messageKey = messageKey;
	}

	public int getStatusCode() {
		return statusCode;
	}

	public String getMessageKey() {
		return messageKey;
	}
}