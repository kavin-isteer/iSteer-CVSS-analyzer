package com.isteer.cvssapplication.datastore.enums;

public enum CVSSEnum {
    // Computer-related operations
    COMPUTER_ADD(2000, "computer.add"),
    COMPUTER_UPDATE(2002, "computer.update"),
    COMPUTER_APP_UPDATE(2006, "computer.application.update"),
    COMPUTER_DELETE(2003, "computer.delete"),
    COMPUTER_NOT_FOUND(2004, "computer.notfound"),
    COMPUTER_UUID_EMPTY(2007, "computer.uuid.empty"),
    IP_ADDRESS_INVALID(2001, "ip.invalid"),
    COMPUTER_WITH_SAME_IP_EXISTS(2005, "computer.duplicate.ip"),
    COMPUTER_DEACTIVATED(2006, "computer.deactivated"),
    COMPUTER_ALREADY_DELETED(2008, "computer.already.deleted"),
    COMPUTER_ALREADY_ACTIVE(2009, "computer.already.active"),
    COMPUTER_INACTIVE(5017, "computer.inactive"),
    COMPUTER_DEVICE_ID_EXISTS(2010, "computer.device_id.exists"),
    COMPUTER_PAYLOAD_INVALID(2021, "Invaild.Computer.payload"),
   

    // Application-related operations
    APPLICATION_ADD(2100, "application.add"),
    APPLICATION_UPDATE(2102, "application.update"),
    APPLICATION_DELETE(2103, "application.delete"),
    APPLICATION_NOT_FOUND(2104, "application.notfound"),
    APPLICATION_UUID_EMPTY(2107, "application.uuid.empty"),
    APPLICATION_WITH_SAME_NAME_EXISTS(2105, "application.name.exists"),
    APPLICATION_NOT_ACTIVE(5018, "application.not.active"),

    // Vulnerability-related operations
    VULNERABILITY_ADD(2200, "vulnerability.add"),
    VULNERABILITY_UPDATE(2202, "vulnerability.update"),
    VULNERABILITY_DELETE(2203, "vulnerability.delete"),
    VULNERABILITY_NOT_FOUND(2204, "vulnerability.notfound"),
    VULNERABILITY_UUID_EMPTY(2207, "vulnerability.uuid.empty"),
    VULNERABILITY_ALREADY_EXISTS(2205, "vulnerability.exists"),
    VULNERABILITY_SEVERITY_INVALID(5006, "vulnerability.severity.invalid"),
    VULNERABILITY_CVSS_SCORE_INVALID(5007, "vulnerability.cvss.score.invalid"),
    INVALID_CVE_ID(5001, "invalid.cve.id"),
    VULNERABILITY_NOT_ACTIVE(5016, "vulnerability.not.active"),

    // General error codes
    INVALID_INPUT(5008, "invalid.input"),
    DATA_INTEGRITY_VIOLATION(5009, "data.integrity.violation"),
    VALIDATION_ERROR(5010, "validation.error"),
    NULL_POINTER_EXCEPTION(5011, "null.pointer.exception"),
    INVALID_SQL_SYNTAX(5012, "invalid.sql.syntax"),
    ILLEGAL_ARGUMENT(5013, "illegal.argument.exception"),
    Internal_Server_Error(9000, "internal.error"), 
    INVALID_DATE_FORMAT(5014, "invalid.date.format"), 
    NO_CHANGES(2033, "no.changes.detected"), APPLICATION_NAME_BLANK(2108, "application.name.blank");

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