package com.isteer.enums;

// Enum class to define various constants related to CVSS (Common Vulnerability Scoring System)
public enum CVSSEnum {

    // Enum constants for computer-related operations
    COMPUTER_ADD(2000, "computer.add"), // Code for adding a computer
    COMPUTER_UPDATE(2002, "computer.update"), // Code for updating a computer
    COMPUTER_DELETE(2003, "computer.delete"), // Code for deleting a computer
    COMPUTER_NOT_FOUND(2004, "computer.notfound"), // Code for computer not found error
    COMPUTER_UUID_EMPTY(2007, "computer.uuid.empty"), // Code for empty UUID error
    IP_ADDRESS_INVALID(2001, "ip.invalid"), // Code for invalid IP address error
    COMPUTER_WITH_SAME_IP_EXISTS(2005, "computer.duplicate.ip"), // Code for duplicate IP error
    COMPUTER_DEACTIVATED(2006, "computer.deactivated"), // Code for deactivated computer
    COMPUTER_ALREADY_DELETED(2008, "computer.already.deleted"), // Code for already deleted computer
    COMPUTER_ALREADY_ACTIVE(2009, "computer.already.active"), // Code for already active computer
    Internal_Server_Error(9000, "internal.error"), // Code for internal server error

    // Enum constants for application-related operations
    APPLICATION_ADD(2000, "application.add"), // Code for adding an application
    APPLICATION_UPDATE(2002, "application.update"), // Code for updating an application
    APPLICATION_DELETE(2003, "application.delete"), // Code for deleting an application
    APPLICATION_NOT_FOUND(2004, "application.notfound"), // Code for application not found error
    APPLICATION_UUID_EMPTY(2007, "application.uuid.empty"), // Code for empty UUID error
    APPLICATION_WITH_SAME_NAME_EXISTS(2005, "application.name.exists"), // Code for duplicate application name error

    // Enum constants for dependency-related operations
    DEPENDENCY_ADD(2000, "dependency.add"), // Code for adding a dependency
    DEPENDENCY_UPDATE(2002, "dependency.update"), // Code for updating a dependency
    DEPENDENCY_DELETE(2003, "dependency.delete"), // Code for deleting a dependency
    DEPENDENCY_NOT_FOUND(2004, "dependency.notfound"), // Code for dependency not found error
    DEPENDENCY_UUID_EMPTY(2007, "dependency.uuid.empty"), // Code for empty UUID error
    DEPENDENCY_WITH_SAME_NAME_EXISTS(2005, "dependency.name.exists"), // Code for duplicate dependency name error

    // Enum constants for vulnerability-related operations
    VULNERABILITY_ADD(2000, "vulnerability.add"), // Code for adding a vulnerability
    VULNERABILITY_UPDATE(2002, "vulnerability.update"), // Code for updating a vulnerability
    VULNERABILITY_DELETE(2003, "vulnerability.delete"), // Code for deleting a vulnerability
    VULNERABILITY_NOT_FOUND(2004, "vulnerability.notfound"), // Code for vulnerability not found error
    VULNERABILITY_UUID_EMPTY(2007, "vulnerability.uuid.empty"), // Code for empty UUID error
    VULNERABILITY_ALREADY_EXISTS(2005, "vulnerability.exists"), // Code for duplicate vulnerability error
    VULNERABILITY_SEVERITY_INVALID(5006, "vulnerability.severity.invalid"), // Code for invalid severity error
    VULNERABILITY_CVSS_SCORE_INVALID(5007, "vulnerability.cvss.score.invalid"), // Code for invalid CVSS score error
    INVALID_INPUT(5008, "invalid.input"), // Code for invalid input error
    INVALID_CVE_ID(5001, "invalid.cve.id"), // Code for invalid CVE ID error
    DATA_INTEGRITY_VIOLATION(5009, "data.integrity.violation"), // Code for data integrity violation error
    VALIDATION_ERROR(5010, "validation.error"), // Code for validation error
    NULL_POINTER_EXCEPTION(5011, "null.pointer.exception"), // Code for null pointer exception
    INVALID_SQL_SYNTAX(5012, "invalid.sql.syntax"), // Code for invalid SQL syntax error
    ILLEGAL_ARGUMENT(5013, "illegal.argument.exception"), // Code for illegal argument exception
    COMPUTER_ACTIVATED(5014, "computer.activated"), // Code for activated computer
    DEPENDENCY_NOT_ACTIVE(5015, "dependency.not.active"), // Code for inactive dependency
    VULNERABILITY_NOT_ACTIVE(5016, "vulnerability.not.active"), // Code for inactive vulnerability
    COMPUTER_INACTIVE(5017, "computer.inactive"), // Code for inactive computer
    APPLICATION_NOT_ACTIVE(5018, "application.not.active"), COMPUTER_PAYLOAD_INVALID(2021, "Invaild.Computer.payload"), 
    COMPUTER_APPLICATION_EXISTS(2091, "computer.application.exists"); // Code for inactive application

    // Private fields to store the status code and message key for each enum constant
    private final int statusCode; // Status code associated with the enum constant
    private final String messageKey; // Message key associated with the enum constant

    // Constructor to initialize the enum constants with status code and message key
    CVSSEnum(int statusCode, String messageKey) {
        this.statusCode = statusCode; // Assign the status code
        this.messageKey = messageKey; // Assign the message key
    }

    // Getter method to retrieve the status code
    public int getStatusCode() {
        return statusCode; // Return the status code
    }

    // Getter method to retrieve the message key
    public String getMessageKey() {
        return messageKey; // Return the message key
    }
}
// Note: This enum is used to define various status codes and message keys for different operations