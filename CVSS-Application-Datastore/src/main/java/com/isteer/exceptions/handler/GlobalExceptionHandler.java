package com.isteer.exceptions.handler;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.jdbc.BadSqlGrammarException;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

import com.isteer.dto.ErrorMessageDto;
import com.isteer.enums.CVSSEnum;
import com.isteer.exception.BussinessException;
import com.isteer.util.StatusMessageUtil;

@ControllerAdvice
public class GlobalExceptionHandler {
    // Logger instance for logging error messages
    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    // Handle IllegalArgumentException and return a BAD_REQUEST response
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorMessageDto> handleIllegalArgument(IllegalArgumentException ex) {
        logger.error("Validation error: {}", ex.getMessage()); // Log the error message
        // Create an error response with appropriate status code and message
        ErrorMessageDto errorMessage = new ErrorMessageDto(
            CVSSEnum.ILLEGAL_ARGUMENT.getStatusCode(),
            String.format("%s %s", StatusMessageUtil.getMessage(CVSSEnum.ILLEGAL_ARGUMENT), ex.getMessage())
        );
        return new ResponseEntity<>(errorMessage, HttpStatus.BAD_REQUEST); // Return BAD_REQUEST status
    }

    // Handle SQL syntax errors and return an INTERNAL_SERVER_ERROR response
    @ExceptionHandler(BadSqlGrammarException.class)
    public ResponseEntity<ErrorMessageDto> handleDatabaseError(BadSqlGrammarException ex) {
        logger.error("Database error: {}", ex.getMessage()); // Log the error message
        // Create an error response with appropriate status code and message
        ErrorMessageDto errorMessage = new ErrorMessageDto(
            CVSSEnum.INVALID_SQL_SYNTAX.getStatusCode(),
            String.format("%s %s", StatusMessageUtil.getMessage(CVSSEnum.INVALID_SQL_SYNTAX), ex.getMessage())
        );
        return new ResponseEntity<>(errorMessage, HttpStatus.INTERNAL_SERVER_ERROR); // Return INTERNAL_SERVER_ERROR status
    }

    // Handle general exceptions and return an INTERNAL_SERVER_ERROR response
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorMessageDto> handleGeneralException(Exception ex) {
        logger.error("Unexpected error: {}", ex.getMessage()); // Log the error message
        // Create an error response with appropriate status code and message
        ErrorMessageDto errorMessage = new ErrorMessageDto(
            CVSSEnum.Internal_Server_Error.getStatusCode(),
            String.format("%s %s", StatusMessageUtil.getMessage(CVSSEnum.Internal_Server_Error), ex.getMessage())
        );
        return new ResponseEntity<>(errorMessage, HttpStatus.INTERNAL_SERVER_ERROR); // Return INTERNAL_SERVER_ERROR status
    }

    // Handle custom business exceptions and return a BAD_REQUEST response
    @ExceptionHandler(BussinessException.class)
    public ResponseEntity<ErrorMessageDto> handleBusinessException(BussinessException ex) {
        CVSSEnum error = ex.getError(); // Retrieve the error enum from the exception
        logger.error("Business error: {}", ex.getMessage()); // Log the error message
        // Create an error response with appropriate status code and message
        ErrorMessageDto errorMessage = new ErrorMessageDto(
            error.getStatusCode(),
            StatusMessageUtil.getMessage(error)
        );
        return new ResponseEntity<>(errorMessage, HttpStatus.BAD_REQUEST); // Return BAD_REQUEST status
    }

    // Handle NullPointerException and return an INTERNAL_SERVER_ERROR response
    @ExceptionHandler(NullPointerException.class)
    public ResponseEntity<ErrorMessageDto> handleNullPointerException(NullPointerException ex) {
        logger.error("Null pointer error: {}", ex.getMessage()); // Log the error message
        // Create an error response with appropriate status code and message
        ErrorMessageDto errorMessage = new ErrorMessageDto(
            CVSSEnum.NULL_POINTER_EXCEPTION.getStatusCode(),
            String.format("%s %s", StatusMessageUtil.getMessage(CVSSEnum.NULL_POINTER_EXCEPTION), ex.getMessage())
        );
        return new ResponseEntity<>(errorMessage, HttpStatus.INTERNAL_SERVER_ERROR); // Return INTERNAL_SERVER_ERROR status
    }

    // Handle JSON parsing errors and return a BAD_REQUEST response
    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorMessageDto> handleHttpMessageNotReadable(HttpMessageNotReadableException ex) {
        logger.error("JSON parse error: {}", ex.getMessage()); // Log the error message
        // Create an error response with appropriate status code and message
        ErrorMessageDto errorResponse = new ErrorMessageDto(
            CVSSEnum.INVALID_INPUT.getStatusCode(),
            StatusMessageUtil.getMessage(CVSSEnum.INVALID_INPUT)
        );
        return new ResponseEntity<>(errorResponse, HttpStatus.BAD_REQUEST); // Return BAD_REQUEST status
    }

    // Handle validation errors and return a BAD_REQUEST response
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorMessageDto> handleValidationException(MethodArgumentNotValidException e) {
        ErrorMessageDto errorDto = new ErrorMessageDto(); // Create a new error response object
        errorDto.setErrorCode(9321); // Set a custom error code

        // Retrieve the first field error from the validation result
        FieldError fieldError = e.getBindingResult().getFieldError();
        String errorMessage = (fieldError != null)
            ? fieldError.getDefaultMessage() // Use the default message if available
            : CVSSEnum.VALIDATION_ERROR.getMessageKey(); // Fallback to a generic validation error message

        errorDto.setErrorMessage(errorMessage); // Set the error message
        logger.error("Validation error: {}", errorMessage); // Log the error message
        return new ResponseEntity<>(errorDto, HttpStatus.BAD_REQUEST); // Return BAD_REQUEST status
    }

    // Handle data integrity violations and return appropriate responses
    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ErrorMessageDto> handleDataIntegrityViolation(DataIntegrityViolationException ex) {
        logger.error("Data integrity violation: {}", ex.getMessage()); // Log the error message

        // Check for specific duplicate key errors and return CONFLICT responses
        if (ex.getMessage().contains("Duplicate entry") && ex.getMessage().contains("vulnerabilities.dependency_uuid")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ErrorMessageDto(
                    CVSSEnum.VULNERABILITY_ALREADY_EXISTS.getStatusCode(),
                    StatusMessageUtil.getMessage(CVSSEnum.VULNERABILITY_ALREADY_EXISTS)
                ));
        }

        if (ex.getMessage().contains("Duplicate entry") && ex.getMessage().contains("applications.computer_uuid")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ErrorMessageDto(
                    CVSSEnum.APPLICATION_WITH_SAME_NAME_EXISTS.getStatusCode(),
                    StatusMessageUtil.getMessage(CVSSEnum.APPLICATION_WITH_SAME_NAME_EXISTS)
                ));
        }

        if (ex.getMessage().contains("Duplicate entry") && ex.getMessage().contains("dependencies.application_uuid")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ErrorMessageDto(
                    CVSSEnum.DEPENDENCY_WITH_SAME_NAME_EXISTS.getStatusCode(),
                    StatusMessageUtil.getMessage(CVSSEnum.DEPENDENCY_WITH_SAME_NAME_EXISTS)
                ));
        }

        if (ex.getMessage().contains("Duplicate entry") && ex.getMessage().contains("computers.ip_address")) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST)
                .body(new ErrorMessageDto(
                    CVSSEnum.COMPUTER_WITH_SAME_IP_EXISTS.getStatusCode(),
                    StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_WITH_SAME_IP_EXISTS)
                ));
        }

        // Handle other data integrity violations with a generic response
        ErrorMessageDto errorMessage = new ErrorMessageDto(
            CVSSEnum.DATA_INTEGRITY_VIOLATION.getStatusCode(),
            String.format("%s %s", StatusMessageUtil.getMessage(CVSSEnum.DATA_INTEGRITY_VIOLATION), ex.getMessage())
        );
        return new ResponseEntity<>(errorMessage, HttpStatus.BAD_REQUEST); // Return BAD_REQUEST status
    }
}
