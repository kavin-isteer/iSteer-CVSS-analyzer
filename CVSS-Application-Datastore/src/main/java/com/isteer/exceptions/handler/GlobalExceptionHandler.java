package com.isteer.exceptions.handler;

import com.isteer.dto.ErrorMessageDto;
import com.isteer.enums.CVSSEnum;
import com.isteer.exception.BussinessException;
import com.isteer.util.StatusMessageUtil;
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

@ControllerAdvice
public class GlobalExceptionHandler {
    private static final Logger logger = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(BussinessException.class)
    public ResponseEntity<ErrorMessageDto> handleBusinessException(BussinessException ex) {
        CVSSEnum error = ex.getError();
        logger.error("Business error: {}", ex.getMessage());
        return new ResponseEntity<>(
                new ErrorMessageDto(error.getStatusCode(), StatusMessageUtil.getMessage(error)),
                HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorMessageDto> handleValidationException(MethodArgumentNotValidException ex) {
        FieldError fieldError = ex.getBindingResult().getFieldError();
        String errorMessage = fieldError != null ? fieldError.getDefaultMessage() : "Validation failed";
        logger.error("Validation error: {}", errorMessage);
        return new ResponseEntity<>(
                new ErrorMessageDto(CVSSEnum.VALIDATION_ERROR.getStatusCode(), errorMessage),
                HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorMessageDto> handleHttpMessageNotReadable(HttpMessageNotReadableException ex) {
        logger.error("JSON parse error: {}", ex.getMessage());
        return new ResponseEntity<>(
                new ErrorMessageDto(CVSSEnum.INVALID_INPUT.getStatusCode(), StatusMessageUtil.getMessage(CVSSEnum.INVALID_INPUT)),
                HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ErrorMessageDto> handleDataIntegrityViolation(DataIntegrityViolationException ex) {
        logger.error("Data integrity violation: {}", ex.getMessage());
        String message = ex.getMessage().toLowerCase();
        if (message.contains("computers_device_id_uindex")) {
            return new ResponseEntity<>(
                    new ErrorMessageDto(CVSSEnum.COMPUTER_DEVICE_ID_EXISTS.getStatusCode(),
                            StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_DEVICE_ID_EXISTS)),
                    HttpStatus.BAD_REQUEST);
        } else if (message.contains("computers_ip_address")) {
            return new ResponseEntity<>(
                    new ErrorMessageDto(CVSSEnum.COMPUTER_WITH_SAME_IP_EXISTS.getStatusCode(),
                            StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_WITH_SAME_IP_EXISTS)),
                    HttpStatus.BAD_REQUEST);
        } else if (message.contains("computer_applications_computer_uuid_application_uuid")) {
            return new ResponseEntity<>(
                    new ErrorMessageDto(CVSSEnum.COMPUTER_APPLICATION_EXISTS.getStatusCode(),
                            StatusMessageUtil.getMessage(CVSSEnum.COMPUTER_APPLICATION_EXISTS)),
                    HttpStatus.BAD_REQUEST);
        }
        return new ResponseEntity<>(
                new ErrorMessageDto(CVSSEnum.DATA_INTEGRITY_VIOLATION.getStatusCode(),
                        StatusMessageUtil.getMessage(CVSSEnum.DATA_INTEGRITY_VIOLATION)),
                HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorMessageDto> handleIllegalArgument(IllegalArgumentException ex) {
        logger.error("Illegal argument: {}", ex.getMessage());
        return new ResponseEntity<>(
                new ErrorMessageDto(CVSSEnum.ILLEGAL_ARGUMENT.getStatusCode(),
                        StatusMessageUtil.getMessage(CVSSEnum.ILLEGAL_ARGUMENT)),
                HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(BadSqlGrammarException.class)
    public ResponseEntity<ErrorMessageDto> handleDatabaseError(BadSqlGrammarException ex) {
        logger.error("SQL error: {}", ex.getMessage());
        return new ResponseEntity<>(
                new ErrorMessageDto(CVSSEnum.INVALID_SQL_SYNTAX.getStatusCode(),
                        StatusMessageUtil.getMessage(CVSSEnum.INVALID_SQL_SYNTAX)),
                HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(NullPointerException.class)
    public ResponseEntity<ErrorMessageDto> handleNullPointerException(NullPointerException ex) {
        logger.error("Null pointer: {}", ex.getMessage());
        return new ResponseEntity<>(
                new ErrorMessageDto(CVSSEnum.NULL_POINTER_EXCEPTION.getStatusCode(),
                        StatusMessageUtil.getMessage(CVSSEnum.NULL_POINTER_EXCEPTION)),
                HttpStatus.INTERNAL_SERVER_ERROR);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorMessageDto> handleGeneralException(Exception ex) {
        logger.error("Unexpected error: {}", ex.getMessage());
        return new ResponseEntity<>(
                new ErrorMessageDto(CVSSEnum.Internal_Server_Error.getStatusCode(),
                        StatusMessageUtil.getMessage(CVSSEnum.Internal_Server_Error)),
                HttpStatus.INTERNAL_SERVER_ERROR);
    }
}