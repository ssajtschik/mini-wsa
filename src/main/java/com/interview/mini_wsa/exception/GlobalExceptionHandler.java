package com.interview.mini_wsa.exception;

import io.swagger.v3.oas.annotations.Hidden;
import org.hibernate.exception.ConstraintViolationException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
@Hidden
public class GlobalExceptionHandler {

    static final String EVENT_ID_UNIQUE_CONSTRAINT = "unique_security_events_event_id";

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<String> handleDataIntegrityViolation(DataIntegrityViolationException ex) {
        if (EVENT_ID_UNIQUE_CONSTRAINT.equalsIgnoreCase(constraintName(ex))) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body("Duplicate event ID detected. Event was already ingested.");
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Database integrity violation.");
    }

    private static String constraintName(Throwable ex) {
        for (Throwable cause = ex; cause != null; cause = cause.getCause()) {
            if (cause instanceof ConstraintViolationException cve) {
                return cve.getConstraintName();
            }
        }
        return null;
    }

    @ExceptionHandler(InvalidIngestRequestException.class)
    public ResponseEntity<String> handleInvalidIngestRequest(InvalidIngestRequestException ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getMessage());
    }
}