package com.interview.mini_wsa.exception;

import io.swagger.v3.oas.annotations.Hidden;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
@Hidden
public class GlobalExceptionHandler {

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<String> handleDataIntegrityViolation(DataIntegrityViolationException ex) {
        if (ex.getMessage() != null && ex.getMessage().contains("unique_security_events_event_id")) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body("Duplicate event ID detected. Event was already ingested.");
        }
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("Database integrity violation.");
    }
}