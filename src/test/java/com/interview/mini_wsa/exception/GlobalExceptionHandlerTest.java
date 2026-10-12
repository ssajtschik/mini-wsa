package com.interview.mini_wsa.exception;

import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import java.sql.SQLException;

import static org.junit.jupiter.api.Assertions.assertEquals;

class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @Test
    void handleDataIntegrityViolation_eventIdUniqueConstraint_returnsConflict() {
        ResponseEntity<String> response = handler.handleDataIntegrityViolation(
                integrityViolation(GlobalExceptionHandler.EVENT_ID_UNIQUE_CONSTRAINT));

        assertEquals(HttpStatus.CONFLICT, response.getStatusCode());
    }

    @Test
    void handleDataIntegrityViolation_otherConstraint_returnsBadRequest() {
        ResponseEntity<String> response = handler.handleDataIntegrityViolation(
                integrityViolation("security_events_threat_score_check"));

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
    }

    @Test
    void handleInvalidIngestRequest_returnsBadRequestWithMessage() {
        ResponseEntity<String> response = handler.handleInvalidIngestRequest(
                new InvalidIngestRequestException("events[1].hostname: must not be null"));

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("events[1].hostname: must not be null", response.getBody());
    }

    private static DataIntegrityViolationException integrityViolation(String constraintName) {
        return new DataIntegrityViolationException("could not execute statement",
                new ConstraintViolationException("constraint violated", new SQLException(), constraintName));
    }
}
