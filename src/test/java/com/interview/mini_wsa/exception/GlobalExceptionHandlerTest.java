package com.interview.mini_wsa.exception;

import jakarta.validation.ConstraintViolation;
import jakarta.validation.Validation;
import jakarta.validation.Validator;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import org.hibernate.exception.ConstraintViolationException;
import org.junit.jupiter.api.Test;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;

import java.lang.reflect.Method;
import java.sql.SQLException;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class GlobalExceptionHandlerTest {

    private final GlobalExceptionHandler handler = new GlobalExceptionHandler();

    @Test
    void handleDataIntegrityViolation_eventIdUniqueConstraint_returnsConflictWithFixedMessage() {
        ResponseEntity<ProblemDetail> response = handler.handleDataIntegrityViolation(
                integrityViolation(GlobalExceptionHandler.EVENT_ID_UNIQUE_CONSTRAINT));

        assertEquals(HttpStatus.CONFLICT, response.getStatusCode());
        assertEquals(409, response.getBody().getStatus());
        assertEquals(GlobalExceptionHandler.DUPLICATE_EVENT, response.getBody().getDetail());
    }

    @Test
    void handleDataIntegrityViolation_otherConstraint_returnsBadRequestWithFixedMessage() {
        ResponseEntity<ProblemDetail> response = handler.handleDataIntegrityViolation(
                integrityViolation("security_events_threat_score_check"));

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals(GlobalExceptionHandler.INTEGRITY_VIOLATION, response.getBody().getDetail());
    }

    @Test
    void handleDataIntegrityViolation_withoutConstraintCause_returnsBadRequest() {
        ResponseEntity<ProblemDetail> response = handler.handleDataIntegrityViolation(
                new DataIntegrityViolationException("no constraint name available"));

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals(GlobalExceptionHandler.INTEGRITY_VIOLATION, response.getBody().getDetail());
    }

    @Test
    void handleInvalidIngestRequest_returnsMessageAndEveryViolation() {
        ResponseEntity<ProblemDetail> response = handler.handleInvalidIngestRequest(
                new InvalidIngestRequestException("Invalid security event(s).", List.of(
                        "events[1].hostname: must not be null",
                        "events[1].rule.severity: must not be null")));

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("Invalid security event(s).", response.getBody().getDetail());
        assertEquals(List.of("events[1].hostname: must not be null", "events[1].rule.severity: must not be null"),
                errors(response.getBody()));
    }

    @Test
    void handleInvalidIngestRequest_withoutViolations_omitsErrors() {
        ResponseEntity<ProblemDetail> response = handler.handleInvalidIngestRequest(
                new InvalidIngestRequestException("Exactly one of 'event' or 'events' must be supplied, but neither was present"));

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("Exactly one of 'event' or 'events' must be supplied, but neither was present",
                response.getBody().getDetail());
        assertNull(response.getBody().getProperties());
    }

    @Test
    void handleIllegalArgument_returnsBadRequestWithExceptionMessage() {
        ResponseEntity<ProblemDetail> response = handler.handleIllegalArgument(
                new IllegalArgumentException("Limit must be greater than 0."));

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("Limit must be greater than 0.", response.getBody().getDetail());
    }

    @Test
    void handleIllegalArgument_withoutMessage_fallsBackToFixedMessage() {
        ResponseEntity<ProblemDetail> response = handler.handleIllegalArgument(new IllegalArgumentException());

        assertEquals(GlobalExceptionHandler.VALIDATION_FAILED, response.getBody().getDetail());
    }

    @Test
    void handleConstraintViolation_listsViolationsByParameterName() throws Exception {
        Method method = Endpoint.class.getMethod("getSamples", Integer.class, Integer.class);
        Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
        Set<ConstraintViolation<Endpoint>> violations = validator.forExecutables()
                .validateParameters(new Endpoint(), method, new Object[]{101, -1});

        ResponseEntity<ProblemDetail> response = handler.handleConstraintViolation(
                new jakarta.validation.ConstraintViolationException(violations));

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals(GlobalExceptionHandler.VALIDATION_FAILED, response.getBody().getDetail());
        assertEquals(List.of("limit: must be less than or equal to 100", "offset: must be greater than or equal to 0"),
                errors(response.getBody()));
    }

    @Test
    void handleConstraintViolation_withoutViolations_returnsExceptionMessage() {
        ResponseEntity<ProblemDetail> response = handler.handleConstraintViolation(
                new jakarta.validation.ConstraintViolationException("limit out of range", Set.of()));

        assertEquals(HttpStatus.BAD_REQUEST, response.getStatusCode());
        assertEquals("limit out of range", response.getBody().getDetail());
    }

    @SuppressWarnings("unchecked")
    private static List<String> errors(ProblemDetail problem) {
        Map<String, Object> properties = problem.getProperties();
        return properties == null ? null : (List<String>) properties.get(GlobalExceptionHandler.ERRORS_PROPERTY);
    }

    private static DataIntegrityViolationException integrityViolation(String constraintName) {
        return new DataIntegrityViolationException("could not execute statement",
                new ConstraintViolationException("constraint violated", new SQLException(), constraintName));
    }

    /** Stand-in for the generated API method, to produce real method-validation violations. */
    static class Endpoint {
        public void getSamples(@Max(100) Integer limit, @Min(0) Integer offset) {
        }
    }
}
