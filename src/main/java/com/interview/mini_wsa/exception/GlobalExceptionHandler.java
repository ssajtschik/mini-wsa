package com.interview.mini_wsa.exception;

import io.swagger.v3.oas.annotations.Hidden;
import jakarta.validation.ElementKind;
import jakarta.validation.Path;
import org.hibernate.exception.ConstraintViolationException;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.StreamSupport;

/**
 * Maps errors to RFC 9457 problem details. Validation errors are answered with 400, a fixed
 * {@code detail} where one applies (otherwise the exception message) and, when known, the
 * individual violations as an {@code errors} list of {@code "<field>: <message>"} entries.
 */
@ControllerAdvice
@Hidden
public class GlobalExceptionHandler extends ResponseEntityExceptionHandler {

    static final String EVENT_ID_UNIQUE_CONSTRAINT = "unique_security_events_event_id";

    public static final String VALIDATION_FAILED = "Invalid request content.";
    public static final String DUPLICATE_EVENT = "Duplicate event ID detected. Event was already ingested.";
    public static final String INTEGRITY_VIOLATION = "Database integrity violation.";
    public static final String ERRORS_PROPERTY = "errors";

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ResponseEntity<ProblemDetail> handleDataIntegrityViolation(DataIntegrityViolationException ex) {
        if (EVENT_ID_UNIQUE_CONSTRAINT.equalsIgnoreCase(constraintName(ex))) {
            return problem(HttpStatus.CONFLICT, DUPLICATE_EVENT, List.of());
        }
        return problem(HttpStatus.BAD_REQUEST, INTEGRITY_VIOLATION, List.of());
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
    public ResponseEntity<ProblemDetail> handleInvalidIngestRequest(InvalidIngestRequestException ex) {
        return problem(HttpStatus.BAD_REQUEST, messageOrDefault(ex), ex.getErrors());
    }

    /** Invalid query parameters, e.g. pagination values or an unknown category/action filter. */
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ProblemDetail> handleIllegalArgument(IllegalArgumentException ex) {
        return problem(HttpStatus.BAD_REQUEST, messageOrDefault(ex), List.of());
    }

    /** Constraint annotations on the generated API parameters, e.g. {@code limit > 100}. */
    @ExceptionHandler(jakarta.validation.ConstraintViolationException.class)
    public ResponseEntity<ProblemDetail> handleConstraintViolation(jakarta.validation.ConstraintViolationException ex) {
        List<String> errors = ex.getConstraintViolations().stream()
                .map(v -> parameterPath(v.getPropertyPath()) + ": " + v.getMessage())
                .sorted()
                .toList();
        return problem(HttpStatus.BAD_REQUEST, errors.isEmpty() ? messageOrDefault(ex) : VALIDATION_FAILED, errors);
    }

    /** {@code getSamples.limit} becomes {@code limit}. */
    private static String parameterPath(Path path) {
        return StreamSupport.stream(path.spliterator(), false)
                .filter(node -> node.getKind() != ElementKind.METHOD)
                .map(Path.Node::toString)
                .collect(Collectors.joining("."));
    }

    private static String messageOrDefault(Exception ex) {
        return ex.getMessage() != null ? ex.getMessage() : VALIDATION_FAILED;
    }

    private static ResponseEntity<ProblemDetail> problem(HttpStatus status, String detail, List<String> errors) {
        return ResponseEntity.status(status).body(body(status, detail, errors));
    }

    private static ProblemDetail body(HttpStatus status, String detail, List<String> errors) {
        ProblemDetail problem = ProblemDetail.forStatusAndDetail(status, detail);
        if (!errors.isEmpty()) {
            problem.setProperty(ERRORS_PROPERTY, errors);
        }
        return problem;
    }
}
