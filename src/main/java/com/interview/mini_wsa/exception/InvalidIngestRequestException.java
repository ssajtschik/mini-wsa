package com.interview.mini_wsa.exception;

import lombok.Getter;

import java.util.List;

/**
 * Raised when an ingest payload does not satisfy the {@code oneOf} contract of
 * {@code IngestRequest}, i.e. it carries both {@code event} and {@code events} or neither,
 * or when one of its events fails validation.
 */
@Getter
public class InvalidIngestRequestException extends RuntimeException {

    /** Per-field violations, e.g. {@code events[1].hostname: must not be null}; empty if none apply. */
    private final List<String> errors;

    public InvalidIngestRequestException(String message) {
        this(message, List.of());
    }

    public InvalidIngestRequestException(String message, List<String> errors) {
        super(message);
        this.errors = List.copyOf(errors);
    }
}
