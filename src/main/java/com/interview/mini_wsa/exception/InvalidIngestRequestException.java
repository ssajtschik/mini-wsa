package com.interview.mini_wsa.exception;

/**
 * Raised when an ingest payload does not satisfy the {@code oneOf} contract of
 * {@code IngestRequest}, i.e. it carries both {@code event} and {@code events} or neither.
 */
public class InvalidIngestRequestException extends RuntimeException {

    public InvalidIngestRequestException(String message) {
        super(message);
    }
}
