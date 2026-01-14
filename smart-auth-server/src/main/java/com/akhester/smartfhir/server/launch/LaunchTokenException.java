package com.akhester.smartfhir.server.launch;

/**
 * Thrown when a launch token is invalid, expired, or already used.
 * Results in a token exchange failure with {@code invalid_grant}.
 */
public class LaunchTokenException extends RuntimeException {

    public LaunchTokenException(String message) {
        super(message);
    }
}
