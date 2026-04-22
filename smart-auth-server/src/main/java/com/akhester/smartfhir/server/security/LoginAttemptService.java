package com.akhester.smartfhir.server.security;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Tracks failed login attempts per client IP and enforces a 15-minute lockout
 * after 5 consecutive failures. Per-IP (not per-username) to avoid the
 * denial-of-service vector where an attacker locks out a known clinician's account.
 * State is in-process ({@code ConcurrentHashMap}); replace with a distributed cache
 * (e.g. Caffeine + Redis) for multi-instance deployments.
 */
@Service
public class LoginAttemptService {

    private static final Logger log = LoggerFactory.getLogger(LoginAttemptService.class);

    /** Number of failures before lockout. */
    private static final int MAX_ATTEMPTS = 5;

    /** How long the lockout lasts in seconds. */
    private static final long LOCKOUT_SECONDS = 15 * 60; // 15 minutes

    private final Map<String, AttemptRecord> attempts = new ConcurrentHashMap<>();

    /**
     * Called when a login attempt fails. Records the failure.
     * @param ip the client IP address
     */
    public void recordFailure(String ip) {
        attempts.compute(ip, (key, existing) -> {
            if (existing == null || existing.isExpired()) {
                return new AttemptRecord(1, Instant.now().plusSeconds(LOCKOUT_SECONDS));
            }
            return existing.increment();
        });

        AttemptRecord record = attempts.get(ip);
        if (record != null && record.count >= MAX_ATTEMPTS) {
            log.warn("Login lockout activated — IP={}, failures={}, unlockAt={}",
                    ip, record.count, record.lockoutUntil);
        } else {
            log.debug("Login failure recorded — IP={}, failures={}", ip,
                    record != null ? record.count : 1);
        }
    }

    /**
     * Called when a login succeeds. Clears the failure record.
     * @param ip the client IP address
     */
    public void recordSuccess(String ip) {
        attempts.remove(ip);
        log.debug("Login success — failure counter cleared for IP={}", ip);
    }

    /**
     * Returns true if this IP is currently locked out.
     * Expired lockouts are cleared lazily.
     *
     * @param ip the client IP address
     * @return true if too many recent failures
     */
    public boolean isLockedOut(String ip) {
        AttemptRecord record = attempts.get(ip);
        if (record == null) {
            return false;
        }
        if (record.isExpired()) {
            attempts.remove(ip); // lazy eviction
            return false;
        }
        return record.count >= MAX_ATTEMPTS;
    }

    /**
     * Clears all recorded failures and lockouts.
     *
     * <p><strong>Intended for testing only.</strong> Call this in
     * {@code @BeforeEach} / {@code @AfterEach} to reset the in-memory counter
     * between integration test methods that exercise lockout behaviour.
     * In production this is never called — a restart has the same effect.
     */
    public void resetAll() {
        attempts.clear();
    }

    // ── Internal state ────────────────────────────────────────────────────────

    private record AttemptRecord(int count, Instant lockoutUntil) {

        AttemptRecord increment() {
            return new AttemptRecord(count + 1, lockoutUntil);
        }

        boolean isExpired() {
            return Instant.now().isAfter(lockoutUntil);
        }
    }
}
