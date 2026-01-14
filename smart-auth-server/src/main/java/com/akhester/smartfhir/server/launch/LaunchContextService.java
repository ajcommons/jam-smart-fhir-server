package com.akhester.smartfhir.server.launch;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;

/**
 * Creates and resolves SMART EHR launch tokens (SMART App Launch v2 §7.2).
 * The token is a 256-bit opaque handle passed to the app as {@code ?launch=}
 * and resolved back to patient/encounter context at token-issuance time by
 * {@link com.akhester.smartfhir.server.token.SmartTokenCustomizer}.
 * Expired tokens are purged by a scheduled cleanup task.
 */
@Service
public class LaunchContextService {

    private static final Logger log = LoggerFactory.getLogger(LaunchContextService.class);

    private final LaunchContextRepository repository;
    private final SecureRandom secureRandom = new SecureRandom();

    public LaunchContextService(LaunchContextRepository repository) {
        this.repository = repository;
    }

    /**
     * Creates a new launch context and returns the opaque launch token.
     *
     * Called by the patient picker UI when a clinician clicks "Launch App".
     *
     * @param patientFhirId     FHIR Patient ID from the HAPI server
     * @param encounterFhirId   FHIR Encounter ID — may be null
     * @param needPatientBanner whether the app must render a patient header
     * @param clientId          the registered app client ID
     * @param launchedBy        the clinician's username
     * @return the opaque launch token to pass to the SMART client as {@code ?launch=}
     */
    @Transactional
    public String createLaunchToken(String patientFhirId,
                                    String encounterFhirId,
                                    boolean needPatientBanner,
                                    String clientId,
                                    String launchedBy) {
        String token = generateToken();

        LaunchContext context = new LaunchContext(
                token, patientFhirId, encounterFhirId,
                needPatientBanner, clientId, launchedBy
        );
        repository.save(context);

        log.info("Launch token created — patient={}, client={}, launchedBy={}",
                patientFhirId, clientId, launchedBy);

        return token;
    }

    /**
     * Resolves a launch token to its clinical context.
     *
     * <p>Uses an atomic {@code UPDATE ... WHERE used = false AND expiresAt > now}
     * to enforce single-use semantics without a race condition. A clinician
     * double-clicking "Launch App" cannot cause two concurrent requests to both
     * succeed — only one UPDATE will match, the second gets {@code updated = 0}.</p>
     *
     * <p>{@code @Transactional} is required because {@link LaunchContextRepository#markUsedAtomic}
     * is a {@code @Modifying} query that requires an active transaction.
     * Without it, {@code TransactionRequiredException} is thrown in strict JPA
     * provider configurations.</p>
     *
     * @param token the opaque launch token from the authorize request
     * @return the {@link LaunchContext} — or throws if token is invalid/expired/used
     * @throws LaunchTokenException if the token doesn't exist, is expired, or already used
     */
    @Transactional
    public LaunchContext resolveLaunchToken(String token) {
        // Atomic single-use enforcement — one SQL UPDATE, no read-then-write race
        int updated = repository.markUsedAtomic(token, Instant.now());

        if (updated == 0) {
            // Token was not found, already used, or expired
            throw new LaunchTokenException(
                    "Launch token not found, already used, or expired: " + token);
        }

        // Token was successfully claimed — fetch the full context for patient/encounter data
        LaunchContext context = repository.findByToken(token)
                .orElseThrow(() -> new LaunchTokenException(
                        "Launch token disappeared after atomic claim: " + token));

        log.info("Launch token resolved and consumed — patient={}, encounter={}",
                context.getPatientFhirId(), context.getEncounterFhirId());

        return context;
    }

    /**
     * Purges expired launch tokens every 10 minutes.
     * Keeps the database clean — expired tokens are useless and
     * their patient data shouldn't stay around unnecessarily.
     *
     * <p>Explicit {@code @Transactional} is required here because
     * {@code @Scheduled} methods run in a new thread outside any active
     * transaction — the class-level {@code @Transactional} does not cover them.</p>
     */
    @Scheduled(cron = "0 */10 * * * *")  // every 10 minutes, on the minute
    @Transactional
    public void purgeExpiredTokens() {
        int deleted = repository.deleteExpiredBefore(Instant.now());
        if (deleted > 0) {
            log.debug("Purged {} expired launch tokens", deleted);
        }
    }

    // ── private ───────────────────────────────────────────────────────────────

    private String generateToken() {
        // 32 random bytes → 43-char URL-safe base64 (256-bit entropy)
        byte[] bytes = new byte[32];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
