package com.akhester.smartfhir.server.launch;

import jakarta.persistence.*;
import java.time.Instant;

/**
 * Persisted binding between an opaque EHR launch token and the patient/encounter
 * context it represents (SMART App Launch v2 §7.2).
 * Tokens are single-use and expire after 5 minutes; {@link LaunchContextService}
 * creates and resolves them during the OAuth2 authorization flow.
 */
@Entity
@Table(name = "launch_contexts")
public class LaunchContext {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    /**
     * The opaque launch token — sent to the SMART client as {@code ?launch=}.
     * 32 random bytes, URL-safe base64 (256-bit entropy).
     */
    @Column(nullable = false, unique = true)
    private String token;

    /**
     * FHIR Patient resource ID from the HAPI server.
     * Included as {@code patient} in the token response.
     */
    @Column(nullable = false)
    private String patientFhirId;

    /**
     * FHIR Encounter resource ID — may be null if no encounter was selected.
     * Included as {@code encounter} in the token response when present.
     */
    @Column
    private String encounterFhirId;

    /**
     * Whether the SMART client app must render a patient header/banner.
     * Included as {@code need_patient_banner} in the token response.
     */
    @Column(nullable = false)
    private boolean needPatientBanner = true;

    /**
     * The client ID of the registered app that will handle this launch.
     * Used to validate that the authorize request comes from the right app.
     */
    @Column(nullable = false)
    private String clientId;

    /** Username of the clinician who initiated this launch. */
    @Column(nullable = false)
    private String launchedBy;

    /** When this launch token expires. Set to now + 5 minutes at creation. */
    @Column(nullable = false)
    private Instant expiresAt;

    /** Set to true after the token has been used in a token exchange. */
    @Column(nullable = false)
    private boolean used = false;

    /** When this record was created. */
    @Column(nullable = false)
    private Instant createdAt = Instant.now();

    // ── Constructors ──────────────────────────────────────────────────────────

    protected LaunchContext() {}

    public LaunchContext(String token, String patientFhirId, String encounterFhirId,
                         boolean needPatientBanner, String clientId, String launchedBy) {
        this.token              = token;
        this.patientFhirId      = patientFhirId;
        this.encounterFhirId    = encounterFhirId;
        this.needPatientBanner  = needPatientBanner;
        this.clientId           = clientId;
        this.launchedBy         = launchedBy;
        this.expiresAt          = Instant.now().plusSeconds(300); // 5 minutes
        this.createdAt          = Instant.now();
    }

    // ── Accessors ─────────────────────────────────────────────────────────────

    public String getToken()             { return token; }
    public String getPatientFhirId()     { return patientFhirId; }
    public String getEncounterFhirId()   { return encounterFhirId; }
    public boolean isNeedPatientBanner() { return needPatientBanner; }
    public String getClientId()          { return clientId; }
    public String getLaunchedBy()        { return launchedBy; }
    public Instant getExpiresAt()        { return expiresAt; }
    public boolean isUsed()              { return used; }

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }

    /**
     * @deprecated No longer called directly. Single-use enforcement is now handled
     * atomically at the database level via
     * {@link LaunchContextRepository#markUsedAtomic(String, java.time.Instant)},
     * which issues a single {@code UPDATE ... WHERE used = false} statement.
     * This eliminates the read-then-write race condition that existed when
     * marking tokens used through this method.
     *
     * <p>The {@code used} field is still set by the {@code UPDATE} query directly
     * on the database row — this Java method is retained only for JPA entity
     * consistency and testing purposes.</p>
     */
    @Deprecated(since = "0.1.0", forRemoval = false)
    public void markUsed() {
        this.used = true;
    }

    @Override
    public String toString() {
        return "LaunchContext[patient=" + patientFhirId
                + ", encounter=" + encounterFhirId
                + ", client=" + clientId
                + ", used=" + used + "]";
    }
}
