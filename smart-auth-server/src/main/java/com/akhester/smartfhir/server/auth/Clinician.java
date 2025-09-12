package com.akhester.smartfhir.server.auth;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;

/**
 * A clinician who can log in to this SMART auth server to authorise apps.
 * {@code fhirUserId} is the corresponding FHIR {@code Practitioner} resource ID,
 * surfaced as the {@code fhirUser} claim in the OIDC {@code id_token}.
 * Patient records are stored in the HAPI FHIR server, not in this table.
 */
@Entity
@Table(name = "clinicians")
public class Clinician {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    /** Login username — used on the login page. */
    @Column(nullable = false, unique = true)
    @NotBlank
    private String username;

    /** BCrypt-hashed password. */
    @Column(nullable = false)
    @NotBlank
    private String passwordHash;

    /** Full display name — included as {@code name} in the id_token. */
    @Column
    private String displayName;

    /** FHIR Practitioner resource ID in the HAPI server. */
    @Column
    private String fhirUserId;

    /** Whether this account is active. */
    @Column(nullable = false)
    private boolean enabled = true;

    /**
     * Role granted to this clinician: {@code CLINICIAN} (default) or {@code ADMIN}.
     * Stored as a plain string — no enum to keep migrations simple.
     * Spring Security sees this as {@code ROLE_CLINICIAN} or {@code ROLE_ADMIN}.
     */
    @Column(nullable = false)
    private String role = "CLINICIAN";

    protected Clinician() {}

    /** Standard constructor — creates a regular clinician account. */
    public Clinician(String username, String passwordHash,
                     String displayName, String fhirUserId) {
        this.username     = username;
        this.passwordHash = passwordHash;
        this.displayName  = displayName;
        this.fhirUserId   = fhirUserId;
    }

    /** Constructor with explicit role — use {@code "ADMIN"} for admin accounts. */
    public Clinician(String username, String passwordHash,
                     String displayName, String fhirUserId, String role) {
        this(username, passwordHash, displayName, fhirUserId);
        this.role = role != null ? role : "CLINICIAN";
    }

    public String getId()           { return id; }
    public String getUsername()     { return username; }
    public String getPasswordHash() { return passwordHash; }
    public String getDisplayName()  { return displayName; }
    public String getFhirUserId()   { return fhirUserId; }
    public boolean isEnabled()      { return enabled; }
    public String getRole()         { return role; }

    // ── Package-private mutators (only AdminService may call) ─────────────────
    void setPasswordHash(String h)  { this.passwordHash = h; }
    void setDisplayName(String n)   { this.displayName  = n; }
    void setFhirUserId(String f)    { this.fhirUserId   = f; }
    void setEnabled(boolean e)      { this.enabled      = e; }
    void setRole(String r)          { this.role         = r != null ? r : "CLINICIAN"; }
}
