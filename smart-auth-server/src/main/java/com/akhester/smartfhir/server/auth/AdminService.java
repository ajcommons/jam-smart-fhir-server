package com.akhester.smartfhir.server.auth;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Optional;

/**
 * Application-layer service for admin CRUD on clinicians and SMART app registrations.
 * Lives in the {@code auth} package to access package-private entity mutators.
 * Raw passwords are BCrypt-hashed before persistence; plain text is never stored.
 */
@Service
@Transactional
public class AdminService {

    private final ClinicianRepository  clinicianRepository;
    private final RegisteredAppRepository appRepository;
    private final PasswordEncoder      passwordEncoder;

    public AdminService(ClinicianRepository clinicianRepository,
                        RegisteredAppRepository appRepository,
                        PasswordEncoder passwordEncoder) {
        this.clinicianRepository = clinicianRepository;
        this.appRepository       = appRepository;
        this.passwordEncoder     = passwordEncoder;
    }

    // ══════════════════════════════════════════════════════════════
    //  Clinician operations
    // ══════════════════════════════════════════════════════════════

    @Transactional(readOnly = true)
    public List<Clinician> listClinicians() {
        return clinicianRepository.findAll();
    }

    @Transactional(readOnly = true)
    public Optional<Clinician> findClinician(String id) {
        return clinicianRepository.findById(id);
    }

    @Transactional(readOnly = true)
    public boolean usernameExists(String username) {
        return clinicianRepository.findByUsername(username).isPresent();
    }

    /**
     * Creates a new clinician account.
     *
     * @param username    login username — must be unique
     * @param rawPassword plain-text password (will be hashed before storage)
     * @param displayName full name shown in the portal and id_token
     * @param fhirUserId  FHIR Practitioner resource ID (may be null)
     * @param role        {@code "CLINICIAN"} or {@code "ADMIN"}
     * @return the saved {@link Clinician}
     * @throws IllegalArgumentException if username is already taken
     */
    public Clinician createClinician(String username, String rawPassword,
                                     String displayName, String fhirUserId,
                                     String role) {
        if (clinicianRepository.findByUsername(username).isPresent()) {
            throw new IllegalArgumentException(
                    "Username already exists: " + username);
        }
        String hash = passwordEncoder.encode(rawPassword);
        Clinician c = new Clinician(username, hash, displayName, fhirUserId, role);
        return clinicianRepository.save(c);
    }

    /**
     * Updates an existing clinician.  Pass {@code null} for {@code rawPassword} to
     * leave the password unchanged.
     *
     * @throws IllegalArgumentException if {@code id} is not found
     */
    public Clinician updateClinician(String id, String rawPassword,
                                     String displayName, String fhirUserId,
                                     boolean enabled, String role) {
        Clinician c = clinicianRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Clinician not found: " + id));
        if (rawPassword != null && !rawPassword.isBlank()) {
            c.setPasswordHash(passwordEncoder.encode(rawPassword));
        }
        c.setDisplayName(displayName);
        c.setFhirUserId(fhirUserId);
        c.setEnabled(enabled);
        c.setRole(role);
        return clinicianRepository.save(c);
    }

    /**
     * Deletes a clinician by internal ID.
     *
     * @return the deleted clinician's username (for flash messages — fetched and
     *         deleted in the same transaction, avoiding a read-then-delete race)
     * @throws IllegalArgumentException if not found
     */
    public String deleteClinician(String id) {
        Clinician c = clinicianRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException(
                        "Clinician not found: " + id));
        String username = c.getUsername();
        clinicianRepository.delete(c);
        return username;
    }

    // ══════════════════════════════════════════════════════════════
    //  SMART app operations
    // ══════════════════════════════════════════════════════════════

    @Transactional(readOnly = true)
    public List<RegisteredApp> listApps() {
        return appRepository.findAll();
    }

    @Transactional(readOnly = true)
    public Optional<RegisteredApp> findApp(String id) {
        return appRepository.findById(id);
    }

    @Transactional(readOnly = true)
    public boolean clientIdExists(String clientId) {
        return appRepository.findByClientId(clientId).isPresent();
    }

    /**
     * Registers a new SMART app.
     *
     * @param clientId            OAuth2 client identifier — must be unique
     * @param appName             human-readable display name
     * @param redirectUri         allowed redirect URI
     * @param allowedScopes       comma-separated SMART scope list
     * @param accessTokenTtlSecs  per-app token TTL override; {@code null} = server default
     * @throws IllegalArgumentException if clientId is already taken
     */
    public RegisteredApp createApp(String clientId, String appName,
                                   String redirectUri, String allowedScopes,
                                   Long accessTokenTtlSecs) {
        if (appRepository.findByClientId(clientId).isPresent()) {
            throw new IllegalArgumentException(
                    "Client ID already exists: " + clientId);
        }
        RegisteredApp app = new RegisteredApp(clientId, appName, redirectUri, allowedScopes);
        app.setAccessTokenTtlSeconds(accessTokenTtlSecs);
        return appRepository.save(app);
    }

    /**
     * Updates an existing SMART app registration.
     *
     * @throws IllegalArgumentException if {@code id} is not found
     */
    public RegisteredApp updateApp(String id, String appName,
                                   String redirectUri, String allowedScopes,
                                   Long accessTokenTtlSecs, boolean active) {
        RegisteredApp app = appRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException(
                        "App not found: " + id));
        app.setAppName(appName);
        app.setRedirectUri(redirectUri);
        app.setAllowedScopes(allowedScopes);
        app.setAccessTokenTtlSeconds(accessTokenTtlSecs);
        app.setActive(active);
        return appRepository.save(app);
    }

    /**
     * Deletes a SMART app registration.
     *
     * @return the deleted app's name (for flash messages — fetched and deleted in
     *         the same transaction, avoiding a read-then-delete race)
     * @throws IllegalArgumentException if not found
     */
    public String deleteApp(String id) {
        RegisteredApp app = appRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException(
                        "App not found: " + id));
        String appName = app.getAppName();
        appRepository.delete(app);
        return appName;
    }
}
