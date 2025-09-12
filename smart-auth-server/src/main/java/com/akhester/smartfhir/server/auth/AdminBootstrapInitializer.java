package com.akhester.smartfhir.server.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Seeds the first {@code ROLE_ADMIN} account on a fresh production deployment.
 * Runs only under the {@code prod} profile; dev uses {@link DataInitializer}.
 * Idempotent — skips insert if any clinician row already exists.
 * Override defaults via {@code BOOTSTRAP_ADMIN_USERNAME} / {@code BOOTSTRAP_ADMIN_PASSWORD}
 * env vars. <strong>Change or delete the bootstrap account immediately after first login.</strong>
 */
@Component
@Order(1)   // run before any other CommandLineRunner
@org.springframework.context.annotation.Profile("prod")
public class AdminBootstrapInitializer implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(AdminBootstrapInitializer.class);

    /**
     * Default bootstrap username — override with {@code BOOTSTRAP_ADMIN_USERNAME}.
     * Deliberately simple so operators can find and change it immediately.
     */
    private static final String DEFAULT_USERNAME = "admin";

    /**
     * Default bootstrap password — override with {@code BOOTSTRAP_ADMIN_PASSWORD}.
     * Deliberately simple — the warning makes it impossible to miss.
     */
    private static final String DEFAULT_PASSWORD = "admin";

    private final ClinicianRepository clinicianRepository;
    private final PasswordEncoder     passwordEncoder;

    @org.springframework.beans.factory.annotation.Value(
            "${BOOTSTRAP_ADMIN_USERNAME:" + DEFAULT_USERNAME + "}")
    private String bootstrapUsername;

    @org.springframework.beans.factory.annotation.Value(
            "${BOOTSTRAP_ADMIN_PASSWORD:" + DEFAULT_PASSWORD + "}")
    private String bootstrapPassword;

    public AdminBootstrapInitializer(ClinicianRepository clinicianRepository,
                                     PasswordEncoder passwordEncoder) {
        this.clinicianRepository = clinicianRepository;
        this.passwordEncoder     = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        if (clinicianRepository.count() > 0) {
            // Database already has accounts — nothing to bootstrap.
            log.debug("AdminBootstrapInitializer: clinician table not empty — skipping bootstrap");
            return;
        }

        Clinician admin = new Clinician(
                bootstrapUsername,
                passwordEncoder.encode(bootstrapPassword),
                "Bootstrap Admin",
                null,           // no FHIR Practitioner ID — set via admin UI after first login
                "ADMIN"
        );
        clinicianRepository.save(admin);

        // ── Loud, unmissable warning — same style as Keycloak / OpenMRS ──────
        log.warn("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        log.warn("  SMART AUTH SERVER — BOOTSTRAP ADMIN ACCOUNT CREATED");
        log.warn("  Username : {}", bootstrapUsername);
        log.warn("  Password : {}", usingDefault() ? DEFAULT_PASSWORD + "  ← CHANGE THIS NOW" : "*** (custom)");
        log.warn("");
        log.warn("  1. Log in at /admin");
        log.warn("  2. Create your real admin account (Clinicians tab)");
        log.warn("  3. Log out and log back in as the new admin");
        log.warn("  4. Delete the '{}' account from the Clinicians tab", bootstrapUsername);
        log.warn("");
        log.warn("  Leaving default credentials active is a SECURITY RISK.");
        log.warn("  Override at first boot with env vars:");
        log.warn("    BOOTSTRAP_ADMIN_USERNAME=<username>");
        log.warn("    BOOTSTRAP_ADMIN_PASSWORD=<strong-password>");
        log.warn("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
    }

    private boolean usingDefault() {
        return DEFAULT_USERNAME.equals(bootstrapUsername)
            && DEFAULT_PASSWORD.equals(bootstrapPassword);
    }
}
