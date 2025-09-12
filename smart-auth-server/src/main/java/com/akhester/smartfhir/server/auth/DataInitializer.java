package com.akhester.smartfhir.server.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Profile;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Seeds test clinicians and a registered SMART client app on first startup.
 * Skipped if any clinician row already exists. Active in all profiles except
 * {@code prod} and {@code idp} — production uses {@link AdminBootstrapInitializer}.
 */
@Component
@Profile("!prod & !idp")   // does NOT run in production or when IdP federation is active
public class DataInitializer implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(DataInitializer.class);

    private final ClinicianRepository clinicianRepository;
    private final RegisteredAppRepository registeredAppRepository;
    private final PasswordEncoder passwordEncoder;

    public DataInitializer(ClinicianRepository clinicianRepository,
                           RegisteredAppRepository registeredAppRepository,
                           PasswordEncoder passwordEncoder) {
        this.clinicianRepository    = clinicianRepository;
        this.registeredAppRepository = registeredAppRepository;
        this.passwordEncoder        = passwordEncoder;
    }

    @Override
    public void run(String... args) {
        seedClinicians();
        seedRegisteredApps();
    }

    private void seedClinicians() {
        if (clinicianRepository.count() > 0) {
            log.debug("Clinician database already populated — skipping seed data");
            return;
        }

        clinicianRepository.save(new Clinician(
                "dr.smith",
                passwordEncoder.encode("password"),
                "Dr. Jane Smith",
                "Practitioner-EXAMPLE-001"   // ← replace with a real Practitioner ID from your HAPI server
        ));

        clinicianRepository.save(new Clinician(
                "dr.jones",
                passwordEncoder.encode("password"),
                "Dr. Robert Jones",
                "Practitioner-EXAMPLE-002"   // ← replace with a real Practitioner ID from your HAPI server
        ));

        log.info("Test clinicians created — username: dr.smith / dr.jones");
        log.warn("Default password is set in DataInitializer — CHANGE before any non-local deployment");
    }

    private void seedRegisteredApps() {
        if (registeredAppRepository.count() > 0) {
            log.debug("Registered apps already populated — skipping seed data");
            return;
        }

        // Register our own SMART client app (akhester-smart-on-fhir)
        registeredAppRepository.save(new RegisteredApp(
                "akhester-smart-client",
                "AKHester SMART on FHIR Client",
                "http://localhost:8080/callback",
                "launch, launch/patient, openid, fhirUser, " +
                "patient/Patient.rs, patient/Condition.rs, " +
                "patient/MedicationRequest.rs, patient/Observation.rs, " +
                "patient/AllergyIntolerance.rs, offline_access"
        ));

        log.info("Default SMART client app registered — client_id: akhester-smart-client");
    }
}
