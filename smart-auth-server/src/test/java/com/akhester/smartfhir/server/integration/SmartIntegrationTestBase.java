package com.akhester.smartfhir.server.integration;

import com.akhester.smartfhir.server.auth.Clinician;
import com.akhester.smartfhir.server.auth.ClinicianRepository;
import com.akhester.smartfhir.server.auth.RegisteredApp;
import com.akhester.smartfhir.server.auth.RegisteredAppRepository;
import com.akhester.smartfhir.server.security.LoginAttemptService;
import org.junit.jupiter.api.BeforeEach;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

/**
 * Base class for SMART on FHIR integration tests.
 *
 * <h3>What this provides</h3>
 * <ul>
 *   <li>Full Spring context with H2 in-memory database</li>
 *   <li>MockMvc for real HTTP simulation through all filter chains</li>
 *   <li>A seeded clinician ({@code test.clinician} / {@code Test1234!})</li>
 *   <li>A seeded SMART app registration ({@code test-smart-app})</li>
 *   <li>PKCE helper methods (code verifier / challenge generation)</li>
 * </ul>
 *
 * <h3>Profile</h3>
 * Runs under the {@code dev} profile so:
 * <ul>
 *   <li>H2 in-memory, Flyway disabled, {@code ddl-auto: create-drop}</li>
 *   <li>InMemoryOAuth2AuthorizationService (no JDBC setup needed)</li>
 *   <li>DataInitializer is skipped (we seed our own test data)</li>
 * </ul>
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
@ActiveProfiles("dev")
@TestPropertySource(properties = {
        "smart.server.cors.allowed-origins=http://localhost:8081,http://localhost:3000"
})
public abstract class SmartIntegrationTestBase {

    /** Test clinician credentials — consistent across all integration tests. */
    protected static final String TEST_USERNAME = "test.clinician";
    protected static final String TEST_PASSWORD = "Test1234!";

    /** Test SMART app client registration values. */
    protected static final String TEST_CLIENT_ID    = "test-smart-app";
    protected static final String TEST_REDIRECT_URI = "http://localhost:8081/callback";
    protected static final String TEST_SCOPES       =
            "launch, launch/patient, openid, fhirUser, patient/Patient.rs, offline_access";

    @Autowired
    protected MockMvc mockMvc;

    @Autowired
    private ClinicianRepository clinicianRepository;

    @Autowired
    private RegisteredAppRepository registeredAppRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private LoginAttemptService loginAttemptService;

    /**
     * Seeds one clinician and one SMART app before each test.
     * Uses {@code deleteAll()} + re-insert to ensure a clean, deterministic state.
     * H2 is recreated fresh for each test class ({@code ddl-auto: create-drop}).
     */
    @BeforeEach
    void seedTestData() {
        // Reset the in-memory IP failure counter so lockout tests don't bleed into each other
        loginAttemptService.resetAll();

        clinicianRepository.deleteAll();
        registeredAppRepository.deleteAll();

        clinicianRepository.save(new Clinician(
                TEST_USERNAME,
                passwordEncoder.encode(TEST_PASSWORD),
                "Test Clinician",
                "Practitioner-TEST-001"
        ));

        registeredAppRepository.save(new RegisteredApp(
                TEST_CLIENT_ID,
                "Integration Test SMART App",
                TEST_REDIRECT_URI,
                TEST_SCOPES
        ));
    }

    // ── PKCE helpers ──────────────────────────────────────────────────────────

    /**
     * Returns a cryptographically random code verifier (43–128 chars, URL-safe).
     * Uses a fixed value so tests are deterministic and reproducible.
     */
    protected static String testCodeVerifier() {
        // Fixed 64-char URL-safe string — meets RFC 7636 §4.1 requirements
        return "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    }

    /**
     * Returns the S256 code challenge for the fixed verifier above.
     * S256(verifier) = BASE64URL(SHA-256(ASCII(verifier)))
     */
    protected static String testCodeChallenge() {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(testCodeVerifier().getBytes(StandardCharsets.US_ASCII));
            return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
        } catch (Exception e) {
            throw new RuntimeException("SHA-256 not available", e);
        }
    }
}
