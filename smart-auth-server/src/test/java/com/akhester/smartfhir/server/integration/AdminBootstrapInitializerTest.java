package com.akhester.smartfhir.server.integration;

import com.akhester.smartfhir.server.auth.AdminBootstrapInitializer;
import com.akhester.smartfhir.server.auth.Clinician;
import com.akhester.smartfhir.server.auth.ClinicianRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies that {@link AdminBootstrapInitializer} creates the first admin account
 * when the clinician table is empty, and is idempotent when accounts already exist.
 *
 * <p>The initializer is {@code @Profile("prod")} so it is not registered as a Spring
 * bean under the {@code dev} test profile.  Tests construct it directly, injecting
 * the repository and password encoder from the Spring context — this exercises the
 * real logic without needing to switch profiles.</p>
 */
@DisplayName("AdminBootstrapInitializer")
class AdminBootstrapInitializerTest extends SmartIntegrationTestBase {

    @Autowired
    private ClinicianRepository clinicianRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    /** Build the initializer directly — bypasses the @Profile("prod") guard. */
    private AdminBootstrapInitializer initializer() {
        return new AdminBootstrapInitializer(clinicianRepository, passwordEncoder);
    }

    @Test
    @DisplayName("Creates admin/admin when clinician table is empty")
    void run_emptyTable_createsDefaultAdmin() throws Exception {
        // Wipe the table seeded by SmartIntegrationTestBase.seedTestData()
        clinicianRepository.deleteAll();
        assertThat(clinicianRepository.count()).isZero();

        initializer().run();

        assertThat(clinicianRepository.count()).isEqualTo(1);

        Clinician admin = clinicianRepository.findAll().get(0);
        assertThat(admin.getUsername()).isEqualTo("admin");
        assertThat(admin.getRole()).isEqualTo("ADMIN");
        assertThat(admin.isEnabled()).isTrue();
        assertThat(passwordEncoder.matches("admin", admin.getPasswordHash())).isTrue();
    }

    @Test
    @DisplayName("Does NOT insert when clinician table already has accounts (idempotent)")
    void run_tableNotEmpty_doesNothing() throws Exception {
        // seedTestData() already inserted one clinician
        long countBefore = clinicianRepository.count();
        assertThat(countBefore).isGreaterThan(0);

        initializer().run();

        // Count must not change
        assertThat(clinicianRepository.count()).isEqualTo(countBefore);
    }

    @Test
    @DisplayName("Bootstrap admin has ROLE_ADMIN authority in UserDetails")
    void bootstrapAdmin_hasAdminAuthority() throws Exception {
        clinicianRepository.deleteAll();
        initializer().run();

        Clinician admin = clinicianRepository.findAll().get(0);
        com.akhester.smartfhir.server.auth.ClinicianUserDetails details =
                new com.akhester.smartfhir.server.auth.ClinicianUserDetails(admin);

        assertThat(details.getAuthorities())
                .extracting(a -> a.getAuthority())
                .contains("ROLE_ADMIN", "ROLE_CLINICIAN");
    }
}
