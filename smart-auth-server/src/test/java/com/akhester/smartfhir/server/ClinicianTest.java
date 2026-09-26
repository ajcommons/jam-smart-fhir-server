package com.akhester.smartfhir.server;

import com.akhester.smartfhir.server.auth.Clinician;
import com.akhester.smartfhir.server.auth.ClinicianUserDetails;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for Clinician entity and ClinicianUserDetails adapter.
 */
class ClinicianTest {

    @Test
    void clinician_storesFields() {
        Clinician c = new Clinician(
                "dr.smith", "hashed-pw", "Dr. Jane Smith", "Practitioner-EXAMPLE-001");

        assertThat(c.getUsername()).isEqualTo("dr.smith");
        assertThat(c.getPasswordHash()).isEqualTo("hashed-pw");
        assertThat(c.getDisplayName()).isEqualTo("Dr. Jane Smith");
        assertThat(c.getFhirUserId()).isEqualTo("Practitioner-EXAMPLE-001");
        assertThat(c.isEnabled()).isTrue();
    }

    @Test
    void clinicianUserDetails_returnsCorrectUsername() {
        Clinician c = new Clinician(
                "dr.jones", "hashed-pw", "Dr. Robert Jones", "Practitioner-EXAMPLE-002");
        ClinicianUserDetails details = new ClinicianUserDetails(c);

        assertThat(details.getUsername()).isEqualTo("dr.jones");
    }

    @Test
    void clinicianUserDetails_returnsPasswordHash() {
        Clinician c = new Clinician(
                "dr.smith", "bcrypt-hash-here", "Dr. Jane Smith", "Practitioner-EXAMPLE-001");
        ClinicianUserDetails details = new ClinicianUserDetails(c);

        assertThat(details.getPassword()).isEqualTo("bcrypt-hash-here");
    }

    @Test
    void clinicianUserDetails_hasRoleUser() {
        Clinician c = new Clinician(
                "dr.smith", "hashed-pw", "Dr. Jane Smith", "Practitioner-EXAMPLE-001");
        ClinicianUserDetails details = new ClinicianUserDetails(c);

        assertThat(details.getAuthorities())
                .map(a -> a.getAuthority())
                .contains("ROLE_CLINICIAN");
    }

    @Test
    void clinicianUserDetails_exposedFhirUserId() {
        Clinician c = new Clinician(
                "dr.smith", "hashed-pw", "Dr. Jane Smith", "Practitioner-EXAMPLE-001");
        ClinicianUserDetails details = new ClinicianUserDetails(c);

        assertThat(details.getFhirUserId()).isEqualTo("Practitioner-EXAMPLE-001");
    }

    @Test
    void clinicianUserDetails_isEnabledWhenClinicianEnabled() {
        Clinician c = new Clinician(
                "dr.smith", "hashed-pw", "Dr. Jane Smith", "Practitioner-EXAMPLE-001");
        ClinicianUserDetails details = new ClinicianUserDetails(c);

        assertThat(details.isEnabled()).isTrue();
        assertThat(details.isAccountNonExpired()).isTrue();
        assertThat(details.isAccountNonLocked()).isTrue();
        assertThat(details.isCredentialsNonExpired()).isTrue();
    }
}
