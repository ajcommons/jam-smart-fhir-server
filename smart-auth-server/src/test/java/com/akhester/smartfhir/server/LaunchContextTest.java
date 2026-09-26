package com.akhester.smartfhir.server;

import com.akhester.smartfhir.server.launch.LaunchContext;
import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for LaunchContext entity.
 */
class LaunchContextTest {

    @Test
    void newLaunchContext_isNotUsed() {
        LaunchContext ctx = new LaunchContext(
                "test-token", "Patient-123", null,
                true, "akhester-smart-client", "dr.smith");

        assertThat(ctx.isUsed()).isFalse();
    }

    @Test
    void newLaunchContext_expiresInFiveMinutes() {
        Instant before = Instant.now();
        LaunchContext ctx = new LaunchContext(
                "test-token", "Patient-123", null,
                true, "akhester-smart-client", "dr.smith");
        Instant after = Instant.now();

        assertThat(ctx.getExpiresAt())
                .isAfterOrEqualTo(before.plusSeconds(299))
                .isBeforeOrEqualTo(after.plusSeconds(301));
    }

    @Test
    void newLaunchContext_isNotExpired() {
        LaunchContext ctx = new LaunchContext(
                "test-token", "Patient-123", null,
                true, "akhester-smart-client", "dr.smith");

        assertThat(ctx.isExpired()).isFalse();
    }

    @Test
    void launchContext_storesPatientAndEncounterFhirIds() {
        LaunchContext ctx = new LaunchContext(
                "test-token", "Patient-ABC", "Encounter-XYZ",
                true, "akhester-smart-client", "dr.smith");

        assertThat(ctx.getPatientFhirId()).isEqualTo("Patient-ABC");
        assertThat(ctx.getEncounterFhirId()).isEqualTo("Encounter-XYZ");
    }

    @Test
    void launchContext_nullEncounterIsAllowed() {
        LaunchContext ctx = new LaunchContext(
                "test-token", "Patient-ABC", null,
                true, "akhester-smart-client", "dr.smith");

        assertThat(ctx.getEncounterFhirId()).isNull();
    }

    @Test
    void launchContext_needPatientBannerDefaultsTrue() {
        LaunchContext ctx = new LaunchContext(
                "test-token", "Patient-ABC", null,
                true, "akhester-smart-client", "dr.smith");

        assertThat(ctx.isNeedPatientBanner()).isTrue();
    }

    @Test
    void markUsed_setsUsedFlag() {
        LaunchContext ctx = new LaunchContext(
                "test-token", "Patient-ABC", null,
                true, "akhester-smart-client", "dr.smith");

        ctx.markUsed();

        assertThat(ctx.isUsed()).isTrue();
    }

    @Test
    void toString_containsKeyInfo() {
        LaunchContext ctx = new LaunchContext(
                "test-token", "Patient-ABC", "Encounter-XYZ",
                true, "akhester-smart-client", "dr.smith");

        String str = ctx.toString();

        assertThat(str).contains("Patient-ABC");
        assertThat(str).contains("Encounter-XYZ");
        assertThat(str).contains("akhester-smart-client");
    }
}
