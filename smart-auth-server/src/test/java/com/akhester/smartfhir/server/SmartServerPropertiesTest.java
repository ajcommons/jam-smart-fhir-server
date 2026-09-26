package com.akhester.smartfhir.server;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for SmartServerProperties record.
 */
class SmartServerPropertiesTest {

    @Test
    void properties_accessorsReturnCorrectValues() {
        SmartServerProperties props = new SmartServerProperties(
                "http://localhost:8080/fhir",
                "http://localhost:9000",
                3600L,
                86400L,
                true,
                "http://localhost:8081/launch",
                "akhester-smart-client"
        );

        assertThat(props.fhirBaseUrl()).isEqualTo("http://localhost:8080/fhir");
        assertThat(props.issuerUrl()).isEqualTo("http://localhost:9000");
        assertThat(props.accessTokenTtlSeconds()).isEqualTo(3600L);
        assertThat(props.refreshTokenTtlSeconds()).isEqualTo(86400L);
        assertThat(props.defaultNeedPatientBanner()).isTrue();
        assertThat(props.smartClientLaunchUrl()).isEqualTo("http://localhost:8081/launch");
        assertThat(props.defaultClientId()).isEqualTo("akhester-smart-client");
    }

    @Test
    void properties_record_equality() {
        SmartServerProperties a = new SmartServerProperties(
                "http://localhost:8080/fhir", "http://localhost:9000",
                3600L, 86400L, true,
                "http://localhost:8081/launch", "akhester-smart-client");

        SmartServerProperties b = new SmartServerProperties(
                "http://localhost:8080/fhir", "http://localhost:9000",
                3600L, 86400L, true,
                "http://localhost:8081/launch", "akhester-smart-client");

        assertThat(a).isEqualTo(b);
    }
}
