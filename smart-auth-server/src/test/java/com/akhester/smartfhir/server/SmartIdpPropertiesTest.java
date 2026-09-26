package com.akhester.smartfhir.server;

import com.akhester.smartfhir.server.auth.SmartIdpProperties;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for SmartIdpProperties record and its URL-building utility.
 */
class SmartIdpPropertiesTest {

    @Test
    void buildLookupUrl_replacesIdentifierPlaceholder() {
        SmartIdpProperties props = new SmartIdpProperties(
                "email",
                "http://localhost:8080/fhir/Practitioner?identifier=http://myorg.com/fhir/emp/{identifier}"
        );

        String url = props.buildLookupUrl("jane.smith@example.com");

        // email should be URL-encoded
        assertThat(url).contains("jane.smith%40example.com");
        assertThat(url).doesNotContain("{identifier}");
    }

    @Test
    void buildLookupUrl_handlesSimpleIdentifier() {
        SmartIdpProperties props = new SmartIdpProperties(
                "employee_id",
                "http://localhost:8080/fhir/Practitioner?identifier=http://myorg.com/fhir/emp/{identifier}"
        );

        String url = props.buildLookupUrl("EMP-12345");

        assertThat(url).endsWith("EMP-12345");
        assertThat(url).doesNotContain("{identifier}");
    }

    @Test
    void properties_accessors() {
        SmartIdpProperties props = new SmartIdpProperties(
                "email",
                "http://localhost:8080/fhir/Practitioner?identifier={identifier}"
        );

        assertThat(props.userIdClaim()).isEqualTo("email");
        assertThat(props.userLookupQuery())
                .isEqualTo("http://localhost:8080/fhir/Practitioner?identifier={identifier}");
    }
}
