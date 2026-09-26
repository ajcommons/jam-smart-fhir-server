package com.akhester.smartfhir.server;

import com.akhester.smartfhir.server.discovery.SmartDiscoveryController;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for SmartDiscoveryController.
 * Verifies that the /.well-known/smart-configuration document
 * contains all fields required by SMART App Launch v2.2.
 */
class SmartDiscoveryControllerTest {

    private static final String ISSUER = "http://localhost:9000";

    private SmartDiscoveryController controller() {
        SmartServerProperties props = new SmartServerProperties(
                "http://localhost:8080/fhir",
                ISSUER,
                3600L,
                86400L,
                true,
                "http://localhost:8081/launch",
                "akhester-smart-client"
        );
        return new SmartDiscoveryController(props);
    }

    @Test
    void discoveryDocument_containsRequiredOAuth2Endpoints() {
        Map<String, Object> doc = controller().smartConfiguration();

        assertThat(doc).containsKey("authorization_endpoint");
        assertThat(doc).containsKey("token_endpoint");
        assertThat(doc.get("authorization_endpoint"))
                .isEqualTo(ISSUER + "/oauth2/authorize");
        assertThat(doc.get("token_endpoint"))
                .isEqualTo(ISSUER + "/oauth2/token");
    }

    @Test
    void discoveryDocument_containsIntrospectionEndpoint() {
        Map<String, Object> doc = controller().smartConfiguration();

        assertThat(doc).containsKey("introspection_endpoint");
        assertThat(doc.get("introspection_endpoint"))
                .isEqualTo(ISSUER + "/oauth2/introspect");
    }

    @Test
    void discoveryDocument_containsRevocationEndpoint() {
        Map<String, Object> doc = controller().smartConfiguration();

        assertThat(doc).containsKey("revocation_endpoint");
        assertThat(doc.get("revocation_endpoint"))
                .isEqualTo(ISSUER + "/oauth2/revoke");
    }

    @Test
    void discoveryDocument_containsJwksUri() {
        Map<String, Object> doc = controller().smartConfiguration();

        assertThat(doc).containsKey("jwks_uri");
        assertThat(doc.get("jwks_uri")).isEqualTo(ISSUER + "/oauth2/jwks");
    }

    @Test
    void discoveryDocument_containsSmartCapabilities() {
        Map<String, Object> doc = controller().smartConfiguration();

        assertThat(doc).containsKey("capabilities");
        @SuppressWarnings("unchecked")
        var caps = (java.util.List<String>) doc.get("capabilities");
        assertThat(caps).contains(
                "launch-ehr",
                "launch-standalone",
                "client-public",
                "sso-openid-connect"
        );
    }

    @Test
    void discoveryDocument_containsPkceS256() {
        Map<String, Object> doc = controller().smartConfiguration();

        assertThat(doc).containsKey("code_challenge_methods_supported");
        @SuppressWarnings("unchecked")
        var methods = (java.util.List<String>) doc.get("code_challenge_methods_supported");
        assertThat(methods).contains("S256");
    }

    @Test
    void discoveryDocument_containsIssuer() {
        Map<String, Object> doc = controller().smartConfiguration();

        assertThat(doc).containsKey("issuer");
        assertThat(doc.get("issuer")).isEqualTo(ISSUER);
    }

    @Test
    void discoveryDocument_containsScopes() {
        Map<String, Object> doc = controller().smartConfiguration();

        assertThat(doc).containsKey("scopes_supported");
        @SuppressWarnings("unchecked")
        var scopes = (java.util.List<String>) doc.get("scopes_supported");
        assertThat(scopes).contains("launch", "openid", "offline_access",
                "patient/Patient.rs", "fhirUser");
    }
}
