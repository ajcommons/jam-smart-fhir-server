package com.akhester.smartfhir.server.integration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.options;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for the SMART on FHIR discovery endpoint.
 *
 * <h3>What is tested</h3>
 * <ol>
 *   <li>Discovery document is publicly accessible (no auth required)</li>
 *   <li>All required SMART App Launch v2 fields are present</li>
 *   <li>PKCE S256 is listed under code_challenge_methods_supported</li>
 *   <li>Required grant types are listed</li>
 *   <li>Discovery endpoint is accessible via CORS (wildcard) from any origin</li>
 *   <li>JWKS endpoint is publicly accessible and returns a valid JWK Set</li>
 *   <li>CORS is open for /.well-known/smart-configuration and /oauth2/jwks</li>
 * </ol>
 *
 * <h3>SMART App Launch specification reference</h3>
 * §7.1 — SMART on FHIR server capabilities (discovery) document requirements.
 * The {@code /.well-known/smart-configuration} endpoint is the machine-readable
 * capability statement that EHR launchers use to discover endpoint URLs.
 */
@DisplayName("SMART discovery and JWKS endpoints")
class SmartDiscoveryIntegrationTest extends SmartIntegrationTestBase {

    @Autowired
    private ObjectMapper objectMapper;

    // ── 1. Discovery document accessibility ───────────────────────────────────

    @Test
    @DisplayName("/.well-known/smart-configuration is accessible without authentication")
    void discoveryEndpoint_isPubliclyAccessible() throws Exception {
        mockMvc.perform(get("/.well-known/smart-configuration"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON));
    }

    // ── 2. Required SMART fields ──────────────────────────────────────────────

    @Test
    @DisplayName("Discovery document contains all required SMART App Launch v2 fields")
    void discoveryDocument_containsRequiredFields() throws Exception {
        MvcResult result = mockMvc.perform(get("/.well-known/smart-configuration"))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode doc = objectMapper.readTree(result.getResponse().getContentAsString());

        // Required top-level fields per SMART App Launch v2 §7.1
        assertThat(doc.has("issuer"))
                .as("issuer must be present").isTrue();
        assertThat(doc.has("authorization_endpoint"))
                .as("authorization_endpoint must be present").isTrue();
        assertThat(doc.has("token_endpoint"))
                .as("token_endpoint must be present").isTrue();
        assertThat(doc.has("jwks_uri"))
                .as("jwks_uri must be present").isTrue();
        assertThat(doc.has("capabilities"))
                .as("capabilities array must be present").isTrue();

        // authorization_endpoint must be the /oauth2/authorize path
        assertThat(doc.get("authorization_endpoint").asText())
                .endsWith("/oauth2/authorize");

        // token_endpoint must be the /oauth2/token path
        assertThat(doc.get("token_endpoint").asText())
                .endsWith("/oauth2/token");
    }

    @Test
    @DisplayName("Discovery capabilities array includes launch-ehr, sso-openid-connect, and context-ehr-patient")
    void discoveryDocument_capabilitiesIncludeSmartCapabilities() throws Exception {
        MvcResult result = mockMvc.perform(get("/.well-known/smart-configuration"))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode doc = objectMapper.readTree(result.getResponse().getContentAsString());
        assertThat(doc.has("capabilities")).isTrue();

        String capabilitiesRaw = doc.get("capabilities").toString();

        // Core SMART capabilities that every SMART auth server must advertise
        assertThat(capabilitiesRaw).contains("launch-ehr");
        assertThat(capabilitiesRaw).contains("sso-openid-connect");
        assertThat(capabilitiesRaw).contains("context-ehr-patient");
    }

    // ── 3. PKCE support ───────────────────────────────────────────────────────

    @Test
    @DisplayName("code_challenge_methods_supported includes S256")
    void discoveryDocument_supportsS256PkceMethod() throws Exception {
        MvcResult result = mockMvc.perform(get("/.well-known/smart-configuration"))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode doc = objectMapper.readTree(result.getResponse().getContentAsString());

        // SMART App Launch v2 requires S256 — plain is discouraged and not implemented
        String pkce = doc.has("code_challenge_methods_supported")
                ? doc.get("code_challenge_methods_supported").toString()
                : "";
        assertThat(pkce).contains("S256");
    }

    // ── 4. Grant types ────────────────────────────────────────────────────────

    @Test
    @DisplayName("grant_types_supported includes authorization_code and refresh_token")
    void discoveryDocument_supportsRequiredGrantTypes() throws Exception {
        MvcResult result = mockMvc.perform(get("/.well-known/smart-configuration"))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode doc = objectMapper.readTree(result.getResponse().getContentAsString());

        if (doc.has("grant_types_supported")) {
            String grantTypes = doc.get("grant_types_supported").toString();
            assertThat(grantTypes).contains("authorization_code");
            assertThat(grantTypes).contains("refresh_token");
        }
        // grant_types_supported is RECOMMENDED, not REQUIRED, in SMART App Launch v2 —
        // so we skip the assertion if the field is absent rather than failing.
    }

    // ── 5. Phase 2: standalone patient context capability ─────────────────────

    @Test
    @DisplayName("capabilities includes context-standalone-patient (standalone launch support)")
    void discoveryDocument_capabilitiesIncludeStandalonePatient() throws Exception {
        MvcResult result = mockMvc.perform(get("/.well-known/smart-configuration"))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode doc = objectMapper.readTree(result.getResponse().getContentAsString());
        String capabilities = doc.get("capabilities").toString();

        assertThat(capabilities)
                .as("Standalone launch support must be advertised via context-standalone-patient")
                .contains("context-standalone-patient");
    }

    @Test
    @DisplayName("grant_types_supported is present and includes both required grant types")
    void discoveryDocument_grantTypesPresent() throws Exception {
        MvcResult result = mockMvc.perform(get("/.well-known/smart-configuration"))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode doc = objectMapper.readTree(result.getResponse().getContentAsString());

        // Now a hard assertion — we've added grant_types_supported in Phase 2
        assertThat(doc.has("grant_types_supported"))
                .as("grant_types_supported must be present in the discovery document")
                .isTrue();

        String grantTypes = doc.get("grant_types_supported").toString();
        assertThat(grantTypes).contains("authorization_code");
        assertThat(grantTypes).contains("refresh_token");
    }

    // ── 7. CORS on public endpoints ───────────────────────────────────────────

    @Test
    @DisplayName("Discovery endpoint returns CORS wildcard for browser-based SMART apps")
    void discoveryEndpoint_corsHeaderPresent() throws Exception {
        mockMvc.perform(get("/.well-known/smart-configuration")
                        .header(HttpHeaders.ORIGIN, "https://evil-unknown-app.example.com"))
                .andExpect(status().isOk())
                // Per CorsConfig: /.well-known/smart-configuration gets wildcard CORS
                .andExpect(header().string("Access-Control-Allow-Origin", "*"));
    }

    @Test
    @DisplayName("Discovery preflight (OPTIONS) succeeds")
    void discoveryEndpoint_preflight_succeeds() throws Exception {
        mockMvc.perform(options("/.well-known/smart-configuration")
                        .header(HttpHeaders.ORIGIN,                        "https://any-app.example.com")
                        .header(HttpHeaders.ACCESS_CONTROL_REQUEST_METHOD, "GET"))
                .andExpect(status().isOk());
    }

    // ── 8. JWKS endpoint ──────────────────────────────────────────────────────

    @Test
    @DisplayName("/oauth2/jwks is publicly accessible and returns a JWK Set")
    void jwksEndpoint_isPubliclyAccessible() throws Exception {
        MvcResult result = mockMvc.perform(get("/oauth2/jwks"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andReturn();

        JsonNode jwks = objectMapper.readTree(result.getResponse().getContentAsString());
        assertThat(jwks.has("keys")).isTrue();
        assertThat(jwks.get("keys").isArray()).isTrue();
        assertThat(jwks.get("keys").size()).isGreaterThanOrEqualTo(1);

        // Each key must have kty (key type) and kid (key id)
        JsonNode firstKey = jwks.get("keys").get(0);
        assertThat(firstKey.has("kty")).isTrue();
        assertThat(firstKey.has("kid")).isTrue();
    }

    @Test
    @DisplayName("/oauth2/jwks returns CORS wildcard so FHIR servers can validate tokens")
    void jwksEndpoint_corsWildcard() throws Exception {
        mockMvc.perform(get("/oauth2/jwks")
                        .header(HttpHeaders.ORIGIN, "https://fhir-server.example.com"))
                .andExpect(status().isOk())
                .andExpect(header().string("Access-Control-Allow-Origin", "*"));
    }
}
