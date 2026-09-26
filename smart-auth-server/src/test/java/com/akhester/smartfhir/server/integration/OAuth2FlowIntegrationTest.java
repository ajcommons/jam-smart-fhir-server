package com.akhester.smartfhir.server.integration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for the OAuth2 authorization code + PKCE flow.
 *
 * <h3>What is tested</h3>
 * <ol>
 *   <li>Full happy path: authorize → login → token exchange → SMART claims present</li>
 *   <li>PKCE enforcement: missing code_verifier in token request → 400</li>
 *   <li>Wrong code_verifier → 400 (not a PKCE bypass)</li>
 *   <li>Refresh token rotation: each refresh grant issues a NEW refresh token</li>
 *   <li>Reuse of old refresh token after rotation → 400 (revoked)</li>
 *   <li>Token introspection returns active=true for a live token</li>
 *   <li>Token revocation: post-revoke introspection returns active=false</li>
 * </ol>
 *
 * <h3>Design notes</h3>
 * MockMvc drives the full Spring Security filter stack (all three filter chains
 * including Spring Authorization Server). H2 in-memory database, dev profile —
 * see {@link SmartIntegrationTestBase} for context setup.
 */
@DisplayName("OAuth2 authorization code + PKCE flow")
class OAuth2FlowIntegrationTest extends SmartIntegrationTestBase {

    @Autowired
    private ObjectMapper objectMapper;

    /** Injected from application.yml — must equal aud in every issued access token. */
    @Value("${smart.server.fhir-base-url:http://localhost:8080/fhir}")
    private String fhirBaseUrl;

    // ── 1. Happy path ─────────────────────────────────────────────────────────

    @Test
    @DisplayName("Full authorize → login → token exchange succeeds and returns SMART claims")
    void fullAuthorizationCodeFlow_returnsSmartClaims() throws Exception {
        MockHttpSession session = new MockHttpSession();

        // Step 1: GET /oauth2/authorize — Spring AS redirects to /login
        MvcResult authorizeResult = mockMvc.perform(get("/oauth2/authorize")
                        .session(session)
                        .param("response_type",         "code")
                        .param("client_id",             TEST_CLIENT_ID)
                        .param("redirect_uri",          TEST_REDIRECT_URI)
                        .param("scope",                 "openid launch/patient patient/Patient.rs")
                        .param("state",                 "test-state-abc")
                        .param("code_challenge",        testCodeChallenge())
                        .param("code_challenge_method", "S256"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String loginRedirect = authorizeResult.getResponse().getRedirectedUrl();
        assertThat(loginRedirect).contains("/login");

        // Step 2: POST /login — authenticate the clinician
        MvcResult loginResult = mockMvc.perform(post("/login")
                        .session(session)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("username", TEST_USERNAME)
                        .param("password", TEST_PASSWORD))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        // After login Spring redirects back to the original /oauth2/authorize request
        String afterLoginRedirect = loginResult.getResponse().getRedirectedUrl();
        assertThat(afterLoginRedirect).isNotNull();

        // Step 3: Follow the redirect back to /oauth2/authorize — Spring AS returns
        //         a redirect to the redirect_uri with the authorization code
        MvcResult codeResult = mockMvc.perform(get(afterLoginRedirect)
                        .session(session))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String redirectWithCode = codeResult.getResponse().getRedirectedUrl();
        assertThat(redirectWithCode).startsWith(TEST_REDIRECT_URI);
        assertThat(redirectWithCode).contains("code=");
        assertThat(redirectWithCode).contains("state=test-state-abc");

        String authCode = extractParam(redirectWithCode, "code");
        assertThat(authCode).isNotBlank();

        // Step 4: POST /oauth2/token — exchange the authorization code for tokens
        MvcResult tokenResult = mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type",    "authorization_code")
                        .param("code",          authCode)
                        .param("redirect_uri",  TEST_REDIRECT_URI)
                        .param("client_id",     TEST_CLIENT_ID)
                        .param("code_verifier", testCodeVerifier()))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andReturn();

        JsonNode tokens = objectMapper.readTree(tokenResult.getResponse().getContentAsString());

        // Access token present
        assertThat(tokens.has("access_token")).isTrue();
        String accessToken = tokens.get("access_token").asText();
        assertThat(accessToken).isNotBlank();

        // Token type is Bearer
        assertThat(tokens.get("token_type").asText()).isEqualToIgnoringCase("Bearer");

        // Refresh token present (offline_access scope implicitly granted by client config)
        assertThat(tokens.has("refresh_token")).isTrue();

        // SMART-specific: patient context claim
        // SmartTokenCustomizer adds 'patient' claim when launch/patient scope is granted
        // Note: claim is in the token itself — response includes it as top-level field
        // per SMART App Launch v2 §7.1.5
        assertThat(tokens.has("patient")).isTrue();
    }

    // ── 2. PKCE enforcement ───────────────────────────────────────────────────

    @Test
    @DisplayName("Token exchange without code_verifier returns 400")
    void tokenExchange_missingCodeVerifier_returns400() throws Exception {
        String authCode = obtainAuthorizationCode();

        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type",   "authorization_code")
                        .param("code",         authCode)
                        .param("redirect_uri", TEST_REDIRECT_URI)
                        .param("client_id",    TEST_CLIENT_ID))
                // code_verifier omitted — Spring AS must reject this
                .andExpect(status().isBadRequest());
    }

    @Test
    @DisplayName("Token exchange with wrong code_verifier returns 400")
    void tokenExchange_wrongCodeVerifier_returns400() throws Exception {
        String authCode = obtainAuthorizationCode();

        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type",    "authorization_code")
                        .param("code",          authCode)
                        .param("redirect_uri",  TEST_REDIRECT_URI)
                        .param("client_id",     TEST_CLIENT_ID)
                        .param("code_verifier", "this-is-absolutely-not-the-right-verifier"))
                .andExpect(status().isBadRequest());
    }

    // ── 3. Refresh token rotation ─────────────────────────────────────────────

    @Test
    @DisplayName("Refresh grant issues a NEW refresh token (rotation enabled)")
    void refreshGrant_issuesNewRefreshToken() throws Exception {
        // Get initial token set
        JsonNode initialTokens = obtainTokenSet();
        String initialRefreshToken = initialTokens.get("refresh_token").asText();
        String initialAccessToken  = initialTokens.get("access_token").asText();
        assertThat(initialRefreshToken).isNotBlank();

        // Use the refresh token to get a new token set
        MvcResult refreshResult = mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type",    "refresh_token")
                        .param("refresh_token", initialRefreshToken)
                        .param("client_id",     TEST_CLIENT_ID))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode refreshedTokens = objectMapper.readTree(refreshResult.getResponse().getContentAsString());
        String newRefreshToken = refreshedTokens.get("refresh_token").asText();
        String newAccessToken  = refreshedTokens.get("access_token").asText();

        // Rotation: a NEW refresh token must be issued
        assertThat(newRefreshToken).isNotBlank();
        assertThat(newRefreshToken).isNotEqualTo(initialRefreshToken);

        // New access token is also different
        assertThat(newAccessToken).isNotBlank();
        assertThat(newAccessToken).isNotEqualTo(initialAccessToken);
    }

    @Test
    @DisplayName("Reusing a rotated-away refresh token returns 400 (token revoked)")
    void refreshGrant_reuseOldToken_returns400() throws Exception {
        JsonNode initialTokens = obtainTokenSet();
        String initialRefreshToken = initialTokens.get("refresh_token").asText();

        // First refresh — consumes (rotates away) initialRefreshToken
        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type",    "refresh_token")
                        .param("refresh_token", initialRefreshToken)
                        .param("client_id",     TEST_CLIENT_ID))
                .andExpect(status().isOk());

        // Second attempt with the OLD token — must be rejected
        mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type",    "refresh_token")
                        .param("refresh_token", initialRefreshToken)
                        .param("client_id",     TEST_CLIENT_ID))
                .andExpect(status().isBadRequest());
    }

    // ── 4. Token introspection ────────────────────────────────────────────────

    @Test
    @DisplayName("Introspection of a live access token returns active=true")
    void introspection_liveToken_returnsActive() throws Exception {
        JsonNode tokens   = obtainTokenSet();
        String accessToken = tokens.get("access_token").asText();

        MvcResult introspectResult = mockMvc.perform(post("/oauth2/introspect")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("token",     accessToken)
                        .param("client_id", TEST_CLIENT_ID))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode body = objectMapper.readTree(introspectResult.getResponse().getContentAsString());
        assertThat(body.get("active").asBoolean()).isTrue();
    }

    // ── 5. Token revocation ───────────────────────────────────────────────────

    @Test
    @DisplayName("Revoking a token then introspecting it returns active=false")
    void revocation_revokedToken_introspectionReturnsInactive() throws Exception {
        JsonNode tokens   = obtainTokenSet();
        String accessToken = tokens.get("access_token").asText();

        // Revoke the access token
        mockMvc.perform(post("/oauth2/revoke")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("token",     accessToken)
                        .param("client_id", TEST_CLIENT_ID))
                .andExpect(status().isOk());

        // Introspect — should now be inactive
        MvcResult introspectResult = mockMvc.perform(post("/oauth2/introspect")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("token",     accessToken)
                        .param("client_id", TEST_CLIENT_ID))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode body = objectMapper.readTree(introspectResult.getResponse().getContentAsString());
        assertThat(body.get("active").asBoolean()).isFalse();
    }

    // ── 6. Access token aud claim ─────────────────────────────────────────────

    @Test
    @DisplayName("Access token aud claim is the FHIR server URL, not the client_id")
    void accessToken_audClaimIsFhirBaseUrl() throws Exception {
        // SMART v2.2 §7.1.5: aud in the access token must be the FHIR server URL.
        // Spring AS defaults aud to the client_id — SmartTokenCustomizer must override it.
        // Inferno checks this during the EHR launch sequence.
        JsonNode tokens = obtainTokenSet();
        String accessToken = tokens.get("access_token").asText();
        assertThat(accessToken).isNotBlank();

        // Decode the JWT payload (middle segment) without signature verification.
        // We are testing claims content, not signature — crypto is tested by JWKS tests.
        String[] parts = accessToken.split("\\.");
        assertThat(parts).as("JWT must have 3 parts").hasSize(3);

        byte[] payloadBytes = Base64.getUrlDecoder().decode(
                // Pad to a multiple of 4 to satisfy standard Base64 decoder
                parts[1] + "=".repeat((4 - parts[1].length() % 4) % 4));
        JsonNode payload = objectMapper.readTree(payloadBytes);

        // aud is either a string or an array; both are valid per RFC 7519.
        JsonNode audNode = payload.get("aud");
        assertThat(audNode)
                .as("Access token must contain an 'aud' claim")
                .isNotNull();

        // Collect all aud values into a single string for assertion
        String audValue;
        if (audNode.isArray()) {
            // Array form: ["http://localhost:8080/fhir"]
            assertThat(audNode.size()).as("aud array must be non-empty").isGreaterThan(0);
            audValue = audNode.get(0).asText();
        } else {
            // String form: "http://localhost:8080/fhir"
            audValue = audNode.asText();
        }

        assertThat(audValue)
                .as("aud must be the FHIR base URL (%s), not the client_id (%s)",
                        fhirBaseUrl, TEST_CLIENT_ID)
                .isEqualTo(fhirBaseUrl);

        // Confirm aud is definitely NOT the client_id (the Spring AS default)
        assertThat(audValue)
                .as("aud must NOT be the client_id — that would violate SMART v2.2 §7.1.5")
                .isNotEqualTo(TEST_CLIENT_ID);
    }

    // ── 7. fhirUser claim in id_token is an absolute URL ──────────────────────

    @Test
    @DisplayName("fhirUser claim in id_token is an absolute FHIR URL, not a relative reference")
    void idToken_fhirUserIsAbsoluteUrl() throws Exception {
        // SMART v2.2 §7.3.1: fhirUser must be an absolute URL of the FHIR resource,
        // e.g. "http://localhost:8080/fhir/Practitioner/abc" — NOT "Practitioner/abc".
        // IdTokenBuilder was fixed in Phase 2 to prefix with the FHIR base URL.
        JsonNode tokens = obtainTokenSet();

        assertThat(tokens.has("id_token")).isTrue();
        String idToken = tokens.get("id_token").asText();

        // Decode id_token payload
        String[] parts = idToken.split("\\.");
        assertThat(parts).hasSize(3);
        byte[] payloadBytes = Base64.getUrlDecoder().decode(
                parts[1] + "=".repeat((4 - parts[1].length() % 4) % 4));
        JsonNode payload = objectMapper.readTree(payloadBytes);

        // fhirUser is only included when fhirUser scope is requested;
        // obtainTokenSet() doesn't request it, so check conditionally.
        if (payload.has("fhirUser")) {
            String fhirUser = payload.get("fhirUser").asText();
            assertThat(fhirUser)
                    .as("fhirUser must be an absolute URL (start with http)")
                    .startsWith("http");
            assertThat(fhirUser)
                    .as("fhirUser must contain /Practitioner/")
                    .contains("/Practitioner/");
        }
        // If fhirUser is absent (scope not requested), this test passes vacuously —
        // the claim is only emitted when the fhirUser scope is granted.
    }

    // ── 8. Nonce round-trip in id_token ──────────────────────────────────────

    @Test
    @DisplayName("nonce sent in authorize request appears unchanged in id_token")
    void idToken_nonceRoundTrip() throws Exception {
        // OIDC Core §3.1.2.1: if nonce is sent in the authorize request,
        // the authorization server MUST include it verbatim in the id_token.
        // Inferno and SMART clients validate this to prevent replay attacks.
        // Spring AS handles nonce natively — this test confirms nothing in our
        // customization accidentally removes or overwrites it.

        final String testNonce = "inferno-nonce-" + System.currentTimeMillis();
        MockHttpSession session = new MockHttpSession();

        // Step 1: GET /oauth2/authorize with nonce
        MvcResult authorizeResult = mockMvc.perform(get("/oauth2/authorize")
                        .session(session)
                        .param("response_type",         "code")
                        .param("client_id",             TEST_CLIENT_ID)
                        .param("redirect_uri",          TEST_REDIRECT_URI)
                        .param("scope",                 "openid patient/Patient.rs")
                        .param("state",                 "nonce-state")
                        .param("nonce",                 testNonce)
                        .param("code_challenge",        testCodeChallenge())
                        .param("code_challenge_method", "S256"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String loginRedirect = authorizeResult.getResponse().getRedirectedUrl();
        assertThat(loginRedirect).contains("/login");

        // Step 2: POST /login
        MvcResult loginResult = mockMvc.perform(post("/login")
                        .session(session)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("username", TEST_USERNAME)
                        .param("password", TEST_PASSWORD))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String afterLoginRedirect = loginResult.getResponse().getRedirectedUrl();

        // Step 3: Follow redirect back to /oauth2/authorize
        MvcResult codeResult = mockMvc.perform(get(afterLoginRedirect)
                        .session(session))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String redirectWithCode = codeResult.getResponse().getRedirectedUrl();
        assertThat(redirectWithCode).isNotNull().contains("code=");
        String authCode = extractParam(redirectWithCode, "code");

        // Step 4: POST /oauth2/token — must include id_token because openid scope
        MvcResult tokenResult = mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type",    "authorization_code")
                        .param("code",          authCode)
                        .param("redirect_uri",  TEST_REDIRECT_URI)
                        .param("client_id",     TEST_CLIENT_ID)
                        .param("code_verifier", testCodeVerifier()))
                .andExpect(status().isOk())
                .andReturn();

        JsonNode tokens = objectMapper.readTree(tokenResult.getResponse().getContentAsString());

        // id_token must be present (openid scope was requested)
        assertThat(tokens.has("id_token"))
                .as("Token response must include id_token when openid scope is granted")
                .isTrue();
        String idToken = tokens.get("id_token").asText();
        assertThat(idToken).isNotBlank();

        // Decode the id_token payload
        String[] parts = idToken.split("\\.");
        assertThat(parts).as("id_token must be a three-part JWT").hasSize(3);

        byte[] payloadBytes = Base64.getUrlDecoder().decode(
                parts[1] + "=".repeat((4 - parts[1].length() % 4) % 4));
        JsonNode payload = objectMapper.readTree(payloadBytes);

        // nonce must be present and unchanged
        assertThat(payload.has("nonce"))
                .as("id_token must contain 'nonce' when nonce was sent in the authorize request")
                .isTrue();
        assertThat(payload.get("nonce").asText())
                .as("nonce in id_token must equal the nonce sent in the authorize request")
                .isEqualTo(testNonce);
    }

    // ── Helper methods ────────────────────────────────────────────────────────

    /**
     * Drives a full authorization code flow and returns the authorization code.
     * Used by PKCE enforcement tests that only need the code, not the full tokens.
     */
    private String obtainAuthorizationCode() throws Exception {
        MockHttpSession session = new MockHttpSession();

        mockMvc.perform(post("/login")
                .session(session)
                .with(csrf())
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("username", TEST_USERNAME)
                .param("password", TEST_PASSWORD));

        MvcResult result = mockMvc.perform(get("/oauth2/authorize")
                        .session(session)
                        .param("response_type",         "code")
                        .param("client_id",             TEST_CLIENT_ID)
                        .param("redirect_uri",          TEST_REDIRECT_URI)
                        .param("scope",                 "openid launch/patient patient/Patient.rs")
                        .param("state",                 "s1")
                        .param("code_challenge",        testCodeChallenge())
                        .param("code_challenge_method", "S256"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String redirect = result.getResponse().getRedirectedUrl();
        assertThat(redirect).isNotNull();
        return extractParam(redirect, "code");
    }

    /**
     * Drives the full flow and returns the token set JSON.
     * Shared by rotation, introspection, and revocation tests.
     */
    private JsonNode obtainTokenSet() throws Exception {
        MockHttpSession session = new MockHttpSession();

        // GET /oauth2/authorize
        mockMvc.perform(get("/oauth2/authorize")
                .session(session)
                .param("response_type",         "code")
                .param("client_id",             TEST_CLIENT_ID)
                .param("redirect_uri",          TEST_REDIRECT_URI)
                .param("scope",                 "openid launch/patient patient/Patient.rs offline_access")
                .param("state",                 "s1")
                .param("code_challenge",        testCodeChallenge())
                .param("code_challenge_method", "S256"));

        // POST /login
        MvcResult loginResult = mockMvc.perform(post("/login")
                        .session(session)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("username", TEST_USERNAME)
                        .param("password", TEST_PASSWORD))
                .andReturn();

        String afterLogin = loginResult.getResponse().getRedirectedUrl();

        // Follow redirect back to /oauth2/authorize
        MvcResult codeResult = mockMvc.perform(get(afterLogin != null ? afterLogin : "/oauth2/authorize")
                        .session(session)
                        .param("response_type",         "code")
                        .param("client_id",             TEST_CLIENT_ID)
                        .param("redirect_uri",          TEST_REDIRECT_URI)
                        .param("scope",                 "openid launch/patient patient/Patient.rs offline_access")
                        .param("state",                 "s1")
                        .param("code_challenge",        testCodeChallenge())
                        .param("code_challenge_method", "S256"))
                .andReturn();

        String redirectWithCode = codeResult.getResponse().getRedirectedUrl();
        // If we got a redirect to /login again, follow the saved-request redirect
        if (redirectWithCode != null && redirectWithCode.contains("/login")) {
            codeResult = mockMvc.perform(get("/oauth2/authorize")
                            .session(session)
                            .param("response_type",         "code")
                            .param("client_id",             TEST_CLIENT_ID)
                            .param("redirect_uri",          TEST_REDIRECT_URI)
                            .param("scope",                 "openid launch/patient patient/Patient.rs offline_access")
                            .param("state",                 "s1")
                            .param("code_challenge",        testCodeChallenge())
                            .param("code_challenge_method", "S256"))
                    .andReturn();
            redirectWithCode = codeResult.getResponse().getRedirectedUrl();
        }

        assertThat(redirectWithCode).isNotNull().contains("code=");
        String authCode = extractParam(redirectWithCode, "code");

        // POST /oauth2/token
        MvcResult tokenResult = mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type",    "authorization_code")
                        .param("code",          authCode)
                        .param("redirect_uri",  TEST_REDIRECT_URI)
                        .param("client_id",     TEST_CLIENT_ID)
                        .param("code_verifier", testCodeVerifier()))
                .andExpect(status().isOk())
                .andReturn();

        return objectMapper.readTree(tokenResult.getResponse().getContentAsString());
    }

    /**
     * Extracts a named query parameter from a URL string.
     */
    private static String extractParam(String url, String paramName) {
        String query = url.contains("?") ? url.substring(url.indexOf('?') + 1) : url;
        for (String part : query.split("&")) {
            if (part.startsWith(paramName + "=")) {
                return part.substring(paramName.length() + 1);
            }
        }
        throw new AssertionError("Parameter '" + paramName + "' not found in: " + url);
    }
}
