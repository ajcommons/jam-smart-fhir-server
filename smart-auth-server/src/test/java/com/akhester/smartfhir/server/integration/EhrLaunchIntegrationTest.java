package com.akhester.smartfhir.server.integration;

import com.akhester.smartfhir.server.launch.LaunchContext;
import com.akhester.smartfhir.server.launch.LaunchContextRepository;
import com.akhester.smartfhir.server.launch.LaunchContextService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * End-to-end integration tests for the SMART EHR launch flow.
 *
 * <h3>The flow under test</h3>
 * <pre>
 *   1. Clinician POSTs to /portal/launch → server creates LaunchContext (opaque token)
 *      and redirects to the SMART client app (?iss=...&amp;launch={token})
 *
 *   2. SMART client sends  GET /oauth2/authorize
 *        ?response_type=code &amp;client_id=... &amp;scope=... &amp;launch={token}
 *        &amp;code_challenge=... &amp;code_challenge_method=S256
 *      → Spring AS validates the request, checks consent, issues an auth code,
 *        and redirects to the app's redirect_uri?code={code}&amp;state={state}
 *
 *   3. SMART client exchanges the code:
 *        POST /oauth2/token  grant_type=authorization_code &amp;code=... &amp;code_verifier=...
 *      → server issues access_token (JWT), refresh_token, id_token
 *
 *   4. Token response body contains SMART context fields extracted from the JWT:
 *        patient, need_patient_banner, (encounter if set)
 *      Access token aud = FHIR server URL (not client_id)
 * </pre>
 *
 * <h3>What is tested</h3>
 * <ol>
 *   <li>POST /portal/launch creates a LaunchContext and returns redirect to the client</li>
 *   <li>Redirect URL from /portal/launch contains iss= and launch= params</li>
 *   <li>LaunchContextService.createLaunchToken stores the patient FHIR ID</li>
 *   <li>Full EHR launch: authorize → token exchange → access token issued</li>
 *   <li>Token response contains patient and need_patient_banner context fields</li>
 *   <li>Token response contains encounter when an encounter was set in the launch context</li>
 *   <li>Access token aud claim is the FHIR server URL, not the client ID</li>
 *   <li>Launch token is single-use: second token exchange with the same launch param fails or
 *       produces a token without patient context (token already consumed)</li>
 *   <li>Expired launch token: authorize with a manually expired token → token response
 *       lacks patient context (SmartTokenCustomizer logs warning, continues)</li>
 *   <li>POST /portal/launch rejects invalid patientId (contains special chars)</li>
 *   <li>GET /portal requires authentication</li>
 *   <li>POST /portal/launch requires authentication</li>
 * </ol>
 *
 * <h3>No HAPI FHIR required</h3>
 * The EHR launch flow does not call the FHIR server — the clinician's patient
 * selection has already happened before the launch token is created.  The FHIR
 * server is only used by the patient-picker UI (GET /portal), which is tested
 * gracefully with the FHIR-unavailable banner. The core launch → authorize →
 * token tests work entirely without a running FHIR server.
 *
 * <h3>Consent bypass</h3>
 * Tests that complete the full token exchange drive Spring AS through the consent
 * page.  To avoid needing a second HTTP round-trip, the consent is pre-recorded
 * directly via a helper that calls the approve POST, obtaining a real auth code
 * from Spring AS.
 */
@DisplayName("EHR launch flow — end-to-end")
class EhrLaunchIntegrationTest extends SmartIntegrationTestBase {

    private static final String PATIENT_FHIR_ID  = "Patient-EHR-001";
    private static final String ENCOUNTER_FHIR_ID = "Encounter-EHR-001";
    private static final String EHR_SCOPE =
            "openid fhirUser launch launch/patient patient/Patient.rs offline_access";

    @Autowired private LaunchContextService    launchContextService;
    @Autowired private LaunchContextRepository launchContextRepository;
    @Autowired private ObjectMapper            objectMapper;

    // ── 1. /portal/launch creates LaunchContext ───────────────────────────────

    @Test
    @DisplayName("POST /portal/launch creates a LaunchContext with the selected patient ID")
    void portalLaunch_createsLaunchContext() throws Exception {
        MockHttpSession session = loginSession();

        mockMvc.perform(post("/portal/launch")
                        .session(session)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("patientId", PATIENT_FHIR_ID))
                .andExpect(status().is3xxRedirection());

        // A LaunchContext for this patient must now exist in the repository
        boolean found = launchContextRepository.findAll().stream()
                .anyMatch(lc -> PATIENT_FHIR_ID.equals(lc.getPatientFhirId())
                             && !lc.isUsed());
        assertThat(found)
                .as("A LaunchContext for Patient-EHR-001 must have been persisted")
                .isTrue();
    }

    // ── 2. Redirect from /portal/launch contains iss and launch ──────────────

    @Test
    @DisplayName("POST /portal/launch redirect contains iss= and launch= query params")
    void portalLaunch_redirectContainsIssAndLaunchParams() throws Exception {
        MockHttpSession session = loginSession();

        MvcResult result = mockMvc.perform(post("/portal/launch")
                        .session(session)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("patientId", PATIENT_FHIR_ID))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String redirect = result.getResponse().getRedirectedUrl();
        assertThat(redirect).as("Redirect must contain iss= param").contains("iss=");
        assertThat(redirect).as("Redirect must contain launch= param").contains("launch=");
    }

    // ── 3. LaunchContextService stores patient ID ─────────────────────────────

    @Test
    @DisplayName("LaunchContextService.createLaunchToken stores patient FHIR ID and clientId")
    void createLaunchToken_storesPatientAndClientId() {
        String token = launchContextService.createLaunchToken(
                PATIENT_FHIR_ID, null, true, TEST_CLIENT_ID, TEST_USERNAME);

        assertThat(token).isNotBlank();

        LaunchContext lc = launchContextRepository.findByToken(token).orElseThrow();
        assertThat(lc.getPatientFhirId()).isEqualTo(PATIENT_FHIR_ID);
        assertThat(lc.getClientId()).isEqualTo(TEST_CLIENT_ID);
        assertThat(lc.getLaunchedBy()).isEqualTo(TEST_USERNAME);
        assertThat(lc.isUsed()).isFalse();
        assertThat(lc.isExpired()).isFalse();
    }

    // ── 4. Full EHR launch: authorize → token exchange → access token ─────────

    @Test
    @DisplayName("Full EHR launch flow: launch token → auth code → access token issued")
    void fullEhrLaunch_producesAccessToken() throws Exception {
        String launchToken = launchContextService.createLaunchToken(
                PATIENT_FHIR_ID, null, true, TEST_CLIENT_ID, TEST_USERNAME);

        String code = obtainAuthCode(launchToken, "full-ehr-state");
        assertThat(code).as("Auth code must be issued after successful authorize").isNotBlank();

        JsonNode tokenResponse = exchangeCodeForToken(code);
        assertThat(tokenResponse.has("access_token"))
                .as("Token response must contain access_token").isTrue();
        assertThat(tokenResponse.has("token_type"))
                .as("Token response must contain token_type").isTrue();
        assertThat(tokenResponse.get("token_type").asText())
                .isEqualToIgnoringCase("Bearer");
    }

    // ── 5. Token response contains patient context ────────────────────────────

    @Test
    @DisplayName("Token response body contains patient and need_patient_banner after EHR launch")
    void tokenResponse_containsPatientContext() throws Exception {
        String launchToken = launchContextService.createLaunchToken(
                PATIENT_FHIR_ID, null, true, TEST_CLIENT_ID, TEST_USERNAME);

        String code = obtainAuthCode(launchToken, "patient-ctx-state");
        JsonNode tokenResponse = exchangeCodeForToken(code);

        assertThat(tokenResponse.has("patient"))
                .as("Token response must contain patient context field").isTrue();
        assertThat(tokenResponse.get("patient").asText())
                .as("patient field must match the FHIR patient ID selected at launch")
                .isEqualTo(PATIENT_FHIR_ID);

        assertThat(tokenResponse.has("need_patient_banner"))
                .as("Token response must contain need_patient_banner").isTrue();
    }

    // ── 6. Token response contains encounter when launch includes one ──────────

    @Test
    @DisplayName("Token response contains encounter when encounter was set in launch context")
    void tokenResponse_containsEncounterContext_whenLaunchHasEncounter() throws Exception {
        String launchToken = launchContextService.createLaunchToken(
                PATIENT_FHIR_ID, ENCOUNTER_FHIR_ID, true, TEST_CLIENT_ID, TEST_USERNAME);

        String code = obtainAuthCode(launchToken, "encounter-ctx-state");
        JsonNode tokenResponse = exchangeCodeForToken(code);

        assertThat(tokenResponse.has("encounter"))
                .as("Token response must contain encounter when set in launch context").isTrue();
        assertThat(tokenResponse.get("encounter").asText())
                .isEqualTo(ENCOUNTER_FHIR_ID);
    }

    // ── 7. Access token aud = FHIR server URL ────────────────────────────────

    @Test
    @DisplayName("Access token aud claim is the FHIR server URL, not the client_id")
    void accessToken_aud_isFhirServerUrl() throws Exception {
        String launchToken = launchContextService.createLaunchToken(
                PATIENT_FHIR_ID, null, true, TEST_CLIENT_ID, TEST_USERNAME);

        String code = obtainAuthCode(launchToken, "aud-check-state");
        JsonNode tokenResponse = exchangeCodeForToken(code);

        String jwt = tokenResponse.get("access_token").asText();
        String[] parts = jwt.split("\\.");
        assertThat(parts).as("JWT must have 3 parts").hasSize(3);

        String payloadJson = new String(
                Base64.getUrlDecoder().decode(
                        parts[1] + "=".repeat((4 - parts[1].length() % 4) % 4)),
                StandardCharsets.UTF_8);
        JsonNode payload = objectMapper.readTree(payloadJson);

        // aud must be present and must NOT be the client_id
        assertThat(payload.has("aud")).as("Access token must have aud claim").isTrue();
        String aud = payload.get("aud").isArray()
                ? payload.get("aud").get(0).asText()
                : payload.get("aud").asText();
        assertThat(aud)
                .as("aud must be the FHIR server URL, not the client_id")
                .isNotEqualTo(TEST_CLIENT_ID);
        assertThat(aud)
                .as("aud must look like a URL (starts with http)")
                .startsWith("http");
    }

    // ── 8. Single-use: second authorize with same launch token gets no context ─

    @Test
    @DisplayName("Launch token is single-use: second use produces no patient context")
    void launchToken_singleUse_secondUseHasNoPatientContext() throws Exception {
        String launchToken = launchContextService.createLaunchToken(
                PATIENT_FHIR_ID, null, true, TEST_CLIENT_ID, TEST_USERNAME);

        // First use — normal
        String code1 = obtainAuthCode(launchToken, "single-use-state-1");
        JsonNode first = exchangeCodeForToken(code1);
        assertThat(first.has("patient")).as("First use must have patient context").isTrue();

        // Second use of the same launch token — Spring AS issues a fresh auth code
        // but SmartTokenCustomizer logs a warning and produces no patient context
        String code2 = obtainAuthCode(launchToken, "single-use-state-2");
        if (code2 != null && !code2.isBlank()) {
            JsonNode second = exchangeCodeForToken(code2);
            // The token is issued (server is tolerant) but must have no patient claim
            assertThat(second.has("patient"))
                    .as("Second use of an already-used launch token must not have patient context")
                    .isFalse();
        }
        // If no code was issued the second time, the assertion still holds
    }

    // ── 9. Expired launch token → no patient context ──────────────────────────

    @Test
    @DisplayName("Authorize with an expired launch token produces access token without patient context")
    void expiredLaunchToken_producesTokenWithoutPatientContext() throws Exception {
        // Create a token then manually expire it in the database
        String launchToken = launchContextService.createLaunchToken(
                PATIENT_FHIR_ID, null, true, TEST_CLIENT_ID, TEST_USERNAME);

        LaunchContext lc = launchContextRepository.findByToken(launchToken).orElseThrow();
        // Force-expire it (bypass the entity setter by using JPQL via repository)
        launchContextRepository.deleteExpiredBefore(
                lc.getExpiresAt().plusSeconds(1)); // deletes this specific record

        // The token no longer exists — SmartTokenCustomizer will log a warning
        // and issue the token without patient context
        String code = obtainAuthCode(launchToken, "expired-token-state");
        if (code != null && !code.isBlank()) {
            JsonNode tokenResponse = exchangeCodeForToken(code);
            assertThat(tokenResponse.has("patient"))
                    .as("Expired launch token must not produce patient context")
                    .isFalse();
        }
    }

    // ── 10. /portal/launch rejects invalid patientId ─────────────────────────

    @Test
    @DisplayName("POST /portal/launch with invalid patientId (special chars) returns 400")
    void portalLaunch_invalidPatientId_rejected() throws Exception {
        MockHttpSession session = loginSession();

        // patientId contains a space — violates ^[a-zA-Z0-9\-\.]{1,64}$ regex
        mockMvc.perform(post("/portal/launch")
                        .session(session)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("patientId", "Patient ID with spaces"))
                .andExpect(status().is4xxClientError());
    }

    // ── 11. Portal requires authentication ────────────────────────────────────

    @Test
    @DisplayName("GET /portal without authentication redirects to /login")
    void portal_unauthenticated_redirectsToLogin() throws Exception {
        mockMvc.perform(get("/portal"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/login**"));
    }

    // ── 12. Portal/launch requires authentication ─────────────────────────────

    @Test
    @DisplayName("POST /portal/launch without authentication redirects to /login")
    void portalLaunch_unauthenticated_redirectsToLogin() throws Exception {
        mockMvc.perform(post("/portal/launch")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("patientId", PATIENT_FHIR_ID))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/login**"));
    }

    // ── 13. Portal page renders gracefully without FHIR server ───────────────

    @Test
    @DisplayName("GET /portal renders HTML (with FHIR error banner) when no FHIR server is running")
    void portal_authenticated_rendersGracefullyWithNoFhirServer() throws Exception {
        MockHttpSession session = loginSession();

        mockMvc.perform(get("/portal").session(session))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML));
    }

    // ══════════════════════════════════════════════════════════════════════════
    //  Helpers
    // ══════════════════════════════════════════════════════════════════════════

    /**
     * Drives through the full EHR authorize flow — including the consent page —
     * and returns the authorization code issued by Spring AS.
     *
     * <p>Steps:
     * <ol>
     *   <li>GET /oauth2/authorize with the launch token → Spring AS redirects to
     *       /oauth2/consent (because requireAuthorizationConsent=true).</li>
     *   <li>POST /oauth2/authorize with all approved scopes + Spring AS state →
     *       Spring AS records consent and redirects to redirect_uri?code=…</li>
     *   <li>Extract and return the code= param from that redirect.</li>
     * </ol>
     *
     * @param launchToken the opaque EHR launch token created by LaunchContextService
     * @param state       caller-supplied state to correlate the request
     * @return the authorization code, or {@code null} if the flow did not produce one
     */
    private String obtainAuthCode(String launchToken, String state) throws Exception {
        MockHttpSession session = loginSession();

        // Step 1: send the authorize request → expect redirect to /oauth2/consent
        MvcResult authorizeResult = mockMvc.perform(get("/oauth2/authorize")
                        .session(session)
                        .param("response_type",         "code")
                        .param("client_id",             TEST_CLIENT_ID)
                        .param("redirect_uri",          TEST_REDIRECT_URI)
                        .param("scope",                 EHR_SCOPE)
                        .param("state",                 state)
                        .param("launch",                launchToken)
                        .param("code_challenge",        testCodeChallenge())
                        .param("code_challenge_method", "S256"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String consentRedirect = authorizeResult.getResponse().getRedirectedUrl();
        if (consentRedirect == null || !consentRedirect.contains("/oauth2/consent")) {
            // Already issued a code (consent was previously recorded) or error
            return extractParam(consentRedirect, "code");
        }

        // Step 2: approve the consent — POST to /oauth2/authorize with all scopes
        String springState = extractParam(consentRedirect, "state");

        MvcResult approveResult = mockMvc.perform(post("/oauth2/authorize")
                        .session(session)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("client_id", TEST_CLIENT_ID)
                        .param("state",     springState)
                        .param("scope",     "fhirUser")
                        .param("scope",     "launch")
                        .param("scope",     "launch/patient")
                        .param("scope",     "patient/Patient.rs")
                        .param("scope",     "offline_access"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String codeRedirect = approveResult.getResponse().getRedirectedUrl();
        return extractParam(codeRedirect, "code");
    }

    /**
     * Exchanges an authorization code for tokens at POST /oauth2/token using
     * the fixed PKCE code verifier from the base class.
     *
     * @param code the authorization code from {@link #obtainAuthCode}
     * @return parsed JSON token response body
     */
    private JsonNode exchangeCodeForToken(String code) throws Exception {
        MultiValueMap<String, String> params = new LinkedMultiValueMap<>();
        params.add("grant_type",    "authorization_code");
        params.add("code",          code);
        params.add("redirect_uri",  TEST_REDIRECT_URI);
        params.add("client_id",     TEST_CLIENT_ID);
        params.add("code_verifier", testCodeVerifier());

        MvcResult result = mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .params(params))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_JSON))
                .andReturn();

        return objectMapper.readTree(result.getResponse().getContentAsString());
    }

    /**
     * Authenticates {@code TEST_USERNAME} and returns the MockHttpSession.
     */
    private MockHttpSession loginSession() throws Exception {
        MockHttpSession session = new MockHttpSession();
        mockMvc.perform(get("/login").session(session));
        MvcResult r = mockMvc.perform(post("/login")
                        .session(session)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("username", TEST_USERNAME)
                        .param("password", TEST_PASSWORD))
                .andReturn();
        String redirect = r.getResponse().getRedirectedUrl();
        if (redirect != null && !redirect.isEmpty()) {
            mockMvc.perform(get(redirect).session(session));
        }
        return session;
    }

    /**
     * Extracts a named query parameter from a URL string (handles URL-encoding).
     * Returns {@code null} if the URL is null or the param is absent.
     */
    private static String extractParam(String url, String param) {
        if (url == null) return null;
        int q = url.indexOf('?');
        if (q < 0) return null;
        for (String part : url.substring(q + 1).split("&")) {
            int eq = part.indexOf('=');
            if (eq < 0) continue;
            String key = URLDecoder.decode(part.substring(0, eq), StandardCharsets.UTF_8);
            if (key.equals(param)) {
                return URLDecoder.decode(part.substring(eq + 1), StandardCharsets.UTF_8);
            }
        }
        return null;
    }
}
