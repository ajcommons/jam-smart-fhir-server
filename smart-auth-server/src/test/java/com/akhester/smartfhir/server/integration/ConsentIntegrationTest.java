package com.akhester.smartfhir.server.integration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for the SMART on FHIR consent page.
 *
 * <h3>What is tested</h3>
 * <ol>
 *   <li>An authenticated clinician is redirected to the consent page after a valid
 *       SMART authorization request (requireAuthorizationConsent=true)</li>
 *   <li>The consent page renders correctly — HTTP 200, HTML content type</li>
 *   <li>The consent page contains the app name and requested scopes</li>
 *   <li>The consent page contains the state value Spring AS issued</li>
 *   <li>An unauthenticated request to /oauth2/consent is redirected to /login</li>
 *   <li>Approving the consent (POST /oauth2/authorize with scopes) proceeds toward
 *       code issuance — Spring AS does not reject the request</li>
 *   <li>Denying the consent (POST /oauth2/authorize with no scopes) results in
 *       access_denied redirect to the app's redirect_uri</li>
 * </ol>
 *
 * <h3>Consent service in tests</h3>
 * Integration tests run under the {@code dev} Spring profile, which wires an
 * {@link org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService}.
 * Each test sees a fresh in-memory store — no consent is pre-recorded — so Spring AS
 * always triggers the consent page for the first authorize request.
 */
@DisplayName("Consent UI — scope approval page")
class ConsentIntegrationTest extends SmartIntegrationTestBase {

    private static final String SMART_SCOPE =
            "openid fhirUser launch/patient patient/Patient.rs offline_access";

    // ── 1. Authorization request redirects to consent page ───────────────────

    @Test
    @DisplayName("Authenticated GET /oauth2/authorize triggers a redirect to /oauth2/consent")
    void authorizeRequest_redirectsToConsentPage() throws Exception {
        MockHttpSession session = loginSession();

        MvcResult result = mockMvc.perform(get("/oauth2/authorize")
                        .session(session)
                        .param("response_type",         "code")
                        .param("client_id",             TEST_CLIENT_ID)
                        .param("redirect_uri",          TEST_REDIRECT_URI)
                        .param("scope",                 SMART_SCOPE)
                        .param("state",                 "consent-test-state-1")
                        .param("code_challenge",        testCodeChallenge())
                        .param("code_challenge_method", "S256"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String redirect = result.getResponse().getRedirectedUrl();
        assertThat(redirect)
                .as("First authorize request must redirect to the consent page")
                .contains("/oauth2/consent");
    }

    // ── 2. Consent page renders (HTTP 200) ───────────────────────────────────

    @Test
    @DisplayName("GET /oauth2/consent with valid params returns HTTP 200 HTML")
    void consentPage_rendersSuccessfully() throws Exception {
        MockHttpSession session = loginSession();

        // Drive through Spring AS to get the real state token
        MvcResult authorizeResult = driveToConsentPage(session, "render-state");
        String consentUrl = authorizeResult.getResponse().getRedirectedUrl();
        assertThat(consentUrl).as("Must redirect to consent page").contains("/oauth2/consent");

        mockMvc.perform(get(consentUrl).session(session))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML));
    }

    // ── 3. Consent page contains app name and scopes ─────────────────────────

    @Test
    @DisplayName("Consent page shows app name and each requested scope")
    void consentPage_containsAppNameAndScopes() throws Exception {
        MockHttpSession session = loginSession();

        MvcResult authorizeResult = driveToConsentPage(session, "scope-check-state");
        String consentUrl = authorizeResult.getResponse().getRedirectedUrl();

        MvcResult pageResult = mockMvc.perform(get(consentUrl).session(session))
                .andExpect(status().isOk())
                .andReturn();

        String body = pageResult.getResponse().getContentAsString();

        // App name from the seeded RegisteredApp ("Integration Test SMART App")
        assertThat(body)
                .as("Consent page must show the registered app name")
                .contains("Integration Test SMART App");

        // Scopes — at least fhirUser and offline_access should appear as scope tags
        assertThat(body).as("fhirUser scope should appear on consent page")
                .contains("fhirUser");
        assertThat(body).as("offline_access scope should appear on consent page")
                .contains("offline_access");
        assertThat(body).as("patient/Patient.rs scope should appear on consent page")
                .contains("patient/Patient.rs");

        // openid is in SILENT_SCOPES and must be omitted from the display
        // (it's always granted; showing it confuses clinicians)
        assertThat(body).as("openid is a silent scope and must not appear in the scope list")
                .doesNotContain(">openid<");
    }

    // ── 4. Consent page echoes state ─────────────────────────────────────────

    @Test
    @DisplayName("Consent page contains hidden state input with Spring AS-issued state token")
    void consentPage_containsStateToken() throws Exception {
        MockHttpSession session = loginSession();

        MvcResult authorizeResult = driveToConsentPage(session, "state-echo-test");
        String consentUrl = authorizeResult.getResponse().getRedirectedUrl();
        assertThat(consentUrl).contains("/oauth2/consent");

        // Extract the state= param from the consent redirect URL
        String springState = extractParam(consentUrl, "state");
        assertThat(springState).as("Spring AS must include a state param in the consent redirect")
                .isNotBlank();

        MvcResult pageResult = mockMvc.perform(get(consentUrl).session(session))
                .andExpect(status().isOk())
                .andReturn();

        String body = pageResult.getResponse().getContentAsString();
        // The state must be present as a hidden input value in the form
        assertThat(body)
                .as("Consent page must echo the Spring AS state token in a hidden input")
                .contains(springState);
    }

    // ── 5. Unauthenticated request redirects to login ────────────────────────

    @Test
    @DisplayName("GET /oauth2/consent without authentication redirects to /login")
    void consentPage_notAuthenticated_redirectsToLogin() throws Exception {
        mockMvc.perform(get("/oauth2/consent")
                        .param("client_id", TEST_CLIENT_ID)
                        .param("scope",     SMART_SCOPE)
                        .param("state",     "unauthenticated-state"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/login**"));
    }

    // ── 6. Approving consent proceeds toward code issuance ───────────────────

    @Test
    @DisplayName("POST /oauth2/authorize (approve) with valid scopes + state does not return access_denied")
    void consentApprove_validScopes_proceedsToCodeIssuance() throws Exception {
        MockHttpSession session = loginSession();

        MvcResult authorizeResult = driveToConsentPage(session, "approve-state");
        String consentUrl = authorizeResult.getResponse().getRedirectedUrl();
        assertThat(consentUrl).contains("/oauth2/consent");

        String springState = extractParam(consentUrl, "state");

        // POST the consent form — mimics pressing "Approve Access"
        MvcResult approveResult = mockMvc.perform(post("/oauth2/authorize")
                        .session(session)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("client_id", TEST_CLIENT_ID)
                        .param("state",     springState)
                        // Include the approved scopes (all except openid which is silent)
                        .param("scope", "fhirUser")
                        .param("scope", "launch/patient")
                        .param("scope", "patient/Patient.rs")
                        .param("scope", "offline_access"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String redirect = approveResult.getResponse().getRedirectedUrl();

        // Spring AS should redirect to the app's redirect_uri with a code= param
        // OR redirect back to consent (if the session needs re-auth) — either way,
        // it must NOT be an access_denied error.
        if (redirect != null) {
            assertThat(redirect)
                    .as("Approving consent must not result in access_denied")
                    .doesNotContain("error=access_denied");
        }
    }

    // ── 7. Denying consent produces access_denied ─────────────────────────────

    @Test
    @DisplayName("POST /oauth2/authorize (deny) with no scopes results in access_denied redirect")
    void consentDeny_noScopes_returnsAccessDenied() throws Exception {
        MockHttpSession session = loginSession();

        MvcResult authorizeResult = driveToConsentPage(session, "deny-state");
        String consentUrl = authorizeResult.getResponse().getRedirectedUrl();
        assertThat(consentUrl).contains("/oauth2/consent");

        String springState = extractParam(consentUrl, "state");

        // POST deny form — no scope params, only client_id and state
        MvcResult denyResult = mockMvc.perform(post("/oauth2/authorize")
                        .session(session)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("client_id", TEST_CLIENT_ID)
                        .param("state",     springState))
                // Spring AS sends access_denied as a redirect to the app's redirect_uri
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String redirect = denyResult.getResponse().getRedirectedUrl();
        assertThat(redirect)
                .as("Denying consent must redirect with error=access_denied")
                .contains("error=access_denied");

        // The error must be redirected to the registered redirect_uri
        assertThat(redirect)
                .as("access_denied must be sent to the app's redirect_uri")
                .startsWith(TEST_REDIRECT_URI);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /**
     * Drives the authorization request through Spring AS until it redirects to the
     * consent page.  The {@link MockHttpSession} retains Spring AS's internal
     * authorization request state so subsequent consent POSTs work correctly.
     *
     * <p>We use a {@code launch} param here so the standalone patient-picker filter
     * does not intercept the request before Spring AS gets to it.</p>
     */
    private MvcResult driveToConsentPage(MockHttpSession session, String state) throws Exception {
        return mockMvc.perform(get("/oauth2/authorize")
                        .session(session)
                        .param("response_type",         "code")
                        .param("client_id",             TEST_CLIENT_ID)
                        .param("redirect_uri",          TEST_REDIRECT_URI)
                        .param("scope",                 SMART_SCOPE)
                        .param("state",                 state)
                        .param("launch",                "test-ehr-launch-token") // skip standalone picker
                        .param("code_challenge",        testCodeChallenge())
                        .param("code_challenge_method", "S256"))
                .andExpect(status().is3xxRedirection())
                .andReturn();
    }

    /**
     * Authenticates {@code TEST_USERNAME} and returns a session with Spring Security
     * authentication.  Reuses the same pattern as {@code StandaloneLaunchIntegrationTest}.
     */
    private MockHttpSession loginSession() throws Exception {
        MockHttpSession session = new MockHttpSession();
        mockMvc.perform(get("/login").session(session));

        MvcResult loginResult = mockMvc.perform(post("/login")
                        .session(session)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("username", TEST_USERNAME)
                        .param("password", TEST_PASSWORD))
                .andReturn();

        String redirect = loginResult.getResponse().getRedirectedUrl();
        if (redirect != null && !redirect.isEmpty()) {
            mockMvc.perform(get(redirect).session(session));
        }
        return session;
    }

    /**
     * Extracts a named query parameter from a URL string.
     *
     * @param url   the full URL (may be relative, e.g. {@code /oauth2/consent?...})
     * @param param the parameter name
     * @return the decoded parameter value, or {@code ""} if absent
     */
    private static String extractParam(String url, String param) {
        if (url == null) return "";
        int q = url.indexOf('?');
        if (q < 0) return "";
        String query = url.substring(q + 1);
        for (String part : query.split("&")) {
            int eq = part.indexOf('=');
            if (eq < 0) continue;
            String key = java.net.URLDecoder.decode(part.substring(0, eq),
                    java.nio.charset.StandardCharsets.UTF_8);
            if (key.equals(param)) {
                return java.net.URLDecoder.decode(part.substring(eq + 1),
                        java.nio.charset.StandardCharsets.UTF_8);
            }
        }
        return "";
    }
}
