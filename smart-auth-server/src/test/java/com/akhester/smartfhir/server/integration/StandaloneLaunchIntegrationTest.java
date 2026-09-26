package com.akhester.smartfhir.server.integration;

import com.akhester.smartfhir.server.launch.StandalonePatientPickerFilter;
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
 * Integration tests for the standalone launch patient-picker intercept.
 *
 * <h3>What is tested</h3>
 * <ol>
 *   <li>Standalone authorize request (scope includes launch/patient, no launch param)
 *       is intercepted and redirected to the patient picker</li>
 *   <li>EHR authorize request (launch param present) passes through to Spring AS normally</li>
 *   <li>Authorize request without launch/patient scope is not intercepted</li>
 *   <li>Standalone auth request params are saved to session on intercept</li>
 *   <li>Patient picker page is accessible when logged in</li>
 *   <li>Patient picker page redirects to /login when not authenticated</li>
 *   <li>Picker POST with a patientId reconstructs and redirects to /oauth2/authorize
 *       with a launch token injected (full standalone flow)</li>
 * </ol>
 *
 * <h3>FHIR server</h3>
 * The patient picker's {@code GET /standalone/pick-patient} calls the HAPI FHIR
 * server to list patients. In integration tests, no real HAPI server is running.
 * Tests that reach the patient listing page expect either a FHIR error banner or
 * an empty list — the page must render gracefully without a live FHIR server.
 */
@DisplayName("Standalone launch patient-picker intercept")
class StandaloneLaunchIntegrationTest extends SmartIntegrationTestBase {

    // ── 1. Standalone authorize request intercepted ───────────────────────────

    @Test
    @DisplayName("GET /oauth2/authorize with launch/patient scope and no launch param " +
                 "is redirected to the patient picker")
    void standaloneAuthorize_noLaunchParam_redirectsToPatientPicker() throws Exception {
        MockHttpSession session = loginSession();

        MvcResult result = mockMvc.perform(get("/oauth2/authorize")
                        .session(session)
                        .param("response_type",         "code")
                        .param("client_id",             TEST_CLIENT_ID)
                        .param("redirect_uri",          TEST_REDIRECT_URI)
                        .param("scope",                 "openid launch/patient patient/Patient.rs")
                        .param("state",                 "standalone-state-1")
                        .param("code_challenge",        testCodeChallenge())
                        .param("code_challenge_method", "S256"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        String redirect = result.getResponse().getRedirectedUrl();
        assertThat(redirect)
                .as("Standalone authorize must be redirected to the patient picker")
                .endsWith("/standalone/pick-patient");
    }

    // ── 2. Session contains saved auth request params ─────────────────────────

    @Test
    @DisplayName("Session contains saved authorization request params after intercept")
    void standaloneAuthorize_sessionContainsSavedParams() throws Exception {
        MockHttpSession session = loginSession();

        mockMvc.perform(get("/oauth2/authorize")
                        .session(session)
                        .param("response_type",         "code")
                        .param("client_id",             TEST_CLIENT_ID)
                        .param("redirect_uri",          TEST_REDIRECT_URI)
                        .param("scope",                 "openid launch/patient patient/Patient.rs")
                        .param("state",                 "saved-params-state")
                        .param("code_challenge",        testCodeChallenge())
                        .param("code_challenge_method", "S256"))
                .andExpect(status().is3xxRedirection());

        // The session must contain the saved authorization request params
        Object savedParams = session.getAttribute(StandalonePatientPickerFilter.SESSION_KEY);
        assertThat(savedParams)
                .as("Session must contain saved authorization request params")
                .isNotNull()
                .isInstanceOf(StandalonePatientPickerFilter.StandaloneAuthRequestParams.class);

        StandalonePatientPickerFilter.StandaloneAuthRequestParams params =
                (StandalonePatientPickerFilter.StandaloneAuthRequestParams) savedParams;

        assertThat(params.clientId()).isEqualTo(TEST_CLIENT_ID);
        assertThat(params.redirectUri()).isEqualTo(TEST_REDIRECT_URI);
        assertThat(params.state()).isEqualTo("saved-params-state");
        assertThat(params.scope()).contains("launch/patient");
    }

    // ── 3. EHR launch (launch param present) passes through ──────────────────

    @Test
    @DisplayName("GET /oauth2/authorize with launch param present is NOT intercepted")
    void ehrAuthorize_launchParamPresent_notIntercepted() throws Exception {
        MockHttpSession session = loginSession();

        // Authorize with a launch token — filter must not redirect to picker.
        // Spring AS will redirect to /login (or proceed with auth code) but
        // crucially must NOT redirect to /standalone/pick-patient.
        MvcResult result = mockMvc.perform(get("/oauth2/authorize")
                        .session(session)
                        .param("response_type",         "code")
                        .param("client_id",             TEST_CLIENT_ID)
                        .param("redirect_uri",          TEST_REDIRECT_URI)
                        .param("scope",                 "openid launch/patient patient/Patient.rs")
                        .param("launch",                "some-ehr-launch-token")
                        .param("state",                 "ehr-state")
                        .param("code_challenge",        testCodeChallenge())
                        .param("code_challenge_method", "S256"))
                .andReturn();

        String redirect = result.getResponse().getRedirectedUrl();
        // Must not go to the standalone picker
        if (redirect != null) {
            assertThat(redirect)
                    .as("EHR launch with a launch param must not be redirected to standalone picker")
                    .doesNotContain("/standalone/pick-patient");
        }
    }

    // ── 4. No launch/patient scope — not intercepted ──────────────────────────

    @Test
    @DisplayName("GET /oauth2/authorize without launch/patient scope is not intercepted")
    void authorize_noLaunchPatientScope_notIntercepted() throws Exception {
        MockHttpSession session = loginSession();

        MvcResult result = mockMvc.perform(get("/oauth2/authorize")
                        .session(session)
                        .param("response_type",         "code")
                        .param("client_id",             TEST_CLIENT_ID)
                        .param("redirect_uri",          TEST_REDIRECT_URI)
                        .param("scope",                 "openid patient/Patient.rs")  // no launch/patient
                        .param("state",                 "no-launch-state")
                        .param("code_challenge",        testCodeChallenge())
                        .param("code_challenge_method", "S256"))
                .andReturn();

        String redirect = result.getResponse().getRedirectedUrl();
        if (redirect != null) {
            assertThat(redirect)
                    .as("Request without launch/patient scope must not be redirected to standalone picker")
                    .doesNotContain("/standalone/pick-patient");
        }
    }

    // ── 5. Patient picker page renders when authenticated ─────────────────────

    @Test
    @DisplayName("GET /standalone/pick-patient renders gracefully when FHIR server is unavailable")
    void pickerPage_authenticated_rendersFhirError() throws Exception {
        // First, trigger the intercept to populate the session
        MockHttpSession session = loginSession();

        mockMvc.perform(get("/oauth2/authorize")
                        .session(session)
                        .param("response_type",         "code")
                        .param("client_id",             TEST_CLIENT_ID)
                        .param("redirect_uri",          TEST_REDIRECT_URI)
                        .param("scope",                 "openid launch/patient patient/Patient.rs")
                        .param("state",                 "picker-render-state")
                        .param("code_challenge",        testCodeChallenge())
                        .param("code_challenge_method", "S256"))
                .andExpect(status().is3xxRedirection());

        // Follow the redirect to the patient picker — FHIR server is not running
        // in test, so the page should render with an error banner (not crash with 500)
        mockMvc.perform(get("/standalone/pick-patient")
                        .session(session))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML));
    }

    // ── 6. Patient picker redirects to /login when not authenticated ──────────

    @Test
    @DisplayName("GET /standalone/pick-patient returns 302 to /login when not authenticated")
    void pickerPage_notAuthenticated_redirectsToLogin() throws Exception {
        mockMvc.perform(get("/standalone/pick-patient"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/login**"));
    }

    // ── 7. Full standalone flow: picker POST reconstructs authorize URL ────────

    @Test
    @DisplayName("POST /standalone/pick-patient with patientId reconstructs authorize URL " +
                 "with launch token and no picker re-intercept")
    void pickerSubmit_withPatientId_redirectsToAuthorizeWithLaunch() throws Exception {
        // Step 1: Trigger intercept → session now has saved params
        MockHttpSession session = loginSession();

        mockMvc.perform(get("/oauth2/authorize")
                        .session(session)
                        .param("response_type",         "code")
                        .param("client_id",             TEST_CLIENT_ID)
                        .param("redirect_uri",          TEST_REDIRECT_URI)
                        .param("scope",                 "openid launch/patient patient/Patient.rs")
                        .param("state",                 "full-flow-state")
                        .param("code_challenge",        testCodeChallenge())
                        .param("code_challenge_method", "S256"))
                .andExpect(status().is3xxRedirection());

        // Step 2: POST the selected patientId to the picker endpoint
        MvcResult pickerResult = mockMvc.perform(post("/standalone/pick-patient")
                        .session(session)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("patientId", "Patient-TEST-001"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        // The redirect must go to /oauth2/authorize (not /standalone/pick-patient again)
        String redirect = pickerResult.getResponse().getRedirectedUrl();
        assertThat(redirect)
                .as("Picker POST must redirect to /oauth2/authorize")
                .contains("/oauth2/authorize");

        // The reconstructed URL must contain a launch= parameter (the new launch token)
        assertThat(redirect)
                .as("Reconstructed authorize URL must include a launch= token")
                .contains("launch=");

        // The reconstructed URL must NOT trigger the standalone picker again
        // (filter checks: launch/patient in scope AND launch absent — now launch IS present)
        assertThat(redirect)
                .as("Reconstructed URL must include the original state")
                .contains("state=full-flow-state");

        // The session must no longer have the saved params (consumed on POST)
        assertThat(session.getAttribute(StandalonePatientPickerFilter.SESSION_KEY))
                .as("Session key must be removed after patient selection")
                .isNull();
    }

    // ── Helper: perform login and return authenticated session ────────────────

    /**
     * Authenticates {@code TEST_USERNAME} and returns an HttpSession containing
     * the Spring Security authentication. Used by tests that need to be logged in
     * before reaching the authorize endpoint.
     */
    private MockHttpSession loginSession() throws Exception {
        MockHttpSession session = new MockHttpSession();

        // GET /login to prime CSRF token in session (some builds require this)
        mockMvc.perform(get("/login").session(session));

        // POST /login to authenticate
        MvcResult loginResult = mockMvc.perform(post("/login")
                        .session(session)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("username", TEST_USERNAME)
                        .param("password", TEST_PASSWORD))
                .andReturn();

        // Follow the post-login redirect if there is one
        String loginRedirect = loginResult.getResponse().getRedirectedUrl();
        if (loginRedirect != null && !loginRedirect.isEmpty()) {
            mockMvc.perform(get(loginRedirect).session(session));
        }

        return session;
    }
}
