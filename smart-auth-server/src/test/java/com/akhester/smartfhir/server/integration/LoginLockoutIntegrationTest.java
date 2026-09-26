package com.akhester.smartfhir.server.integration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for the login brute-force lockout.
 *
 * <h3>What is tested</h3>
 * <ol>
 *   <li>Valid login succeeds</li>
 *   <li>Invalid login redirects to /login?error</li>
 *   <li>After 5 consecutive failures the IP is locked out</li>
 *   <li>Locked-out IP is redirected to /login?locked (not /login?error)</li>
 *   <li>Valid credentials from a locked-out IP are still rejected (lockout is IP-based)</li>
 *   <li>Successful login clears the failure counter</li>
 *   <li>/login?locked renders the lockout message (UI smoke test)</li>
 * </ol>
 *
 * <h3>Implementation references</h3>
 * {@link com.akhester.smartfhir.server.security.LoginAttemptService} — failure tracking
 * {@link com.akhester.smartfhir.server.security.LoginLockoutFilter} — pre-auth IP check
 * {@link com.akhester.smartfhir.server.security.SmartAuthenticationFailureHandler} — records failures
 * {@link com.akhester.smartfhir.server.security.SmartAuthenticationSuccessHandler} — clears counter
 *
 * <h3>IP address in tests</h3>
 * MockMvc uses {@code 127.0.0.1} as the remote address for all requests (the same
 * virtual IP). This means all test requests share a single lockout counter.
 * Each test method gets a fresh Spring context so the in-memory counters reset.
 */
@DisplayName("Login brute-force lockout")
class LoginLockoutIntegrationTest extends SmartIntegrationTestBase {

    /** Number of failures that trigger lockout (must match LoginAttemptService.MAX_ATTEMPTS). */
    private static final int MAX_ATTEMPTS = 5;

    // ── 1. Valid login ────────────────────────────────────────────────────────

    @Test
    @DisplayName("Valid credentials — login succeeds and redirects away from /login")
    void validLogin_succeeds() throws Exception {
        mockMvc.perform(post("/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("username", TEST_USERNAME)
                        .param("password", TEST_PASSWORD))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("/portal**"));
    }

    // ── 2. Single invalid login ───────────────────────────────────────────────

    @Test
    @DisplayName("Invalid credentials — login redirects to /login?error")
    void invalidLogin_redirectsToError() throws Exception {
        mockMvc.perform(post("/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("username", TEST_USERNAME)
                        .param("password", "wrong-password"))
                .andExpect(status().is3xxRedirection())
                .andExpect(result -> {
                    String location = result.getResponse().getRedirectedUrl();
                    assertThat(location).isNotNull().contains("error");
                    assertThat(location).doesNotContain("locked");
                });
    }

    // ── 3. Lockout after MAX_ATTEMPTS failures ────────────────────────────────

    @Test
    @DisplayName("After 5 consecutive failures the IP is locked out and redirected to /login?locked")
    void afterMaxFailures_ipIsLocked() throws Exception {
        // Send MAX_ATTEMPTS failed logins — these should all redirect to ?error, not ?locked
        for (int i = 0; i < MAX_ATTEMPTS; i++) {
            mockMvc.perform(post("/login")
                    .with(csrf())
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .param("username", TEST_USERNAME)
                    .param("password", "wrong-" + i));
        }

        // The next attempt (any attempt) from this IP must be redirected to ?locked
        // This is intercepted by LoginLockoutFilter BEFORE Spring Security / BCrypt
        mockMvc.perform(post("/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("username", TEST_USERNAME)
                        .param("password", "still-wrong"))
                .andExpect(status().is3xxRedirection())
                .andExpect(result -> {
                    String location = result.getResponse().getRedirectedUrl();
                    assertThat(location).isNotNull().contains("locked");
                });
    }

    @Test
    @DisplayName("Locked-out IP — even correct password is rejected (lockout is IP-based)")
    void lockedIp_correctPassword_stillRejected() throws Exception {
        // Exhaust the attempts
        for (int i = 0; i < MAX_ATTEMPTS; i++) {
            mockMvc.perform(post("/login")
                    .with(csrf())
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .param("username", TEST_USERNAME)
                    .param("password", "wrong-" + i));
        }

        // Now try with the correct password — should still be blocked by LoginLockoutFilter
        mockMvc.perform(post("/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("username", TEST_USERNAME)
                        .param("password", TEST_PASSWORD))
                .andExpect(status().is3xxRedirection())
                .andExpect(result -> {
                    String location = result.getResponse().getRedirectedUrl();
                    assertThat(location).isNotNull().contains("locked");
                });
    }

    // ── 4. Success clears the failure counter ─────────────────────────────────

    @Test
    @DisplayName("Successful login after some failures resets the failure counter")
    void successfulLogin_resetsFailureCounter() throws Exception {
        // Fail MAX_ATTEMPTS - 1 times (one short of lockout)
        for (int i = 0; i < MAX_ATTEMPTS - 1; i++) {
            mockMvc.perform(post("/login")
                    .with(csrf())
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .param("username", TEST_USERNAME)
                    .param("password", "wrong-" + i));
        }

        // Successful login — clears the counter
        mockMvc.perform(post("/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("username", TEST_USERNAME)
                        .param("password", TEST_PASSWORD))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("/portal**"));

        // Now try MAX_ATTEMPTS failures again — should NOT be locked yet
        // (counter was reset by the successful login above)
        for (int i = 0; i < MAX_ATTEMPTS - 1; i++) {
            int status = mockMvc.perform(post("/login")
                            .with(csrf())
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            .param("username", TEST_USERNAME)
                            .param("password", "wrong-again-" + i))
                    .andReturn()
                    .getResponse()
                    .getStatus();

            // Should redirect (3xx) to /login?error, not to /login?locked
            assertThat(status).isBetween(300, 399);
            // Not locked yet
        }

        // The MAX_ATTEMPTS - 1 failures above do not cause lockout; next login
        // (with correct password) should still work.
        mockMvc.perform(post("/login")
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("username", TEST_USERNAME)
                        .param("password", TEST_PASSWORD))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("/portal**"));
    }

    // ── 5. Login page UI smoke test ───────────────────────────────────────────

    @Test
    @DisplayName("GET /login?locked renders the amber lockout alert block")
    void loginPage_locked_rendersLockoutAlert() throws Exception {
        mockMvc.perform(get("/login").param("locked", ""))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("locked")));
    }

    @Test
    @DisplayName("GET /login?error renders the error alert block")
    void loginPage_error_rendersErrorAlert() throws Exception {
        mockMvc.perform(get("/login").param("error", ""))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("error")));
    }

    @Test
    @DisplayName("GET /login (no params) returns 200 and includes a login form")
    void loginPage_default_rendersForm() throws Exception {
        mockMvc.perform(get("/login"))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("username")));
    }
}
