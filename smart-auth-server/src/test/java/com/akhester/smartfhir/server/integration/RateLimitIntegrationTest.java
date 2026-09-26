package com.akhester.smartfhir.server.integration;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.web.servlet.MvcResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for per-IP rate limiting on token endpoints.
 *
 * <h3>What is tested</h3>
 * <ol>
 *   <li>Requests within the burst capacity succeed (HTTP 200 or 400 — not 429)</li>
 *   <li>After exceeding the burst capacity the server returns HTTP 429</li>
 *   <li>429 response includes a {@code Retry-After} header</li>
 *   <li>Rate limiting applies to /oauth2/token, /oauth2/introspect, /oauth2/revoke</li>
 * </ol>
 *
 * <h3>Design note — why send invalid requests</h3>
 * The rate limit (TokenEndpointRateLimitFilter) runs BEFORE Spring Security
 * authentication. Sending clearly-invalid token requests (no grant_type etc.)
 * means the filter is exercised without needing real credentials, and the test
 * avoids the overhead of a full OAuth2 flow for every burst iteration.
 *
 * Expected status for invalid requests that are NOT rate-limited: 400 Bad Request
 * (Spring AS rejects the malformed request after the rate-limit filter passes it through).
 * Expected status when rate limited: 429 Too Many Requests (returned by the filter itself).
 *
 * <h3>Bucket4j config (TokenEndpointRateLimitFilter)</h3>
 * - Burst capacity: 20 tokens
 * - Refill: 10 tokens per minute
 * - The test sends 21 requests from the same MockMvc instance (same virtual IP)
 *   and asserts the 21st returns 429.
 */
/**
 * Each test drains the full 20-token burst for {@code 127.0.0.1}.
 * {@code @DirtiesContext} restarts the Spring context between test methods so
 * the in-memory Bucket4j bucket map is reset to a full bucket for each test.
 * Rate-limit tests are inherently stateful — this is the simplest, most
 * transparent way to achieve isolation without exposing a reset() API on the filter.
 */
@DirtiesContext(classMode = DirtiesContext.ClassMode.AFTER_EACH_TEST_METHOD)
@DisplayName("Token endpoint rate limiting (Bucket4j)")
class RateLimitIntegrationTest extends SmartIntegrationTestBase {

    private static final int  BURST_CAPACITY  = 20;
    private static final int  OVER_BURST      = BURST_CAPACITY + 1;

    // ── 1. /oauth2/token rate limiting ────────────────────────────────────────

    @Test
    @DisplayName("First 20 requests to /oauth2/token succeed (within burst); the 21st returns 429")
    void tokenEndpoint_burstExceeded_returns429() throws Exception {
        drainBurstAndAssert429("/oauth2/token");
    }

    // ── 2. /oauth2/introspect rate limiting ───────────────────────────────────

    @Test
    @DisplayName("First 20 requests to /oauth2/introspect succeed (within burst); the 21st returns 429")
    void introspectEndpoint_burstExceeded_returns429() throws Exception {
        drainBurstAndAssert429("/oauth2/introspect");
    }

    // ── 3. /oauth2/revoke rate limiting ───────────────────────────────────────

    @Test
    @DisplayName("First 20 requests to /oauth2/revoke succeed (within burst); the 21st returns 429")
    void revokeEndpoint_burstExceeded_returns429() throws Exception {
        drainBurstAndAssert429("/oauth2/revoke");
    }

    // ── 4. Retry-After header ─────────────────────────────────────────────────

    @Test
    @DisplayName("429 response includes Retry-After header")
    void rateLimitedResponse_includesRetryAfterHeader() throws Exception {
        // Drain the burst
        for (int i = 0; i < BURST_CAPACITY; i++) {
            mockMvc.perform(post("/oauth2/token")
                    .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                    .param("grant_type", "authorization_code"));
        }

        // The over-limit request
        MvcResult result = mockMvc.perform(post("/oauth2/token")
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "authorization_code"))
                .andExpect(status().isTooManyRequests())
                .andReturn();

        String retryAfter = result.getResponse().getHeader("Retry-After");
        assertThat(retryAfter)
                .as("Retry-After header must be present on a 429 response")
                .isNotBlank();

        // Retry-After must be a positive integer number of seconds
        assertThat(Integer.parseInt(retryAfter)).isPositive();
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    /**
     * Sends {@code BURST_CAPACITY} invalid requests to {@code endpoint},
     * asserts that each one is NOT 429 (rate limited), then sends one more
     * and asserts that the 21st IS 429.
     *
     * <p>Invalid requests return HTTP 400 from Spring AS (malformed request),
     * which is fine for our purposes — we only care that the filter does NOT
     * return 429 for the first 20.
     */
    private void drainBurstAndAssert429(String endpoint) throws Exception {
        for (int i = 0; i < BURST_CAPACITY; i++) {
            int status = mockMvc.perform(post(endpoint)
                            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                            .param("grant_type", "authorization_code")
                            .param("client_id",  TEST_CLIENT_ID))
                    .andReturn()
                    .getResponse()
                    .getStatus();

            assertThat(status)
                    .as("Request #%d to %s should not be rate-limited (status %d)", i + 1, endpoint, status)
                    .isNotEqualTo(429);
        }

        // The (BURST_CAPACITY + 1)th request must be rate-limited
        mockMvc.perform(post(endpoint)
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "authorization_code")
                        .param("client_id",  TEST_CLIENT_ID))
                .andExpect(status().isTooManyRequests());
    }
}
