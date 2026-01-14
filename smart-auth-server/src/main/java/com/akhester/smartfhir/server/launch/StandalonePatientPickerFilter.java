package com.akhester.smartfhir.server.launch;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Map;

/**
 * Intercepts {@code GET /oauth2/authorize} for SMART standalone launch (v2 §7.3):
 * when {@code scope} contains {@code launch/patient} but no {@code launch} token is
 * present, saves the original request params to session under {@link #SESSION_KEY}
 * and redirects to the patient picker. Registered before
 * {@code OAuth2AuthorizationEndpointFilter} in the Order-1 chain so Spring AS
 * never receives an authorize request without patient context.
 */
@Component
public class StandalonePatientPickerFilter extends OncePerRequestFilter {

    private static final Logger log =
            LoggerFactory.getLogger(StandalonePatientPickerFilter.class);

    /**
     * Session attribute key under which the original /oauth2/authorize params are saved.
     * {@link StandalonePatientPickerController} reads this and removes it after use.
     */
    public static final String SESSION_KEY = "standalone_auth_request";

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        // Only intercept GET /oauth2/authorize
        if (!isAuthorizeRequest(request)) {
            filterChain.doFilter(request, response);
            return;
        }

        String scope  = request.getParameter("scope");
        String launch = request.getParameter("launch");

        // Standalone launch condition: launch/patient in scope AND no launch token
        boolean needsStandalonePicker =
                scope != null
                && scopeContainsLaunchPatient(scope)
                && (launch == null || launch.isBlank());

        if (!needsStandalonePicker) {
            // EHR launch (launch param present) or no launch/patient scope — pass through
            filterChain.doFilter(request, response);
            return;
        }

        // Save the original authorize request params to the session so the
        // patient picker can reconstruct the final /oauth2/authorize URL after
        // the clinician selects a patient.
        HttpSession session = request.getSession(true);

        // Store a snapshot of all request parameters we'll need to reconstruct the request
        StandaloneAuthRequestParams savedParams = new StandaloneAuthRequestParams(
                request.getParameter("response_type"),
                request.getParameter("client_id"),
                request.getParameter("redirect_uri"),
                scope,
                request.getParameter("state"),
                request.getParameter("code_challenge"),
                request.getParameter("code_challenge_method"),
                request.getParameter("nonce")
        );

        session.setAttribute(SESSION_KEY, savedParams);

        String clientId = request.getParameter("client_id");
        log.info("Standalone launch intercepted — client_id={}, redirecting to patient picker",
                clientId);

        // Redirect to the patient picker page
        response.sendRedirect(request.getContextPath() + "/standalone/pick-patient");
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    private boolean isAuthorizeRequest(HttpServletRequest request) {
        return "GET".equalsIgnoreCase(request.getMethod())
                && request.getRequestURI().endsWith("/oauth2/authorize");
    }

    private boolean scopeContainsLaunchPatient(String scope) {
        // scope is space-delimited; check for the exact token "launch/patient"
        for (String token : scope.split("\\s+")) {
            if ("launch/patient".equals(token)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Snapshot of the original {@code /oauth2/authorize} request parameters.
     * Stored in the session and read back by {@link StandalonePatientPickerController}.
     *
     * Serializable so it survives session persistence (though for H2/in-memory
     * sessions this is not strictly required).
     */
    public record StandaloneAuthRequestParams(
            String responseType,
            String clientId,
            String redirectUri,
            String scope,
            String state,
            String codeChallenge,
            String codeChallengeMethod,
            String nonce
    ) implements java.io.Serializable {}
}
