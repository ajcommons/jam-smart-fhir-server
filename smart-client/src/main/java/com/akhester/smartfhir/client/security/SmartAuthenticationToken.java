package com.akhester.smartfhir.client.security;

import com.akhester.smartfhir.client.context.SmartLaunchContext;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;

/**
 * Spring Security {@link org.springframework.security.core.Authentication} token
 * representing a successfully authenticated SMART EHR launch session.
 *
 * <h3>Why a custom token?</h3>
 * Spring Security requires an {@code Authentication} object in the
 * {@code SecurityContext} to consider a request authenticated. We don't use
 * Spring's built-in OAuth2 tokens because our flow is manual — we drove the
 * entire handshake ourselves in Tasks 3–6. This token is our bridge: it wraps
 * the {@link SmartLaunchContext} we already have and presents it to Spring
 * Security in the shape it expects.
 *
 * <h3>Authority</h3>
 * Every successfully launched SMART session gets {@code ROLE_SMART_USER}.
 * This is the role {@link SecurityConfig} checks for on {@code /api/**} routes.
 * Finer-grained access (which FHIR resources) is controlled by
 * {@link SmartLaunchContext#hasScope(String)} in the data layer — not by
 * Spring Security authorities, which are too coarse-grained for SMART scopes.
 *
 * <h3>Lifecycle</h3>
 * Created by {@link SmartSecurityFilter} on every request where a valid,
 * non-expired {@link SmartLaunchContext} is found in the HTTP session.
 * Set into {@code SecurityContextHolder} for the duration of the request.
 */
public class SmartAuthenticationToken extends AbstractAuthenticationToken {

    private static final long serialVersionUID = 1L;

    /** The role granted to every successfully authenticated SMART session. */
    public static final String ROLE_SMART_USER = "ROLE_SMART_USER";

    private final SmartLaunchContext launchContext;

    public SmartAuthenticationToken(SmartLaunchContext launchContext) {
        super(List.of(new SimpleGrantedAuthority(ROLE_SMART_USER)));
        this.launchContext = launchContext;
        // Mark as authenticated — this token is only created after the full
        // SMART handshake has completed and the context has been validated.
        setAuthenticated(true);
    }

    /**
     * The principal is the patient ID from the launch context, or the FHIR base URL
     * when no patient has been selected yet (standalone launch before the picker step).
     *
     * <p>{@code getPrincipal()} must never return {@code null}: Spring Security's audit
     * log, toString(), and several framework internals assume a non-null value here.
     * Returning the FHIR base URL is a meaningful fallback — it uniquely identifies
     * the EHR system the user is connecting to.</p>
     */
    @Override
    public Object getPrincipal() {
        String patientId = launchContext.patientId();
        if (patientId != null && !patientId.isBlank()) {
            return patientId;
        }
        // Standalone launch: patient not yet selected — fall back to FHIR base URL
        String fhirBase = launchContext.fhirBaseUrl();
        return (fhirBase != null && !fhirBase.isBlank()) ? fhirBase : "unknown";
    }

    /**
     * Credentials are not applicable here — the access token is the credential
     * but it lives in {@link SmartLaunchContext} and is not exposed here
     * to prevent it surfacing in Spring Security's audit logs.
     */
    @Override
    public Object getCredentials() {
        return null;
    }

    /**
     * Returns the full launch context — available to any code that casts
     * the {@code Authentication} to this type.
     */
    public SmartLaunchContext getLaunchContext() {
        return launchContext;
    }

    @Override
    public String toString() {
        return "SmartAuthenticationToken[patient=" + launchContext.patientId()
                + ", authenticated=true]";
    }
}
