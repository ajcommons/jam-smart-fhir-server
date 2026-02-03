package com.akhester.smartfhir.server.token;

import com.akhester.smartfhir.server.SmartServerProperties;
import com.akhester.smartfhir.server.launch.LaunchContext;
import com.akhester.smartfhir.server.launch.LaunchContextService;
import com.akhester.smartfhir.server.launch.LaunchTokenException;
import com.akhester.smartfhir.server.oidc.IdTokenBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Adds SMART on FHIR claims to JWTs issued by this authorization server.
 *
 * Resolves the {@code launch} parameter from the authorization context via
 * {@link LaunchContextService} and injects {@code patient}, {@code encounter},
 * and {@code need_patient_banner} into both the access token and id_token.
 * Called for both token types; differentiates via {@code context.getTokenType()}.
 */
@Component
public class SmartTokenCustomizer implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private static final Logger log = LoggerFactory.getLogger(SmartTokenCustomizer.class);

    private final LaunchContextService launchContextService;
    private final IdTokenBuilder idTokenBuilder;
    private final SmartServerProperties serverProperties;

    public SmartTokenCustomizer(LaunchContextService launchContextService,
                                 IdTokenBuilder idTokenBuilder,
                                 SmartServerProperties serverProperties) {
        this.launchContextService = launchContextService;
        this.idTokenBuilder       = idTokenBuilder;
        this.serverProperties     = serverProperties;
    }

    @Override
    public void customize(JwtEncodingContext context) {
        // ── Access token — add SMART extras ───────────────────────────────────
        if (context.getTokenType().getValue().equals("access_token")) {
            customizeAccessToken(context);
        }

        // ── ID token — add OIDC user claims ───────────────────────────────────
        if (context.getTokenType().getValue().equals("id_token")) {
            customizeIdToken(context);
        }
    }

    private void customizeAccessToken(JwtEncodingContext context) {
        // ── SMART v2.2 §7.1.5: aud must be the FHIR server URL ───────────────
        // Spring AS defaults aud to the client_id, which is wrong for SMART.
        // The resource server (HAPI FHIR) validates aud — it must equal the
        // FHIR base URL so the resource server knows this token is for it.
        // Inferno test: "access_token.aud includes FHIR base URL"
        context.getClaims().audience(List.of(serverProperties.fhirBaseUrl()));

        // ── Extract the launch token from the authorization request ────────────
        //
        // Spring Authorization Server 1.3.x stores the original authorize request
        // parameters inside the OAuth2Authorization object under the attribute key
        // OAuth2AuthorizationRequest.class.getName(). The request holds all extra
        // parameters including our SMART-specific "launch" param.
        //
        // This is the correct API — not "additional_parameters" (which was a
        // previous attempt using an unstable internal attribute name).

        String launchToken = null;

        try {
            var authorization = context.getAuthorization();
            if (authorization != null) {
                // Get the stored OAuth2AuthorizationRequest
                org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest
                        authRequest = authorization.getAttribute(
                        org.springframework.security.oauth2.core.endpoint
                                .OAuth2AuthorizationRequest.class.getName());

                if (authRequest != null) {
                    // Additional parameters are any params beyond the standard OAuth2 ones
                    Object lt = authRequest.getAdditionalParameters().get("launch");
                    if (lt != null) {
                        launchToken = lt.toString();
                    }
                }
            }
        } catch (Exception e) {
            log.debug("Could not extract launch param from authorization request: {}",
                    e.getMessage());
        }

        if (launchToken != null && !launchToken.isBlank()) {
            // EHR launch — resolve the token to patient/encounter context
            try {
                LaunchContext launchContext =
                        launchContextService.resolveLaunchToken(launchToken);

                // Add SMART extras to the JWT claims
                // These appear as top-level fields in the token response
                // alongside access_token — exactly what SmartTokenResponse reads
                context.getClaims().claim("patient", launchContext.getPatientFhirId());
                if (launchContext.getEncounterFhirId() != null) {
                    context.getClaims().claim("encounter", launchContext.getEncounterFhirId());
                }
                context.getClaims().claim("need_patient_banner",
                        launchContext.isNeedPatientBanner());

                log.info("SMART extras added to access token — patient={}, encounter={}",
                        launchContext.getPatientFhirId(),
                        launchContext.getEncounterFhirId());

            } catch (LaunchTokenException e) {
                // Non-fatal — access token is still issued, just without patient context.
                // Client's SmartTokenResponse.patient() will be null.
                // Client handles this via requirePatientContext() guard.
                log.warn("Could not resolve launch token '{}' — token issued without patient context: {}",
                        launchToken, e.getMessage());
            }
        } else {
            // Standalone launch — no launch token present.
            log.debug("No launch token in request — standalone mode, no patient context added");
        }
    }

    private void customizeIdToken(JwtEncodingContext context) {
        // Add OIDC claims to the id_token when openid scope is granted.
        // The principal name is the clinician's username.
        String username = context.getPrincipal().getName();

        try {
            var claims = idTokenBuilder.buildClaims(username);
            claims.forEach((key, value) -> context.getClaims().claim(key, value));

            log.debug("OIDC claims added to id_token for user={}", username);
        } catch (Exception e) {
            log.warn("Could not build OIDC claims for user={}: {}", username, e.getMessage());
        }
    }
}
