package com.akhester.smartfhir.server.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * Promotes upstream IdP claims ({@code name}, {@code email}, {@code fhirUser})
 * into the id_token issued by this authorization server.
 *
 * Active under the {@code idp} profile only. Standard OIDC claims ({@code sub},
 * {@code iss}, {@code aud}, {@code exp}, {@code iat}, etc.) are excluded via
 * {@code PROTECTED_CLAIMS} — the authorization server sets these authoritatively
 * and they must not be overridden by upstream values.
 */
@Component
@Profile("idp")
public class FederatedIdentityIdTokenCustomizer
        implements OAuth2TokenCustomizer<JwtEncodingContext> {

    private static final Logger log =
            LoggerFactory.getLogger(FederatedIdentityIdTokenCustomizer.class);

    /**
     * Standard OIDC claims that this server sets authoritatively.
     * These must NOT be overridden by upstream IdP values.
     */
    private static final Set<String> PROTECTED_CLAIMS = Collections.unmodifiableSet(
            new HashSet<>(Arrays.asList(
                    IdTokenClaimNames.ISS,
                    IdTokenClaimNames.SUB,
                    IdTokenClaimNames.AUD,
                    IdTokenClaimNames.EXP,
                    IdTokenClaimNames.IAT,
                    IdTokenClaimNames.AUTH_TIME,
                    IdTokenClaimNames.NONCE,
                    IdTokenClaimNames.ACR,
                    IdTokenClaimNames.AMR,
                    IdTokenClaimNames.AZP,
                    IdTokenClaimNames.AT_HASH,
                    IdTokenClaimNames.C_HASH
            )));

    @Override
    public void customize(JwtEncodingContext context) {
        // Only customise id_token — access token is handled by SmartTokenCustomizer
        if (!OidcParameterNames.ID_TOKEN.equals(
                context.getTokenType().getValue())) {
            return;
        }

        Map<String, Object> upstreamClaims = extractUpstreamClaims(
                context.getPrincipal());

        if (upstreamClaims.isEmpty()) {
            return;
        }

        context.getClaims().claims(existingClaims -> {
            // Add only upstream claims that are NOT in the protected set.
            // Using forEach + containsCheck rather than mutating upstreamClaims
            // makes the filtering intent explicit and avoids side-effects.
            upstreamClaims.forEach((key, value) -> {
                if (!PROTECTED_CLAIMS.contains(key)) {
                    existingClaims.put(key, value);
                }
            });
        });

        log.debug("Federated id_token customised — added claims: {}",
                upstreamClaims.keySet());
    }

    /**
     * Extracts SMART-relevant claims from the upstream IdP authentication.
     *
     * <p>Specifically looks for:</p>
     * <ul>
     *   <li>{@code name} — clinician display name</li>
     *   <li>{@code email} — clinician email</li>
     *   <li>{@code fhir_practitioner_id} — resolved by {@link FederatedIdentityConfig}
     *       and stored as a custom claim on the OidcUser, renamed to {@code fhirUser}
     *       to match the SMART spec</li>
     * </ul>
     */
    private Map<String, Object> extractUpstreamClaims(
            org.springframework.security.core.Authentication principal) {

        Map<String, Object> claims = new HashMap<>();

        if (principal.getPrincipal() instanceof OidcUser oidcUser) {
            OidcIdToken idToken = oidcUser.getIdToken();
            if (idToken != null) {
                // name — clinician display name for the id_token
                if (idToken.getClaimAsString("name") != null) {
                    claims.put("name", idToken.getClaimAsString("name"));
                }
                // email
                if (idToken.getClaimAsString("email") != null) {
                    claims.put("email", idToken.getClaimAsString("email"));
                }
            }

            // fhir_practitioner_id was injected by FederatedIdentityConfig's
            // OidcUserService after the Practitioner lookup — rename to fhirUser
            // as required by the SMART spec
            Object practitionerId = oidcUser.getUserInfo() != null
                    ? oidcUser.getUserInfo().getClaim("fhir_practitioner_id")
                    : null;

            if (practitionerId != null) {
                claims.put("fhirUser", practitionerId.toString());
                log.debug("fhirUser set in id_token: {}", practitionerId);
            } else {
                log.debug("fhir_practitioner_id not present — fhirUser omitted from id_token");
            }

        } else if (principal.getPrincipal() instanceof OAuth2User oauth2User) {
            // Non-OIDC upstream (e.g. GitHub-style OAuth2 only)
            Object name  = oauth2User.getAttribute("name");
            Object email = oauth2User.getAttribute("email");
            if (name  != null) claims.put("name",  name);
            if (email != null) claims.put("email", email);
        }

        return claims;
    }
}
