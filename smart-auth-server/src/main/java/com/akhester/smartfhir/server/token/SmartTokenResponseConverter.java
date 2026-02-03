package com.akhester.smartfhir.server.token;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.MediaType;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AccessTokenAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * Writes the token response JSON, promoting SMART context claims to top-level fields.
 *
 * Spring AS's default response contains only standard OAuth2 fields. SMART App Launch
 * requires {@code patient}, {@code encounter}, {@code need_patient_banner}, and
 * {@code id_token} as top-level JSON fields in the token response body (not buried in the
 * JWT). This handler decodes the access token, extracts those claims (written by
 * {@link SmartTokenCustomizer}), and includes them alongside the standard OAuth2 fields.
 */
@Component
public class SmartTokenResponseConverter implements AuthenticationSuccessHandler {

    private static final Logger log =
            LoggerFactory.getLogger(SmartTokenResponseConverter.class);

    private final ObjectMapper objectMapper;

    public SmartTokenResponseConverter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException {

        if (!(authentication instanceof OAuth2AccessTokenAuthenticationToken tokenAuth)) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return;
        }

        OAuth2AccessToken  accessToken  = tokenAuth.getAccessToken();
        OAuth2RefreshToken refreshToken = tokenAuth.getRefreshToken();

        // ── Build the base response fields ─────────────────────────────────
        // LinkedHashMap preserves insertion order — token response fields appear
        // in a consistent, predictable order on every call (access_token first,
        // SMART extras after standard fields). HashMap gives random order.
        Map<String, Object> responseBody = new LinkedHashMap<>();
        responseBody.put("access_token", accessToken.getTokenValue());
        responseBody.put("token_type",   "Bearer");

        // expires_in in seconds
        if (accessToken.getExpiresAt() != null) {
            long expiresIn = ChronoUnit.SECONDS.between(
                    Instant.now(), accessToken.getExpiresAt());
            responseBody.put("expires_in", Math.max(0, expiresIn));
        }

        // Scope
        Set<String> scopes = accessToken.getScopes();
        if (scopes != null && !scopes.isEmpty()) {
            responseBody.put("scope", String.join(" ", scopes));
        }

        // Refresh token
        if (refreshToken != null) {
            responseBody.put("refresh_token", refreshToken.getTokenValue());
        }

        // ── Extract SMART extras from the JWT claims ────────────────────────
        // SmartTokenCustomizer added patient/encounter/need_patient_banner
        // as JWT claims. We read them back here and promote them to top-level
        // response fields so our client's SmartTokenResponse can read them.
        extractSmartExtras(accessToken.getTokenValue(), responseBody);

        // ── id_token ─────────────────────────────────────────────────────────
        // Spring Auth Server includes the id_token in additionalParameters
        // when openid scope is granted.
        Map<String, Object> additionalParams = tokenAuth.getAdditionalParameters();
        if (additionalParams != null && additionalParams.containsKey("id_token")) {
            responseBody.put("id_token", additionalParams.get("id_token"));
        }

        // ── Write JSON response ───────────────────────────────────────────────
        // RFC 6749 §5.1 requires these headers on every token response.
        // Inferno validates their presence. Without them browsers and proxies
        // may cache access tokens, creating a security risk.
        response.setHeader("Cache-Control", "no-store");
        response.setHeader("Pragma",        "no-cache");
        response.setContentType(MediaType.APPLICATION_JSON_VALUE);
        response.setStatus(HttpServletResponse.SC_OK);
        objectMapper.writeValue(response.getWriter(), responseBody);

        log.debug("SMART token response written — patient={}, encounter={}",
                responseBody.get("patient"), responseBody.get("encounter"));
    }

    /**
     * Decodes the JWT and promotes SMART extras to the response body map.
     *
     * SMART extras added by SmartTokenCustomizer:
     * - {@code patient}             — FHIR Patient resource ID
     * - {@code encounter}           — FHIR Encounter resource ID (may be absent)
     * - {@code need_patient_banner} — boolean
     */
    private void extractSmartExtras(String jwtValue, Map<String, Object> target) {
        try {
            SignedJWT jwt = SignedJWT.parse(jwtValue);
            JWTClaimsSet claims = jwt.getJWTClaimsSet();

            // patient — always present for EHR launch
            String patient = claims.getStringClaim("patient");
            if (patient != null) {
                target.put("patient", patient);
            }

            // encounter — optional (not all EHR launches bind an encounter)
            String encounter = claims.getStringClaim("encounter");
            if (encounter != null) {
                target.put("encounter", encounter);
            }

            // need_patient_banner — boolean
            Object banner = claims.getClaim("need_patient_banner");
            if (banner != null) {
                target.put("need_patient_banner", banner);
            }

        } catch (Exception e) {
            // Non-fatal — SMART extras may be absent for standalone launch
            // or if SmartTokenCustomizer didn't add them
            log.debug("Could not extract SMART extras from JWT: {}", e.getMessage());
        }
    }
}