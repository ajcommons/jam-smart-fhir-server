package com.akhester.smartfhir.server.discovery;

import com.akhester.smartfhir.server.SmartServerProperties;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Serves {@code GET /.well-known/smart-configuration} per SMART App Launch v2.
 *
 * Returns authorization/token endpoints, supported scopes, capabilities
 * (EHR launch, standalone launch, PKCE/S256) and SMART capability flags.
 * SMART clients use this for dynamic discovery before starting the OAuth2 flow.
 *
 * The FHIR server (port 8080) proxies this path to here (port 9000) via
 * {@code SmartDiscoveryProxyFilter} so clients can resolve it from the ISS.
 */
@RestController
public class SmartDiscoveryController {

    private final SmartServerProperties serverProperties;

    public SmartDiscoveryController(SmartServerProperties serverProperties) {
        this.serverProperties = serverProperties;
    }

    @GetMapping(
        value = "/.well-known/smart-configuration",
        produces = MediaType.APPLICATION_JSON_VALUE
    )
    public Map<String, Object> smartConfiguration() {
        String issuer = serverProperties.issuerUrl();

        Map<String, Object> config = new LinkedHashMap<>();

        // ── Required by SMART App Launch v2.2 ────────────────────────────────
        config.put("authorization_endpoint", issuer + "/oauth2/authorize");
        config.put("token_endpoint",         issuer + "/oauth2/token");

        // ── Auth methods — public client (no client_secret, PKCE only) ────────
        config.put("token_endpoint_auth_methods_supported",
                List.of("none")); // public client — PKCE is the credential

        // ── Scopes this server can grant ──────────────────────────────────────
        config.put("scopes_supported", List.of(
                "launch",
                "launch/patient",
                "openid",
                "fhirUser",
                "offline_access",
                "patient/Patient.rs",
                "patient/Patient.cruds",
                "patient/Condition.rs",
                "patient/MedicationRequest.rs",
                "patient/Observation.rs",
                "patient/AllergyIntolerance.rs",
                "patient/Encounter.rs"
        ));

        config.put("response_types_supported", List.of("code"));

        // ── Capabilities — what our client checks with supportsEhrLaunch() ───
        config.put("capabilities", List.of(
                "launch-ehr",                 // supports EHR launch mode
                "launch-standalone",          // supports standalone launch mode
                "client-public",              // public clients (no secret, PKCE only)
                "context-ehr-patient",        // patient context carried in EHR launch token
                "context-ehr-encounter",      // encounter context in EHR launch token
                "context-standalone-patient", // patient selection in standalone launch
                "permission-patient",         // patient/* scopes supported
                "permission-user",            // user/* scopes supported
                "sso-openid-connect"          // OIDC id_token issued
        ));

        // ── Grant types — required by SMART App Launch v2.2 §7.1 ─────────────
        config.put("grant_types_supported",
                List.of("authorization_code", "refresh_token"));

        // ── PKCE — our client checks supportsPkceS256() ───────────────────────
        config.put("code_challenge_methods_supported", List.of("S256"));

        // ── JWKS — where clients verify JWT signatures ────────────────────────
        config.put("jwks_uri", issuer + "/oauth2/jwks");

        // ── Token introspection — required by SMART App Launch v2.2 §7.1.1
        config.put("introspection_endpoint", issuer + "/oauth2/introspect");

        // ── Token revocation — RFC 7009
        config.put("revocation_endpoint", issuer + "/oauth2/revoke");

        // ── OIDC ──────────────────────────────────────────────────────────────
        config.put("issuer", issuer);

        return config;
    }
}
