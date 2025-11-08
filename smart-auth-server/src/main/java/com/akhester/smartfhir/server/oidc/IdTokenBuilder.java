package com.akhester.smartfhir.server.oidc;

import com.akhester.smartfhir.server.SmartServerProperties;
import com.akhester.smartfhir.server.auth.CliniciansUserDetailsService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Component;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Builds the application-specific OIDC claims added to the {@code id_token}.
 * Supplies {@code name} and {@code fhirUser} (FHIR Practitioner reference) when
 * the {@code fhirUser} scope is granted. Standard claims ({@code iss}, {@code aud},
 * {@code exp}, {@code iat}) are set by Spring Authorization Server automatically.
 */
@Component
public class IdTokenBuilder {

    private static final Logger log = LoggerFactory.getLogger(IdTokenBuilder.class);

    private final CliniciansUserDetailsService userDetailsService;
    private final SmartServerProperties serverProperties;

    public IdTokenBuilder(CliniciansUserDetailsService userDetailsService,
                          SmartServerProperties serverProperties) {
        this.userDetailsService = userDetailsService;
        this.serverProperties   = serverProperties;
    }

    /**
     * Builds the custom OIDC claims for the given username.
     *
     * @param username the authenticated clinician's login name
     * @return map of claim name → value to be added to the id_token JWT
     */
    public Map<String, Object> buildClaims(String username) {
        Map<String, Object> claims = new LinkedHashMap<>();

        // sub is already set by Spring Authorization Server (principal name)
        // We add the SMART on FHIR specific claims

        try {
            var user = userDetailsService.loadUserByUsername(username);
            if (user instanceof com.akhester.smartfhir.server.auth.ClinicianUserDetails clinician) {
                // Display name — used by SMART client's UserProfile.displayName()
                if (clinician.getDisplayName() != null) {
                    claims.put("name", clinician.getDisplayName());
                }

                // FHIR resource reference — SMART v2.2 §7.3.1 requires an absolute URL.
                // e.g. "http://localhost:8080/fhir/Practitioner/Practitioner-EXAMPLE-001"
                // Relative form ("Practitioner/...") is rejected by Inferno.
                if (clinician.getFhirUserId() != null) {
                    String fhirBase = serverProperties.fhirBaseUrl();
                    // Strip trailing slash for clean URL concatenation
                    if (fhirBase.endsWith("/")) {
                        fhirBase = fhirBase.substring(0, fhirBase.length() - 1);
                    }
                    claims.put("fhirUser",
                            fhirBase + "/Practitioner/" + clinician.getFhirUserId());
                }
            }
        } catch (UsernameNotFoundException e) {
            // User not found — token still issued with sub only; fhirUser claim omitted.
            // This can happen if the user is deleted between authentication and token issuance.
            log.warn("IdTokenBuilder: user '{}' not found when building id_token claims — fhirUser omitted: {}",
                    username, e.getMessage());
        } catch (Exception e) {
            // Unexpected error (DB connection, mapping failure, etc.) — log at WARN so operators
            // are alerted rather than silently losing the fhirUser claim.
            // Token is still issued with sub only; FHIR access continues.
            log.warn("IdTokenBuilder: unexpected error building id_token claims for user '{}' — fhirUser omitted",
                    username, e);
        }

        return claims;
    }
}
