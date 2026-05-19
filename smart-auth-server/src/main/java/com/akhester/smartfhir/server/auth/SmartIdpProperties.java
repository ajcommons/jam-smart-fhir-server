package com.akhester.smartfhir.server.auth;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Profile;
import org.springframework.validation.annotation.Validated;

/**
 * Binds {@code smart.server.idp.*} properties for upstream IdP federation.
 * Active only under the {@code idp} profile.
 *
 * The IdP authenticates the clinician; {@link PractitionerLookupService} then
 * resolves the configured {@code userIdClaim} to a FHIR Practitioner ID so
 * {@code fhirUser} can be injected into the SMART id_token.
 *
 * See {@code application-idp.yml} for configuration examples.
 */
@Validated
@Profile("idp")
@ConfigurationProperties(prefix = "smart.server.idp")
public record SmartIdpProperties(

        /** IdP claim that identifies the clinician (e.g. "email", "sub", "preferred_username"). */
        @NotBlank(message = "smart.server.idp.user-id-claim must be set (IDP_USER_ID_CLAIM env var)")
        String userIdClaim,

        /**
         * FHIR search URL template — {@code {identifier}} is replaced with the claim value.
         * e.g. {@code http://host/fhir/Practitioner?identifier=http://myorg/emp/{identifier}}
         */
        @NotBlank(message = "smart.server.idp.user-lookup-query must be set (IDP_USER_LOOKUP_QUERY env var)")
        String userLookupQuery

) {
    /** Substitutes the identifier into the lookup URL, URL-encoding the value. */
    public String buildLookupUrl(String identifierValue) {
        return userLookupQuery.replace("{identifier}",
                java.net.URLEncoder.encode(identifierValue,
                        java.nio.charset.StandardCharsets.UTF_8));
    }
}
