package com.akhester.smartfhir.server.auth;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.rest.client.api.IGenericClient;
import org.hl7.fhir.r4.model.Bundle;
import org.hl7.fhir.r4.model.Practitioner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.util.Optional;

/**
 * Resolves an upstream IdP claim (e.g. email from Azure AD / Okta) to a FHIR
 * {@code Practitioner} resource ID by querying the HAPI server with the configured
 * {@code userLookupQuery} template. Active only under the {@code idp} profile.
 * If no Practitioner is found the token is issued without {@code fhirUser} and a
 * WARN is logged — check identifier system alignment in {@code userLookupQuery}.
 */
@Service
@Profile("idp")
public class PractitionerLookupService {

    private static final Logger log =
            LoggerFactory.getLogger(PractitionerLookupService.class);

    private final SmartIdpProperties idpProperties;
    private final IGenericClient fhirClient;

    /**
     * @param fhirContext   the shared {@link FhirContext} singleton from {@link com.akhester.smartfhir.server.launch.FhirConfig}.
     *                      Creating a second FhirContext via FhirContext.forR4() adds ~2–4 s
     *                      startup overhead; injecting the singleton avoids that cost.
     */
    public PractitionerLookupService(SmartIdpProperties idpProperties,
                                      com.akhester.smartfhir.server.SmartServerProperties serverProperties,
                                      FhirContext fhirContext) {
        this.idpProperties = idpProperties;
        this.fhirClient = fhirContext.newRestfulGenericClient(serverProperties.fhirBaseUrl());
    }

    /**
     * Looks up the FHIR Practitioner resource ID for a given IdP claim value.
     *
     * <p>Calls the HAPI FHIR server using the configured
     * {@link SmartIdpProperties#userLookupQuery()} template with
     * {@code {identifier}} replaced by the claim value.</p>
     *
     * @param claimValue the value of the configured {@code user-id-claim}
     *                   from the upstream IdP token (e.g. "jane@hospital.org")
     * @return the FHIR Practitioner logical ID (e.g. "Practitioner/abc-123"),
     *         or {@link Optional#empty()} if no match found
     */
    public Optional<String> lookupPractitionerId(String claimValue) {
        if (claimValue == null || claimValue.isBlank()) {
            log.warn("IdP claim '{}' was blank — cannot look up Practitioner",
                    idpProperties.userIdClaim());
            return Optional.empty();
        }

        String lookupUrl = idpProperties.buildLookupUrl(claimValue);
        log.debug("Looking up Practitioner — claim={}:{}, url={}",
                idpProperties.userIdClaim(), claimValue, lookupUrl);

        try {
            // Execute the FHIR search using the lookup URL directly
            Bundle bundle = fhirClient.search()
                    .byUrl(lookupUrl)
                    .returnBundle(Bundle.class)
                    .execute();

            if (bundle.getEntry().isEmpty()) {
                log.warn("No Practitioner found for {}={} — fhirUser will be absent from token. " +
                         "Check IDP_USER_LOOKUP_QUERY configuration.",
                        idpProperties.userIdClaim(), claimValue);
                return Optional.empty();
            }

            if (bundle.getEntry().size() > 1) {
                log.warn("Multiple Practitioners ({}) found for {}={} — using the first match",
                        bundle.getEntry().size(),
                        idpProperties.userIdClaim(), claimValue);
            }

            Bundle.BundleEntryComponent entry = bundle.getEntry().get(0);
            if (!(entry.getResource() instanceof Practitioner practitioner)) {
                log.warn("Expected Practitioner resource but got {} — skipping fhirUser",
                        entry.getResource().getClass().getSimpleName());
                return Optional.empty();
            }

            String practitionerId = "Practitioner/" +
                    practitioner.getIdElement().getIdPart();

            log.info("Practitioner resolved — {}={} → {}",
                    idpProperties.userIdClaim(), claimValue, practitionerId);

            return Optional.of(practitionerId);

        } catch (Exception e) {
            log.error("Practitioner lookup failed for {}={}: {} — " +
                      "check FHIR server connectivity and IDP_USER_LOOKUP_QUERY",
                    idpProperties.userIdClaim(), claimValue, e.getMessage());
            return Optional.empty();
        }
    }
}
