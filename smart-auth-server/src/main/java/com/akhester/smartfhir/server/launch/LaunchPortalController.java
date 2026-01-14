package com.akhester.smartfhir.server.launch;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.rest.client.api.IGenericClient;
import com.akhester.smartfhir.server.SmartServerProperties;
import jakarta.validation.constraints.Pattern;
import org.hl7.fhir.r4.model.Bundle;
import org.hl7.fhir.r4.model.Patient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Clinician-facing patient picker for EHR launch (SMART App Launch v2 §7.2).
 * {@code GET /portal} lists patients from the HAPI FHIR server; {@code POST /portal/launch}
 * creates a launch token and redirects the clinician's browser to the SMART client
 * with {@code ?iss=&launch=} parameters to begin the OAuth2 flow.
 */
@Controller
@Validated
@RequestMapping("/portal")
public class LaunchPortalController {

    private static final Logger log = LoggerFactory.getLogger(LaunchPortalController.class);

    private final LaunchContextService launchContextService;
    private final SmartServerProperties serverProperties;
    private final FhirContext fhirContext;

    public LaunchPortalController(LaunchContextService launchContextService,
                                   SmartServerProperties serverProperties,
                                   FhirContext fhirContext) {
        this.launchContextService = launchContextService;
        this.serverProperties     = serverProperties;
        this.fhirContext          = fhirContext;
    }

    /**
     * Patient picker page — shows a list of patients from the HAPI FHIR server.
     */
    @GetMapping
    public String portal(Model model,
                         @RequestParam(required = false) String search) {
        model.addAttribute("search",      search);
        model.addAttribute("fhirBaseUrl", serverProperties.fhirBaseUrl());

        try {
            List<Map<String, String>> patients = fetchPatients(search);
            model.addAttribute("patients", patients);
        } catch (Exception e) {
            log.error("Failed to fetch patients from FHIR server at {}: {}",
                    serverProperties.fhirBaseUrl(), e.getMessage(), e);
            model.addAttribute("patients",  List.of());
            model.addAttribute("fhirError",
                    "Could not reach the FHIR server. Please verify the server is running " +
                    "and contact your system administrator if the problem persists.");
        }

        return "portal";
    }

    /**
     * Handles "Launch App" — creates a launch token and redirects to the SMART client.
     *
     * @param patientId   FHIR Patient resource ID selected by the clinician
     * @param encounterId FHIR Encounter resource ID (optional)
     * @param principal   the authenticated clinician
     */
    @PostMapping("/launch")
    public String launch(
            @RequestParam
            @Pattern(
                regexp = "^[a-zA-Z0-9\\-\\.]{1,64}$",
                message = "patientId must be a valid FHIR resource ID (alphanumeric, hyphens, dots, max 64 chars)"
            )
            String patientId,
            @RequestParam(required = false)
            @Pattern(
                regexp = "^[a-zA-Z0-9\\-\\.]{1,64}$",
                message = "encounterId must be a valid FHIR resource ID"
            )
            String encounterId,
            @AuthenticationPrincipal UserDetails principal) {

        String launchToken = launchContextService.createLaunchToken(
                patientId,
                encounterId,
                serverProperties.defaultNeedPatientBanner(),
                serverProperties.defaultClientId(),
                principal.getUsername()
        );

        log.info("EHR launch initiated — clinician={}, patient={}, encounter={}",
                principal.getUsername(), patientId, encounterId);

        // Build the SMART client launch URL safely — UriComponentsBuilder encodes
        // each parameter value, preventing injection if fhirBaseUrl or launchToken
        // ever contain characters that would break a hand-concatenated URL string.
        String launchUrl = UriComponentsBuilder
                .fromHttpUrl(serverProperties.smartClientLaunchUrl())
                .queryParam("iss",    serverProperties.fhirBaseUrl())
                .queryParam("launch", launchToken)
                .toUriString();

        return "redirect:" + launchUrl;
    }

    // ── private ───────────────────────────────────────────────────────────────

    /**
     * Fetches patients from the HAPI FHIR JPA server.
     * Returns a list of maps for easy Thymeleaf rendering.
     * Throws on network or FHIR errors — caller handles the exception.
     */
    private List<Map<String, String>> fetchPatients(String search) {
        IGenericClient client = fhirContext.newRestfulGenericClient(
                serverProperties.fhirBaseUrl());

        var query = client.search().forResource(Patient.class);

        if (search != null && !search.isBlank()) {
            query = query.where(Patient.NAME.matches().value(search));
        }

        Bundle bundle = query.count(20)
                .returnBundle(Bundle.class)
                .execute();

        List<Map<String, String>> result = new ArrayList<>();
        for (Bundle.BundleEntryComponent entry : bundle.getEntry()) {
            if (entry.getResource() instanceof Patient patient) {
                String id = patient.getIdElement().getIdPart();

                String name = patient.getName().isEmpty() ? "Unknown"
                        : (patient.getNameFirstRep().getGivenAsSingleString()
                           + " " + patient.getNameFirstRep().getFamily()).trim();

                String dob    = patient.getBirthDateElement().getValueAsString();
                String gender = patient.getGender() != null
                        ? patient.getGender().toCode() : "unknown";

                result.add(Map.of(
                        "id",     id,
                        "name",   name,
                        "dob",    dob != null ? dob : "",
                        "gender", gender
                ));
            }
        }
        return result;
    }
}
