package com.akhester.smartfhir.server.launch;

import com.akhester.smartfhir.server.SmartServerProperties;
import jakarta.validation.constraints.Pattern;
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

import java.util.List;

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
    private final PatientFetchService patientFetchService;

    public LaunchPortalController(LaunchContextService launchContextService,
                                   SmartServerProperties serverProperties,
                                   PatientFetchService patientFetchService) {
        this.launchContextService  = launchContextService;
        this.serverProperties      = serverProperties;
        this.patientFetchService   = patientFetchService;
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
            model.addAttribute("patients", patientFetchService.fetchPatients(search));
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

}
