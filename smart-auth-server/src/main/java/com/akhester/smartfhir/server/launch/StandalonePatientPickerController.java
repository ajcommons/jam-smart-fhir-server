package com.akhester.smartfhir.server.launch;

import com.akhester.smartfhir.server.SmartServerProperties;
import jakarta.servlet.http.HttpSession;
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
 * Patient picker for SMART standalone launch (SMART App Launch v2 §7.3).
 * Invoked by {@link StandalonePatientPickerFilter} when {@code launch/patient} scope
 * is requested without a {@code launch} token. After the clinician picks a patient,
 * reconstructs the original {@code /oauth2/authorize} URL with a newly created
 * {@code launch=TOKEN} parameter and redirects, allowing Spring AS to proceed normally.
 * Original authorize params are read from {@link StandalonePatientPickerFilter#SESSION_KEY}.
 */
@Controller
@Validated
@RequestMapping("/standalone")
public class StandalonePatientPickerController {

    private static final Logger log =
            LoggerFactory.getLogger(StandalonePatientPickerController.class);

    private final LaunchContextService launchContextService;
    private final SmartServerProperties serverProperties;
    private final PatientFetchService patientFetchService;

    public StandalonePatientPickerController(LaunchContextService launchContextService,
                                              SmartServerProperties serverProperties,
                                              PatientFetchService patientFetchService) {
        this.launchContextService = launchContextService;
        this.serverProperties     = serverProperties;
        this.patientFetchService  = patientFetchService;
    }

    /**
     * Patient picker page for standalone launch.
     *
     * @param search optional patient name filter
     * @param session HTTP session — must contain the saved authorization request
     */
    @GetMapping("/pick-patient")
    public String pickPatient(
            @RequestParam(required = false) String search,
            HttpSession session,
            Model model) {

        // Guard: if the session is missing the saved auth request, the filter
        // didn't send us here — something went wrong or the session expired.
        StandalonePatientPickerFilter.StandaloneAuthRequestParams savedParams =
                (StandalonePatientPickerFilter.StandaloneAuthRequestParams)
                        session.getAttribute(StandalonePatientPickerFilter.SESSION_KEY);

        if (savedParams == null) {
            log.warn("Standalone patient picker accessed without a saved authorization request " +
                     "— session may have expired");
            return "redirect:/error?reason=session_expired";
        }

        model.addAttribute("search",      search);
        model.addAttribute("fhirBaseUrl", serverProperties.fhirBaseUrl());
        model.addAttribute("clientId",    savedParams.clientId());

        try {
            model.addAttribute("patients", patientFetchService.fetchPatients(search));
        } catch (Exception e) {
            log.error("Failed to fetch patients from FHIR server at {}", serverProperties.fhirBaseUrl(), e);
            model.addAttribute("patients",  List.of());
            model.addAttribute("fhirError",
                    "Could not reach the FHIR server. Please verify the server is running " +
                    "and contact your system administrator if the problem persists.");
        }

        return "patient-picker-standalone";
    }

    /**
     * Handles patient selection and injects the patient context into the
     * authorization flow via a newly created launch token.
     *
     * @param patientId the selected patient's FHIR resource ID
     * @param session   HTTP session — must contain the saved authorization request
     * @param principal the authenticated clinician
     */
    @PostMapping("/pick-patient")
    public String pickPatientSubmit(
            @RequestParam
            @Pattern(
                regexp = "^[a-zA-Z0-9\\-\\.]{1,64}$",
                message = "patientId must be a valid FHIR resource ID"
            )
            String patientId,
            HttpSession session,
            @AuthenticationPrincipal UserDetails principal) {

        StandalonePatientPickerFilter.StandaloneAuthRequestParams savedParams =
                (StandalonePatientPickerFilter.StandaloneAuthRequestParams)
                        session.getAttribute(StandalonePatientPickerFilter.SESSION_KEY);

        if (savedParams == null) {
            log.warn("Standalone patient picker POST without saved authorization request — " +
                     "session may have expired. User={}", principal.getUsername());
            return "redirect:/error?reason=session_expired";
        }

        // Create a launch token for the selected patient.
        // This binds the patient context to a short-lived opaque token that
        // SmartTokenCustomizer will resolve when the access token is issued.
        // NOTE: session attribute is removed AFTER the DB call succeeds — if
        // createLaunchToken throws (e.g. DB down), the session is preserved so
        // the user can retry rather than seeing a confusing "session expired" error.
        String launchToken = launchContextService.createLaunchToken(
                patientId,
                null,   // no encounter for standalone launch
                serverProperties.defaultNeedPatientBanner(),
                savedParams.clientId(),
                principal.getUsername()
        );

        // Remove the saved params from the session — consumed successfully
        session.removeAttribute(StandalonePatientPickerFilter.SESSION_KEY);

        log.info("Standalone launch: patient selected — clinician={}, patient={}, client={}",
                principal.getUsername(), patientId, savedParams.clientId());

        // Reconstruct the original /oauth2/authorize URL with the launch token injected.
        // The filter will NOT intercept this time because launch param is now present.
        UriComponentsBuilder builder = UriComponentsBuilder
                .fromPath("/oauth2/authorize")
                .queryParam("response_type",         savedParams.responseType())
                .queryParam("client_id",             savedParams.clientId())
                .queryParam("redirect_uri",          savedParams.redirectUri())
                .queryParam("scope",                 savedParams.scope())
                .queryParam("code_challenge",        savedParams.codeChallenge())
                .queryParam("code_challenge_method", savedParams.codeChallengeMethod())
                .queryParam("launch",                launchToken);

        // Optional params — only add if present in the original request
        if (savedParams.state() != null) {
            builder.queryParam("state", savedParams.state());
        }
        if (savedParams.nonce() != null) {
            builder.queryParam("nonce", savedParams.nonce());
        }

        String authorizeUrl = builder.toUriString();
        log.debug("Redirecting to: {}", authorizeUrl);

        return "redirect:" + authorizeUrl;
    }

}
