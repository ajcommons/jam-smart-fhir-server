package com.akhester.smartfhir.server.auth;

import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * Renders {@code GET /oauth2/consent} — the SMART scope-consent page.
 *
 * Spring AS redirects here when {@code requireAuthorizationConsent=true} and no
 * prior consent is stored. The clinician approves or denies the requested scopes;
 * the form POSTs back to {@code /oauth2/authorize} with the state token Spring AS issued.
 */
@Controller
public class ConsentController {

    /**
     * SMART scopes that do not need a human-readable description on the consent page
     * (they are either implied or have their own canonical phrasing already).
     */
    private static final Set<String> SILENT_SCOPES = Set.of("openid");

    private final RegisteredClientRepository registeredClientRepository;

    public ConsentController(RegisteredClientRepository registeredClientRepository) {
        this.registeredClientRepository = registeredClientRepository;
    }

    /**
     * Renders the consent page for the given authorization request.
     *
     * @param clientId  the OAuth2 client identifier — used to look up the app name
     * @param scope     space-separated list of scopes being requested
     * @param state     opaque state token issued by Spring AS — must be echoed in the POST
     * @param model     Thymeleaf model
     * @return          template name {@code "consent"}
     */
    @GetMapping("/oauth2/consent")
    public String consentPage(
            @RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
            @RequestParam(OAuth2ParameterNames.SCOPE)     String scope,
            @RequestParam(OAuth2ParameterNames.STATE)     String state,
            Model model) {

        // ── App name ──────────────────────────────────────────────────────────
        String appName = clientId; // fallback if not found
        RegisteredClient registeredClient = registeredClientRepository.findByClientId(clientId);
        if (registeredClient != null && registeredClient.getClientName() != null
                && !registeredClient.getClientName().isBlank()) {
            appName = registeredClient.getClientName();
        }

        // ── Humanise the requested scopes ──────────────────────────────────────
        // Build a list of ScopeDetail records for the template so the clinician
        // sees plain-English descriptions rather than raw SMART scope identifiers.
        List<ScopeDetail> scopeDetails = new ArrayList<>();
        Set<String> requestedScopes = new LinkedHashSet<>(
                Arrays.asList(scope.split("\\s+")));

        for (String s : requestedScopes) {
            if (SILENT_SCOPES.contains(s)) {
                continue; // openid is always granted; no need to list it explicitly
            }
            scopeDetails.add(new ScopeDetail(s, humanise(s)));
        }

        model.addAttribute("clientId",    clientId);
        model.addAttribute("appName",     appName);
        model.addAttribute("state",       state);
        model.addAttribute("scopeDetails", scopeDetails);

        return "consent";
    }

    // ── Inner record ──────────────────────────────────────────────────────────

    /**
     * Carries a raw scope identifier and its human-readable description to the template.
     *
     * @param scope       the raw OAuth2/SMART scope string (e.g. {@code "patient/Patient.rs"})
     * @param description plain-English one-liner shown to the clinician
     */
    public record ScopeDetail(String scope, String description) {}

    // ── Scope humanisation ────────────────────────────────────────────────────

    /**
     * Maps a SMART scope string to a short, plain-English description for display
     * on the consent page.
     *
     * <p>Unmapped scopes fall back to the raw scope string so the page never breaks
     * on unknown scopes from future SMART versions.</p>
     */
    private static String humanise(String scope) {
        return switch (scope) {
            // ── SMART launch context ─────────────────────────────────────────
            case "launch"         -> "Access the patient context provided by the EHR";
            case "launch/patient" -> "Allow the server to select the in-scope patient";
            case "launch/encounter" -> "Allow the server to select the in-scope encounter";

            // ── OIDC / identity ───────────────────────────────────────────────
            case "fhirUser"       -> "Identify you as a FHIR Practitioner (your identity)";
            case "profile"        -> "Read your basic profile information";
            case "email"          -> "Read your email address";

            // ── Offline / refresh ─────────────────────────────────────────────
            case "offline_access" -> "Maintain access between sessions (refresh tokens)";

            // ── SMART v2 resource scopes (patient/*.rs, patient/*.cruds, etc.) ─
            default -> humaniseFhirScope(scope);
        };
    }

    /**
     * Attempts to expand a FHIR resource scope such as {@code patient/Patient.rs} into a
     * readable phrase.  Returns the raw scope unchanged when the pattern doesn't match.
     */
    private static String humaniseFhirScope(String scope) {
        // Pattern: {context}/{Resource}.{operations}
        // context  = "patient" | "user" | "system"
        // Resource = FHIR resource type or "*"
        // operations = any combination of c r u d s
        int slashIdx = scope.indexOf('/');
        int dotIdx   = scope.lastIndexOf('.');
        if (slashIdx < 0 || dotIdx <= slashIdx) {
            return scope; // not a FHIR resource scope — return as-is
        }

        String context    = scope.substring(0, slashIdx);
        String resource   = scope.substring(slashIdx + 1, dotIdx);
        String operations = scope.substring(dotIdx + 1);

        String contextLabel = switch (context) {
            case "patient" -> "the current patient's";
            case "user"    -> "your";
            case "system"  -> "all";
            default        -> context + "'s";
        };

        String resourceLabel = "*".equals(resource) ? "all FHIR resources" : resource + " resources";

        List<String> ops = new ArrayList<>();
        if (operations.contains("c")) ops.add("create");
        if (operations.contains("r")) ops.add("read");
        if (operations.contains("u")) ops.add("update");
        if (operations.contains("d")) ops.add("delete");
        if (operations.contains("s")) ops.add("search");

        String opLabel = ops.isEmpty() ? "access" : String.join(", ", ops);

        return capitalise(opLabel) + " " + contextLabel + " " + resourceLabel;
    }

    private static String capitalise(String s) {
        if (s == null || s.isEmpty()) return s;
        return Character.toUpperCase(s.charAt(0)) + s.substring(1);
    }
}
