package com.akhester.smartfhir.server.auth;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * Admin UI controller for managing SMART app registrations and clinician accounts.
 * All {@code /admin/**} routes require {@code ROLE_ADMIN} (Order-2 filter chain).
 * Write operations delegate to {@link AdminService} and follow PRG to prevent
 * duplicate form submissions; validation errors are passed as flash attributes.
 */
@Controller
@RequestMapping("/admin")
public class AdminController {

    private final AdminService adminService;

    public AdminController(AdminService adminService) {
        this.adminService = adminService;
    }

    // ── Main dashboard ────────────────────────────────────────────────────────

    /**
     * Landing page — defaults to the Apps tab.
     */
    @GetMapping({"", "/"})
    public String dashboard(Model model) {
        model.addAttribute("apps",       adminService.listApps());
        model.addAttribute("clinicians", adminService.listClinicians());
        model.addAttribute("activeTab",  "apps");
        return "admin";
    }

    /**
     * Clinicians tab — same template, different active tab.
     */
    @GetMapping("/clinicians")
    public String cliniciansTab(Model model) {
        model.addAttribute("apps",       adminService.listApps());
        model.addAttribute("clinicians", adminService.listClinicians());
        model.addAttribute("activeTab",  "clinicians");
        return "admin";
    }

    // ══════════════════════════════════════════════════════════════
    //  SMART App CRUD
    // ══════════════════════════════════════════════════════════════

    /**
     * Creates a new SMART app registration from the form submission.
     * Form fields: clientId, appName, redirectUri, allowedScopes, accessTokenTtlSeconds
     */
    @PostMapping("/apps/create")
    public String createApp(
            @RequestParam("clientId")            String clientId,
            @RequestParam("appName")             String appName,
            @RequestParam("redirectUri")         String redirectUri,
            @RequestParam("allowedScopes")       String allowedScopes,
            @RequestParam(value = "accessTokenTtlSeconds",
                          required = false)      String ttlStr,
            RedirectAttributes ra) {

        try {
            Long ttl = parseTtl(ttlStr);
            adminService.createApp(clientId.strip(), appName.strip(),
                                   redirectUri.strip(), allowedScopes.strip(), ttl);
            ra.addFlashAttribute("successMessage",
                    "App "" + appName.strip() + "" registered successfully.");
        } catch (IllegalArgumentException e) {
            ra.addFlashAttribute("errorMessage", e.getMessage());
        }
        return "redirect:/admin";
    }

    /**
     * Shows the edit form for an existing app.
     */
    @GetMapping("/apps/{id}/edit")
    public String editAppForm(@PathVariable String id, Model model,
                              RedirectAttributes ra) {
        RegisteredApp app = adminService.findApp(id)
                .orElse(null);
        if (app == null) {
            ra.addFlashAttribute("errorMessage", "App not found.");
            return "redirect:/admin";
        }
        model.addAttribute("editApp",    app);
        model.addAttribute("apps",       adminService.listApps());
        model.addAttribute("clinicians", adminService.listClinicians());
        model.addAttribute("activeTab",  "apps");
        return "admin";
    }

    /**
     * Saves changes to an existing app.
     */
    @PostMapping("/apps/{id}/update")
    public String updateApp(
            @PathVariable                              String id,
            @RequestParam("appName")                   String appName,
            @RequestParam("redirectUri")               String redirectUri,
            @RequestParam("allowedScopes")             String allowedScopes,
            @RequestParam(value = "accessTokenTtlSeconds",
                          required = false)            String ttlStr,
            @RequestParam(value = "active",
                          required = false,
                          defaultValue = "false")      boolean active,
            RedirectAttributes ra) {

        try {
            Long ttl = parseTtl(ttlStr);
            adminService.updateApp(id, appName.strip(), redirectUri.strip(),
                                   allowedScopes.strip(), ttl, active);
            ra.addFlashAttribute("successMessage",
                    "App "" + appName.strip() + "" updated.");
        } catch (IllegalArgumentException e) {
            ra.addFlashAttribute("errorMessage", e.getMessage());
        }
        return "redirect:/admin";
    }

    /**
     * Deletes a SMART app registration.
     */
    @PostMapping("/apps/{id}/delete")
    public String deleteApp(@PathVariable String id, RedirectAttributes ra) {
        try {
            String deletedName = adminService.deleteApp(id);
            ra.addFlashAttribute("successMessage",
                    "App “" + deletedName + "” deleted.");
        } catch (IllegalArgumentException e) {
            ra.addFlashAttribute("errorMessage", e.getMessage());
        }
        return "redirect:/admin";
    }

    // ══════════════════════════════════════════════════════════════
    //  Clinician CRUD
    // ══════════════════════════════════════════════════════════════

    /**
     * Creates a new clinician account.
     * Form fields: username, password, displayName, fhirUserId, role
     */
    @PostMapping("/clinicians/create")
    public String createClinician(
            @RequestParam("username")               String username,
            @RequestParam("password")               String password,
            @RequestParam(value = "displayName",
                          required = false,
                          defaultValue = "")        String displayName,
            @RequestParam(value = "fhirUserId",
                          required = false,
                          defaultValue = "")        String fhirUserId,
            @RequestParam(value = "role",
                          required = false,
                          defaultValue = "CLINICIAN") String role,
            RedirectAttributes ra) {

        try {
            adminService.createClinician(
                    username.strip(),
                    password,
                    displayName.isBlank() ? null : displayName.strip(),
                    fhirUserId.isBlank()  ? null : fhirUserId.strip(),
                    validateRole(role));
            ra.addFlashAttribute("successMessage",
                    "Clinician "" + username.strip() + "" created.");
        } catch (IllegalArgumentException e) {
            ra.addFlashAttribute("errorMessage", e.getMessage());
        }
        return "redirect:/admin/clinicians";
    }

    /**
     * Shows the edit form for a clinician.
     */
    @GetMapping("/clinicians/{id}/edit")
    public String editClinicianForm(@PathVariable String id, Model model,
                                    RedirectAttributes ra) {
        Clinician c = adminService.findClinician(id).orElse(null);
        if (c == null) {
            ra.addFlashAttribute("errorMessage", "Clinician not found.");
            return "redirect:/admin/clinicians";
        }
        model.addAttribute("editClinician", c);
        model.addAttribute("apps",          adminService.listApps());
        model.addAttribute("clinicians",    adminService.listClinicians());
        model.addAttribute("activeTab",     "clinicians");
        return "admin";
    }

    /**
     * Saves changes to a clinician.  Leave {@code password} blank to keep the
     * existing password.
     */
    @PostMapping("/clinicians/{id}/update")
    public String updateClinician(
            @PathVariable                              String id,
            @RequestParam(value = "password",
                          required = false,
                          defaultValue = "")           String password,
            @RequestParam(value = "displayName",
                          required = false,
                          defaultValue = "")           String displayName,
            @RequestParam(value = "fhirUserId",
                          required = false,
                          defaultValue = "")           String fhirUserId,
            @RequestParam(value = "enabled",
                          required = false,
                          defaultValue = "false")      boolean enabled,
            @RequestParam(value = "role",
                          required = false,
                          defaultValue = "CLINICIAN")  String role,
            RedirectAttributes ra) {

        try {
            adminService.updateClinician(
                    id,
                    password.isBlank() ? null : password,
                    displayName.isBlank() ? null : displayName.strip(),
                    fhirUserId.isBlank()  ? null : fhirUserId.strip(),
                    enabled,
                    validateRole(role));
            ra.addFlashAttribute("successMessage", "Clinician updated.");
        } catch (IllegalArgumentException e) {
            ra.addFlashAttribute("errorMessage", e.getMessage());
        }
        return "redirect:/admin/clinicians";
    }

    /**
     * Deletes a clinician account.
     */
    @PostMapping("/clinicians/{id}/delete")
    public String deleteClinician(@PathVariable String id, RedirectAttributes ra) {
        try {
            String deletedUsername = adminService.deleteClinician(id);
            ra.addFlashAttribute("successMessage",
                    "Clinician “" + deletedUsername + "” deleted.");
        } catch (IllegalArgumentException e) {
            ra.addFlashAttribute("errorMessage", e.getMessage());
        }
        return "redirect:/admin/clinicians";
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Valid role values — only these two are recognised by Spring Security. */
    private static final java.util.Set<String> VALID_ROLES =
            java.util.Set.of("CLINICIAN", "ADMIN");

    /**
     * Validates that {@code role} is one of the permitted values.
     *
     * @throws IllegalArgumentException for any other value, preventing arbitrary
     *         strings from being persisted to the {@code clinicians.role} column
     */
    private static String validateRole(String role) {
        String r = (role != null ? role.strip().toUpperCase() : "CLINICIAN");
        if (!VALID_ROLES.contains(r)) {
            throw new IllegalArgumentException(
                    "Invalid role '" + role + "' — must be CLINICIAN or ADMIN");
        }
        return r;
    }

    /**
     * Parses an optional TTL string to a Long.
     *
     * @throws IllegalArgumentException if the value is non-blank but not a valid
     *         positive integer — surfaced to the admin as a form error rather than
     *         silently falling back to the server default
     */
    private static Long parseTtl(String ttlStr) {
        if (ttlStr == null || ttlStr.isBlank()) return null;
        try {
            long v = Long.parseLong(ttlStr.strip());
            if (v <= 0) {
                throw new IllegalArgumentException(
                        "Access token TTL must be a positive number of seconds (got: " + ttlStr.strip() + ")");
            }
            return v;
        } catch (NumberFormatException e) {
            throw new IllegalArgumentException(
                    "Access token TTL must be a whole number of seconds (got: '" + ttlStr.strip() + "')");
        }
    }
}
