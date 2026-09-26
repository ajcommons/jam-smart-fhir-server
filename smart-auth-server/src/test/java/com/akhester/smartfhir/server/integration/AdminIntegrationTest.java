package com.akhester.smartfhir.server.integration;

import com.akhester.smartfhir.server.auth.AdminService;
import com.akhester.smartfhir.server.auth.Clinician;
import com.akhester.smartfhir.server.auth.RegisteredApp;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpSession;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.web.servlet.MvcResult;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Integration tests for the Admin UI and {@link AdminService}.
 *
 * <h3>What is tested</h3>
 * <ol>
 *   <li>ROLE_ADMIN gives access to /admin; ROLE_CLINICIAN is denied (403)</li>
 *   <li>Unauthenticated /admin redirects to /login</li>
 *   <li>Admin dashboard renders with app and clinician lists</li>
 *   <li>Creating a new SMART app via the form persists it</li>
 *   <li>Editing an app via the form updates it</li>
 *   <li>Deleting an app removes it</li>
 *   <li>Creating a clinician via the form persists it with BCrypt hash</li>
 *   <li>Creating a clinician with a duplicate username returns an error message</li>
 *   <li>Editing a clinician updates fields; blank password keeps existing hash</li>
 *   <li>Deleting a clinician removes it</li>
 *   <li>AdminService.createClinician with role=ADMIN grants ROLE_ADMIN authority</li>
 * </ol>
 */
@DisplayName("Admin UI and AdminService")
class AdminIntegrationTest extends SmartIntegrationTestBase {

    @Autowired
    private AdminService adminService;

    @Autowired
    private PasswordEncoder passwordEncoder;

    // ── 1. Access control ─────────────────────────────────────────────────────

    @Test
    @DisplayName("GET /admin without authentication redirects to /login")
    void admin_unauthenticated_redirectsToLogin() throws Exception {
        mockMvc.perform(get("/admin"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrlPattern("**/login**"));
    }

    @Test
    @DisplayName("GET /admin as ROLE_CLINICIAN returns 403")
    void admin_clinicianRole_forbidden() throws Exception {
        MockHttpSession session = loginAs(TEST_USERNAME, TEST_PASSWORD);

        mockMvc.perform(get("/admin").session(session))
                .andExpect(status().isForbidden());
    }

    @Test
    @DisplayName("GET /admin as ROLE_ADMIN returns 200 HTML")
    void admin_adminRole_ok() throws Exception {
        MockHttpSession session = loginAsAdmin();

        mockMvc.perform(get("/admin").session(session))
                .andExpect(status().isOk())
                .andExpect(content().contentTypeCompatibleWith(MediaType.TEXT_HTML));
    }

    // ── 2. Dashboard content ──────────────────────────────────────────────────

    @Test
    @DisplayName("Admin dashboard shows registered apps and clinicians")
    void adminDashboard_showsListsAndTabs() throws Exception {
        MockHttpSession session = loginAsAdmin();

        MvcResult result = mockMvc.perform(get("/admin").session(session))
                .andExpect(status().isOk())
                .andReturn();

        String body = result.getResponse().getContentAsString();
        assertThat(body).contains("Registered Apps");
        assertThat(body).contains("SMART Apps");
        assertThat(body).contains("Clinicians");
        // The seeded test app should appear in the table
        assertThat(body).contains(TEST_CLIENT_ID);
    }

    // ── 3. App create ─────────────────────────────────────────────────────────

    @Test
    @DisplayName("POST /admin/apps/create creates a new SMART app and shows success message")
    void createApp_validData_persistsAndFlashesSuccess() throws Exception {
        MockHttpSession session = loginAsAdmin();

        mockMvc.perform(post("/admin/apps/create")
                        .session(session)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("clientId",      "new-test-app")
                        .param("appName",       "New Test App")
                        .param("redirectUri",   "https://new-app.example.com/cb")
                        .param("allowedScopes", "openid launch"))
                .andExpect(status().is3xxRedirection())
                .andExpect(redirectedUrl("/admin"));

        // Verify persisted
        List<RegisteredApp> apps = adminService.listApps();
        assertThat(apps).anyMatch(a -> "new-test-app".equals(a.getClientId()));
    }

    @Test
    @DisplayName("POST /admin/apps/create with duplicate clientId shows error message")
    void createApp_duplicateClientId_flashesError() throws Exception {
        MockHttpSession session = loginAsAdmin();

        MvcResult result = mockMvc.perform(post("/admin/apps/create")
                        .session(session)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("clientId",      TEST_CLIENT_ID) // already seeded
                        .param("appName",       "Duplicate App")
                        .param("redirectUri",   "https://dup.example.com/cb")
                        .param("allowedScopes", "openid"))
                .andExpect(status().is3xxRedirection())
                .andReturn();

        // Follow redirect and check for error flash
        MvcResult page = mockMvc.perform(get("/admin").session(session))
                .andReturn();
        String body = page.getResponse().getContentAsString();
        assertThat(body).contains("already exists");
    }

    // ── 4. App edit ───────────────────────────────────────────────────────────

    @Test
    @DisplayName("GET /admin/apps/{id}/edit renders the edit form with current values")
    void editAppForm_rendersWithCurrentValues() throws Exception {
        MockHttpSession session = loginAsAdmin();
        String appId = adminService.listApps().stream()
                .filter(a -> TEST_CLIENT_ID.equals(a.getClientId()))
                .findFirst().orElseThrow().getId();

        MvcResult result = mockMvc.perform(
                        get("/admin/apps/" + appId + "/edit").session(session))
                .andExpect(status().isOk())
                .andReturn();

        String body = result.getResponse().getContentAsString();
        assertThat(body).contains(TEST_CLIENT_ID);
        assertThat(body).contains("Save Changes");
    }

    @Test
    @DisplayName("POST /admin/apps/{id}/update persists changes")
    void updateApp_persistsChanges() throws Exception {
        MockHttpSession session = loginAsAdmin();
        String appId = adminService.listApps().stream()
                .filter(a -> TEST_CLIENT_ID.equals(a.getClientId()))
                .findFirst().orElseThrow().getId();

        mockMvc.perform(post("/admin/apps/" + appId + "/update")
                        .session(session)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("appName",       "Updated App Name")
                        .param("redirectUri",   TEST_REDIRECT_URI)
                        .param("allowedScopes", "openid")
                        .param("active",        "true"))
                .andExpect(status().is3xxRedirection());

        RegisteredApp updated = adminService.listApps().stream()
                .filter(a -> TEST_CLIENT_ID.equals(a.getClientId()))
                .findFirst().orElseThrow();
        assertThat(updated.getAppName()).isEqualTo("Updated App Name");
    }

    // ── 5. App delete ─────────────────────────────────────────────────────────

    @Test
    @DisplayName("POST /admin/apps/{id}/delete removes the app")
    void deleteApp_removesApp() throws Exception {
        // Create a throwaway app first
        adminService.createApp("delete-me-app", "Delete Me",
                "https://del.example.com/cb", "openid", null);

        String appId = adminService.listApps().stream()
                .filter(a -> "delete-me-app".equals(a.getClientId()))
                .findFirst().orElseThrow().getId();

        MockHttpSession session = loginAsAdmin();

        mockMvc.perform(post("/admin/apps/" + appId + "/delete")
                        .session(session)
                        .with(csrf()))
                .andExpect(status().is3xxRedirection());

        assertThat(adminService.listApps())
                .noneMatch(a -> "delete-me-app".equals(a.getClientId()));
    }

    // ── 6. Clinician create ───────────────────────────────────────────────────

    @Test
    @DisplayName("POST /admin/clinicians/create creates a new clinician with hashed password")
    void createClinician_persistsWithHashedPassword() throws Exception {
        MockHttpSession session = loginAsAdmin();

        mockMvc.perform(post("/admin/clinicians/create")
                        .session(session)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("username",    "new.clinician")
                        .param("password",    "NewPass123!")
                        .param("displayName", "New Person")
                        .param("fhirUserId",  "Practitioner-NEW-001")
                        .param("role",        "CLINICIAN"))
                .andExpect(status().is3xxRedirection());

        Clinician created = adminService.listClinicians().stream()
                .filter(c -> "new.clinician".equals(c.getUsername()))
                .findFirst().orElseThrow();

        assertThat(created.getDisplayName()).isEqualTo("New Person");
        assertThat(created.getFhirUserId()).isEqualTo("Practitioner-NEW-001");
        // Password must be stored as BCrypt hash, not plain text
        assertThat(created.getPasswordHash()).startsWith("$2a$");
        assertThat(passwordEncoder.matches("NewPass123!", created.getPasswordHash())).isTrue();
    }

    @Test
    @DisplayName("POST /admin/clinicians/create with duplicate username flashes error")
    void createClinician_duplicateUsername_flashesError() throws Exception {
        MockHttpSession session = loginAsAdmin();

        mockMvc.perform(post("/admin/clinicians/create")
                        .session(session)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("username", TEST_USERNAME) // already seeded
                        .param("password", "AnyPass123!"))
                .andExpect(status().is3xxRedirection());

        MvcResult page = mockMvc.perform(get("/admin/clinicians").session(session))
                .andReturn();
        assertThat(page.getResponse().getContentAsString()).contains("already exists");
    }

    // ── 7. Clinician edit ─────────────────────────────────────────────────────

    @Test
    @DisplayName("POST /admin/clinicians/{id}/update with blank password keeps existing hash")
    void updateClinician_blankPassword_keepsExistingHash() throws Exception {
        MockHttpSession session = loginAsAdmin();
        Clinician c = adminService.listClinicians().stream()
                .filter(x -> TEST_USERNAME.equals(x.getUsername()))
                .findFirst().orElseThrow();
        String originalHash = c.getPasswordHash();

        mockMvc.perform(post("/admin/clinicians/" + c.getId() + "/update")
                        .session(session)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("password",    "")          // blank → keep
                        .param("displayName", "Updated Name")
                        .param("enabled",     "true")
                        .param("role",        "CLINICIAN"))
                .andExpect(status().is3xxRedirection());

        Clinician updated = adminService.findClinician(c.getId()).orElseThrow();
        assertThat(updated.getDisplayName()).isEqualTo("Updated Name");
        assertThat(updated.getPasswordHash()).isEqualTo(originalHash);
    }

    // ── 8. Clinician delete ───────────────────────────────────────────────────

    @Test
    @DisplayName("POST /admin/clinicians/{id}/delete removes the clinician")
    void deleteClinician_removesAccount() throws Exception {
        // Create a throwaway clinician
        Clinician throwaway = adminService.createClinician(
                "delete.me", "Pass123!", "Delete Me", null, "CLINICIAN");

        MockHttpSession session = loginAsAdmin();
        mockMvc.perform(post("/admin/clinicians/" + throwaway.getId() + "/delete")
                        .session(session)
                        .with(csrf()))
                .andExpect(status().is3xxRedirection());

        assertThat(adminService.listClinicians())
                .noneMatch(c -> "delete.me".equals(c.getUsername()));
    }

    // ── 9. ROLE_ADMIN authority from role field ───────────────────────────────

    @Test
    @DisplayName("Clinician created with role=ADMIN gets ROLE_ADMIN authority in UserDetails")
    void adminRole_grantsAdminAuthority() {
        Clinician admin = adminService.createClinician(
                "new.admin", "Admin123!", "Admin User", null, "ADMIN");

        assertThat(admin.getRole()).isEqualTo("ADMIN");

        com.akhester.smartfhir.server.auth.ClinicianUserDetails details =
                new com.akhester.smartfhir.server.auth.ClinicianUserDetails(admin);
        assertThat(details.getAuthorities())
                .extracting(a -> a.getAuthority())
                .contains("ROLE_ADMIN", "ROLE_CLINICIAN");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Logs in the given user and returns an authenticated session. */
    private MockHttpSession loginAs(String username, String password) throws Exception {
        MockHttpSession session = new MockHttpSession();
        mockMvc.perform(get("/login").session(session));
        MvcResult r = mockMvc.perform(post("/login")
                        .session(session)
                        .with(csrf())
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("username", username)
                        .param("password", password))
                .andReturn();
        String redirect = r.getResponse().getRedirectedUrl();
        if (redirect != null && !redirect.isEmpty()) {
            mockMvc.perform(get(redirect).session(session));
        }
        return session;
    }

    /**
     * Creates a fresh ROLE_ADMIN clinician, logs in as them, and returns the session.
     * Uses a unique username per test to avoid conflicts with the seeded TEST_USERNAME.
     */
    private MockHttpSession loginAsAdmin() throws Exception {
        String adminUser = "admin." + System.nanoTime();
        adminService.createClinician(adminUser, "Admin123!", "Test Admin", null, "ADMIN");
        return loginAs(adminUser, "Admin123!");
    }
}
