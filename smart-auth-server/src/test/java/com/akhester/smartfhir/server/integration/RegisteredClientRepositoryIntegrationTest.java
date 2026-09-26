package com.akhester.smartfhir.server.integration;

import com.akhester.smartfhir.server.auth.RegisteredApp;
import com.akhester.smartfhir.server.auth.RegisteredAppRepository;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration tests for {@link com.akhester.smartfhir.server.auth.JpaRegisteredClientRepository}.
 *
 * <h3>What is tested</h3>
 * <ol>
 *   <li>{@code save()} inserts a new {@link RegisteredApp} when no row exists</li>
 *   <li>{@code save()} updates an existing row (upsert — no duplicate)</li>
 *   <li>{@code findByClientId()} returns the saved client</li>
 *   <li>{@code findById()} returns the saved client by JPA UUID</li>
 *   <li>Inactive apps ({@code active=false}) are not returned by find methods</li>
 *   <li>Custom access-token TTL is persisted and round-tripped</li>
 *   <li>PKCE requirement and no-consent flag survive the round trip</li>
 * </ol>
 *
 * <h3>Why this matters</h3>
 * Before this fix, {@code save()} was a no-op with a warning. Spring Authorization
 * Server calls {@code save()} when a dynamically-registered client changes, and
 * downstream code (admin API, future consent UI) may also call it. A silent no-op
 * causes invisible data loss.
 */
@DisplayName("JpaRegisteredClientRepository.save() persistence")
class RegisteredClientRepositoryIntegrationTest extends SmartIntegrationTestBase {

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Autowired
    private RegisteredAppRepository registeredAppRepository;

    // ── 1. Insert via save() ──────────────────────────────────────────────────

    @Test
    @DisplayName("save() inserts a new row when no existing app has the same client_id")
    void save_newClient_persistsRow() {
        RegisteredClient client = buildTestClient("new-app-001", "http://localhost:9001/cb");

        registeredClientRepository.save(client);

        Optional<RegisteredApp> found = registeredAppRepository.findByClientId("new-app-001");
        assertThat(found).isPresent();
        assertThat(found.get().getClientId()).isEqualTo("new-app-001");
        assertThat(found.get().getRedirectUri()).isEqualTo("http://localhost:9001/cb");
        assertThat(found.get().isActive()).isTrue();
    }

    @Test
    @DisplayName("save() only inserts one row — not a duplicate — for the same client_id")
    void save_sameClientIdTwice_nosDuplicate() {
        RegisteredClient client = buildTestClient("dedup-app", "http://localhost:9002/cb");

        registeredClientRepository.save(client);
        registeredClientRepository.save(client); // second call must be an update, not an insert

        long count = registeredAppRepository.findAll().stream()
                .filter(a -> a.getClientId().equals("dedup-app"))
                .count();
        assertThat(count).isEqualTo(1);
    }

    // ── 2. Update via save() ──────────────────────────────────────────────────

    @Test
    @DisplayName("save() updates redirect_uri on an existing row")
    void save_existingClient_updatesRedirectUri() {
        // Insert initial row via DataInitializer's seeded app (TEST_CLIENT_ID already exists
        // from SmartIntegrationTestBase.@BeforeEach). Build a RegisteredClient that matches it.
        RegisteredClient initial = buildTestClient(TEST_CLIENT_ID, TEST_REDIRECT_URI);
        registeredClientRepository.save(initial);

        // Now save an updated version with a different redirect URI
        RegisteredClient updated = RegisteredClient.withId(initial.getId())
                .clientId(TEST_CLIENT_ID)
                .clientName("Updated App Name")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:9999/new-callback")
                .scope("openid")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofSeconds(3600))
                        .reuseRefreshTokens(false)
                        .build())
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(false)
                        .build())
                .build();

        registeredClientRepository.save(updated);

        Optional<RegisteredApp> found = registeredAppRepository.findByClientId(TEST_CLIENT_ID);
        assertThat(found).isPresent();
        assertThat(found.get().getRedirectUri()).isEqualTo("http://localhost:9999/new-callback");
        assertThat(found.get().getAppName()).isEqualTo("Updated App Name");
    }

    // ── 3. findByClientId round-trip ──────────────────────────────────────────

    @Test
    @DisplayName("findByClientId returns the saved RegisteredClient with correct properties")
    void findByClientId_returnsSavedClient() {
        RegisteredClient saved = buildTestClient("find-by-cid-app", "http://localhost:9003/cb");
        registeredClientRepository.save(saved);

        RegisteredClient found = registeredClientRepository.findByClientId("find-by-cid-app");

        assertThat(found).isNotNull();
        assertThat(found.getClientId()).isEqualTo("find-by-cid-app");
        assertThat(found.getRedirectUris()).contains("http://localhost:9003/cb");
        assertThat(found.getAuthorizationGrantTypes())
                .contains(AuthorizationGrantType.AUTHORIZATION_CODE);
        assertThat(found.getAuthorizationGrantTypes())
                .contains(AuthorizationGrantType.REFRESH_TOKEN);
        // PKCE must survive the round-trip
        assertThat(found.getClientSettings().isRequireProofKey()).isTrue();
    }

    // ── 4. findById round-trip ────────────────────────────────────────────────

    @Test
    @DisplayName("findById returns the saved RegisteredClient")
    void findById_returnsSavedClient() {
        RegisteredClient saved = buildTestClient("find-by-id-app", "http://localhost:9004/cb");
        registeredClientRepository.save(saved);

        // Look up the persisted app's JPA UUID (assigned by the DB)
        RegisteredApp app = registeredAppRepository.findByClientId("find-by-id-app").orElseThrow();

        RegisteredClient found = registeredClientRepository.findById(app.getId());
        assertThat(found).isNotNull();
        assertThat(found.getClientId()).isEqualTo("find-by-id-app");
    }

    // ── 5. Inactive apps are filtered out ────────────────────────────────────

    @Test
    @DisplayName("Inactive RegisteredApp is not returned by findByClientId")
    void findByClientId_inactiveApp_returnsNull() {
        // Seed an active app then disable it directly via the repository
        RegisteredClient client = buildTestClient("inactive-app", "http://localhost:9005/cb");
        registeredClientRepository.save(client);

        RegisteredApp app = registeredAppRepository.findByClientId("inactive-app").orElseThrow();
        app.setActive(false);
        registeredAppRepository.save(app);

        RegisteredClient found = registeredClientRepository.findByClientId("inactive-app");
        assertThat(found)
                .as("Disabled app must not be returned — prevents disabled apps from authorizing")
                .isNull();
    }

    // ── 6. Custom TTL round-trip ──────────────────────────────────────────────

    @Test
    @DisplayName("Custom access-token TTL is persisted and returned in TokenSettings")
    void save_customTtl_roundTrips() {
        RegisteredClient client = RegisteredClient
                .withId("custom-ttl-id")
                .clientId("custom-ttl-app")
                .clientName("Custom TTL App")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .redirectUri("http://localhost:9006/cb")
                .scope("openid")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofSeconds(600)) // 10 min — not the default
                        .reuseRefreshTokens(false)
                        .build())
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(false)
                        .build())
                .build();

        registeredClientRepository.save(client);

        RegisteredClient found = registeredClientRepository.findByClientId("custom-ttl-app");
        assertThat(found).isNotNull();
        assertThat(found.getTokenSettings().getAccessTokenTimeToLive())
                .isEqualTo(Duration.ofSeconds(600));
    }

    // ── Helper ────────────────────────────────────────────────────────────────

    /**
     * Builds a minimal valid {@link RegisteredClient} for testing.
     * Uses {@code clientId} as the Spring AS UUID as well (fine for tests).
     */
    private RegisteredClient buildTestClient(String clientId, String redirectUri) {
        return RegisteredClient
                .withId(clientId + "-id")
                .clientId(clientId)
                .clientName(clientId + " Test App")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri(redirectUri)
                .scope("openid")
                .scope("patient/Patient.rs")
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofSeconds(3600))
                        .refreshTokenTimeToLive(Duration.ofDays(1))
                        .reuseRefreshTokens(false)
                        .build())
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)
                        .requireAuthorizationConsent(false)
                        .build())
                .build();
    }
}
