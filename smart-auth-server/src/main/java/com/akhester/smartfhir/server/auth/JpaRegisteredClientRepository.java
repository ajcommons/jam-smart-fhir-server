package com.akhester.smartfhir.server.auth;

import com.akhester.smartfhir.server.SmartServerProperties;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.time.Duration;
import java.util.stream.Collectors;

/**
 * JPA-backed {@link RegisteredClientRepository} that reads app registrations from
 * the {@code registered_apps} table, allowing apps to be added or disabled at
 * runtime without a server restart. Converts {@link RegisteredApp} entities to
 * Spring's {@link RegisteredClient}, applying server-wide PKCE and token TTL defaults.
 */
@Component
public class JpaRegisteredClientRepository implements RegisteredClientRepository {

    private final RegisteredAppRepository appRepository;
    private final SmartServerProperties serverProperties;

    public JpaRegisteredClientRepository(RegisteredAppRepository appRepository,
                                          SmartServerProperties serverProperties) {
        this.appRepository    = appRepository;
        this.serverProperties = serverProperties;
    }

    private static final org.slf4j.Logger log =
            org.slf4j.LoggerFactory.getLogger(JpaRegisteredClientRepository.class);

    /**
     * Upserts a {@link RegisteredClient} as a {@link RegisteredApp} row (idempotent).
     *
     * Note: {@link RegisteredApp} stores a single {@code redirectUri}; when multiple
     * URIs are present on the {@link RegisteredClient}, only the first is persisted.
     */
    @Override
    @Transactional
    public void save(RegisteredClient registeredClient) {
        RegisteredApp existing = appRepository
                .findByClientId(registeredClient.getClientId())
                .orElse(null);

        if (existing != null) {
            // Update the mutable fields — id and clientId are immutable
            updateFromRegisteredClient(existing, registeredClient);
            appRepository.save(existing);
            log.debug("Updated RegisteredApp for client_id='{}'",
                    registeredClient.getClientId());
        } else {
            RegisteredApp app = toRegisteredApp(registeredClient);
            appRepository.save(app);
            log.info("Inserted new RegisteredApp for client_id='{}'",
                    registeredClient.getClientId());
        }
    }

    @Override
    public RegisteredClient findById(String id) {
        return appRepository.findById(id)
                .filter(RegisteredApp::isActive)
                .map(this::toRegisteredClient)
                .orElse(null);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        return appRepository.findByClientId(clientId)
                .filter(RegisteredApp::isActive)
                .map(this::toRegisteredClient)
                .orElse(null);
    }

    // ── private helpers ───────────────────────────────────────────────────────

    /**
     * Creates a new {@link RegisteredApp} from a Spring {@link RegisteredClient}.
     * Used by {@link #save(RegisteredClient)} when no existing row is found.
     *
     * <p>Multiple redirect URIs: Spring AS supports many; RegisteredApp stores one.
     * The first URI is used. Add a V3 migration if multi-URI support is needed.
     */
    private RegisteredApp toRegisteredApp(RegisteredClient rc) {
        if (rc.getRedirectUris().size() > 1) {
            log.warn("Client '{}' has {} redirect URIs but RegisteredApp only stores one. " +
                     "Only '{}' will be persisted. Add a V3 migration with a redirect_uris column " +
                     "if multiple URIs are needed.",
                    rc.getClientId(),
                    rc.getRedirectUris().size(),
                    rc.getRedirectUris().iterator().next());
        }

        String redirectUri = rc.getRedirectUris().stream()
                .findFirst()
                .orElseThrow(() -> new IllegalArgumentException(
                        "RegisteredClient has no redirect URIs: " + rc.getClientId()));

        String scopes = rc.getScopes().stream()
                .sorted()
                .collect(Collectors.joining(", "));

        Long ttlSeconds = null;
        if (rc.getTokenSettings() != null) {
            long ttl = rc.getTokenSettings().getAccessTokenTimeToLive().getSeconds();
            if (ttl != serverProperties.accessTokenTtlSeconds()) {
                ttlSeconds = ttl; // only store if different from server default
            }
        }

        RegisteredApp app = new RegisteredApp(
                rc.getClientId(),
                rc.getClientName() != null ? rc.getClientName() : rc.getClientId(),
                redirectUri,
                scopes
        );
        if (ttlSeconds != null) {
            app.setAccessTokenTtlSeconds(ttlSeconds);
        }
        return app;
    }

    /**
     * Updates mutable fields on an existing {@link RegisteredApp} from a
     * {@link RegisteredClient}. Called by {@link #save(RegisteredClient)} when
     * a row with the same {@code clientId} already exists.
     */
    private void updateFromRegisteredClient(RegisteredApp existing, RegisteredClient rc) {
        if (rc.getClientName() != null) {
            existing.setAppName(rc.getClientName());
        }

        if (rc.getRedirectUris().size() > 1) {
            log.warn("Client '{}' has {} redirect URIs but RegisteredApp only stores one — " +
                     "only the first will be retained on update.",
                    rc.getClientId(), rc.getRedirectUris().size());
        }
        rc.getRedirectUris().stream()
                .findFirst()
                .ifPresent(existing::setRedirectUri);

        if (!rc.getScopes().isEmpty()) {
            existing.setAllowedScopes(
                    rc.getScopes().stream().sorted().collect(Collectors.joining(", ")));
        }

        if (rc.getTokenSettings() != null) {
            long ttl = rc.getTokenSettings().getAccessTokenTimeToLive().getSeconds();
            existing.setAccessTokenTtlSeconds(
                    ttl != serverProperties.accessTokenTtlSeconds() ? ttl : null);
        }
    }

    /**
     * Converts a {@link RegisteredApp} JPA entity to a Spring
     * {@link RegisteredClient}.
     *
     * Every client:
     * - Uses authorization_code grant
     * - Supports refresh_token grant
     * - Is a public client (no secret) — PKCE required
     * - Has PKCE enforced via requireProofKey(true)
     */
    private RegisteredClient toRegisteredClient(RegisteredApp app) {
        long ttl = app.getAccessTokenTtlSeconds() != null
                ? app.getAccessTokenTtlSeconds()
                : serverProperties.accessTokenTtlSeconds();

        RegisteredClient.Builder builder = RegisteredClient
                .withId(app.getId())
                .clientId(app.getClientId())
                .clientName(app.getAppName() != null ? app.getAppName() : app.getClientId())
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE) // public client
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri(app.getRedirectUri())
                .tokenSettings(TokenSettings.builder()
                        .accessTokenTimeToLive(Duration.ofSeconds(ttl))
                        .refreshTokenTimeToLive(
                                Duration.ofSeconds(serverProperties.refreshTokenTtlSeconds()))
                        .reuseRefreshTokens(false) // rotate refresh tokens
                        .build())
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(true)             // PKCE S256 required
                        .requireAuthorizationConsent(true) // show consent page on first launch
                        .build());

        // Add all allowed scopes
        for (String scope : app.allowedScopeList()) {
            builder.scope(scope.trim());
        }

        return builder.build();
    }
}
