package com.akhester.smartfhir.server.auth;

import jakarta.persistence.*;
import java.util.List;

/**
 * JPA entity for a registered SMART client application, mapped to a Spring
 * Authorization Server {@link org.springframework.security.oauth2.server.authorization.client.RegisteredClient}
 * by {@link JpaRegisteredClientRepository}. Apps are managed via the admin UI or
 * seeded by {@link DataInitializer}.
 */
@Entity
@Table(name = "registered_apps")
public class RegisteredApp {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private String id;

    /** The OAuth2 client_id — what apps send in authorize/token requests. */
    @Column(nullable = false, unique = true)
    private String clientId;

    /** Human-readable name displayed in the patient picker. */
    @Column(nullable = false)
    private String appName;

    /** URL the auth server redirects to after authorization. */
    @Column(nullable = false)
    private String redirectUri;

    /**
     * Comma-separated SMART scopes this app is allowed to request.
     * Epic equivalent: the scopes registered in App Orchard.
     */
    @Column(nullable = false, length = 1000)
    private String allowedScopes;

    /** Access token TTL in seconds. Defaults to server-wide setting if null. */
    @Column
    private Long accessTokenTtlSeconds;

    /** Whether this app registration is active. */
    @Column(nullable = false)
    private boolean active = true;

    protected RegisteredApp() {}

    public RegisteredApp(String clientId, String appName,
                         String redirectUri, String allowedScopes) {
        this.clientId      = clientId;
        this.appName       = appName;
        this.redirectUri   = redirectUri;
        this.allowedScopes = allowedScopes;
    }

    public String  getId()                   { return id; }
    public String  getClientId()             { return clientId; }
    public String  getAppName()              { return appName; }
    public String  getRedirectUri()          { return redirectUri; }
    public String  getAllowedScopes()        { return allowedScopes; }
    public Long    getAccessTokenTtlSeconds(){ return accessTokenTtlSeconds; }
    public boolean isActive()               { return active; }

    public List<String> allowedScopeList() {
        return List.of(allowedScopes.split(",\\s*"));
    }

    // ── Mutators used by JpaRegisteredClientRepository.save() ─────────────────
    // Package-private: only JpaRegisteredClientRepository (same package) may call these.
    // Use RegisteredAppRepository to persist the result after calling a setter.

    void setAppName(String appName)                         { this.appName = appName; }
    void setRedirectUri(String redirectUri)                 { this.redirectUri = redirectUri; }
    void setAllowedScopes(String allowedScopes)             { this.allowedScopes = allowedScopes; }
    void setAccessTokenTtlSeconds(Long accessTokenTtlSeconds) { this.accessTokenTtlSeconds = accessTokenTtlSeconds; }
    void setActive(boolean active)                          { this.active = active; }
}
