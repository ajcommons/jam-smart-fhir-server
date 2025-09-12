package com.akhester.smartfhir.server.auth;

import com.akhester.smartfhir.server.SmartServerProperties;
import com.akhester.smartfhir.server.launch.StandalonePatientPickerFilter;
import com.akhester.smartfhir.server.security.LoginLockoutFilter;
import com.akhester.smartfhir.server.security.SmartAuthenticationFailureHandler;
import com.akhester.smartfhir.server.security.SmartAuthenticationSuccessHandler;
import com.akhester.smartfhir.server.security.TokenEndpointRateLimitFilter;
import com.akhester.smartfhir.server.token.SmartTokenCustomizer;
import com.akhester.smartfhir.server.token.SmartTokenResponseConverter;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.core.env.Environment;
import org.springframework.web.filter.ForwardedHeaderFilter;
import org.springframework.core.env.Profiles;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.web.cors.CorsConfigurationSource;

@Configuration
public class AuthorizationServerConfig {

    private final SmartServerProperties              serverProperties;
    private final SmartTokenCustomizer               tokenCustomizer;
    private final SmartTokenResponseConverter        tokenResponseConverter;
    private final Environment                        environment;
    private final CorsConfigurationSource            corsConfigurationSource;
    private final TokenEndpointRateLimitFilter       tokenRateLimitFilter;
    private final LoginLockoutFilter                 loginLockoutFilter;
    private final SmartAuthenticationFailureHandler  authFailureHandler;
    private final SmartAuthenticationSuccessHandler  authSuccessHandler;
    private final StandalonePatientPickerFilter      standalonePickerFilter;

    public AuthorizationServerConfig(
            SmartServerProperties             serverProperties,
            SmartTokenCustomizer              tokenCustomizer,
            SmartTokenResponseConverter       tokenResponseConverter,
            Environment                       environment,
            CorsConfigurationSource           corsConfigurationSource,
            TokenEndpointRateLimitFilter      tokenRateLimitFilter,
            LoginLockoutFilter                loginLockoutFilter,
            SmartAuthenticationFailureHandler authFailureHandler,
            SmartAuthenticationSuccessHandler authSuccessHandler,
            StandalonePatientPickerFilter     standalonePickerFilter) {

        this.serverProperties        = serverProperties;
        this.tokenCustomizer         = tokenCustomizer;
        this.tokenResponseConverter  = tokenResponseConverter;
        this.environment             = environment;
        this.corsConfigurationSource = corsConfigurationSource;
        this.tokenRateLimitFilter    = tokenRateLimitFilter;
        this.loginLockoutFilter      = loginLockoutFilter;
        this.authFailureHandler      = authFailureHandler;
        this.authSuccessHandler      = authSuccessHandler;
        this.standalonePickerFilter  = standalonePickerFilter;
    }

    // ── Order 1: OAuth2 / OIDC Authorization Server filter chain ─────────────
    //
    // Restricted to the AS endpoint set only (getEndpointsMatcher).
    // /login, /portal, /error etc. fall through to Order 2.
    //
    @Bean
    @Order(1)
    public SecurityFilterChain authorizationServerSecurityFilterChain(
            HttpSecurity http) throws Exception {

        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                new OAuth2AuthorizationServerConfigurer();

        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())

                // ── CORS: defined origins for token / authorization endpoints ──
                .cors(cors -> cors.configurationSource(corsConfigurationSource))

                .with(authorizationServerConfigurer, configurer -> configurer
                        .oidc(Customizer.withDefaults())
                        .authorizationEndpoint(endpoint -> endpoint
                                // Custom consent page — Spring AS redirects here when
                                // requireAuthorizationConsent=true and no prior consent exists.
                                .consentPage("/oauth2/consent")
                        )
                        .tokenEndpoint(token -> token
                                .accessTokenResponseHandler(tokenResponseConverter)
                        )
                )
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .exceptionHandling(ex -> ex
                        .defaultAuthenticationEntryPointFor(
                                new LoginUrlAuthenticationEntryPoint(
                                        isIdpProfileActive() ? "/oauth2/authorization/idp" : "/login"),
                                new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                        )
                )
                .oauth2ResourceServer(rs -> rs.jwt(Customizer.withDefaults()))

                // ── Rate limit: per-IP token bucket on /oauth2/token etc. ──────
                // Runs before Spring Security authentication filters so malicious
                // burst traffic is dropped before any credential verification.
                .addFilterBefore(tokenRateLimitFilter, UsernamePasswordAuthenticationFilter.class)

                // ── Standalone launch intercept ────────────────────────────────
                // Detects GET /oauth2/authorize with launch/patient scope but no
                // launch token, saves the request to session, and redirects to
                // the standalone patient picker. Runs before the AS authorize
                // endpoint filter so Spring AS never sees an incomplete request.
                .addFilterBefore(standalonePickerFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // ── Order 2: form-login / default security chain (local auth only) ────────
    //
    // Active only when the 'idp' profile is NOT set.
    // Handles /login, /portal, /error, /logout and the SMART discovery/JWKS URLs.
    //
    @Bean
    @Order(2)
    @org.springframework.context.annotation.Profile("!idp")
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http)
            throws Exception {

        http
                // ── CORS: same source bean (covers /login, /portal etc.) ───────
                .cors(cors -> cors.configurationSource(corsConfigurationSource))

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/.well-known/smart-configuration",
                                "/oauth2/jwks",
                                "/actuator/health",
                                "/login",
                                "/logout",
                                "/error"
                                // Note: /h2-console is NOT permitted here.
                                // H2 console access is configured in DevSecurityConfig
                                // which is only active under the 'dev' profile.
                        ).permitAll()
                        // Consent page — must be authenticated (Spring AS redirects here
                        // after the authorize request; clinician is already logged in).
                        .requestMatchers("/oauth2/consent").authenticated()
                        // Admin UI — restricted to ROLE_ADMIN only.
                        .requestMatchers("/admin", "/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .formLogin(form -> form
                        .loginPage("/login")
                        // ── Login lockout + brute-force protection ──────────────
                        // successHandler: clears the IP's failure counter on login
                        // failureHandler: records failures; redirects to ?locked
                        //   after 5 consecutive failures from the same IP
                        .successHandler(authSuccessHandler)
                        .failureHandler(authFailureHandler)
                )

                // ── Lockout pre-check: reject POST /login from locked IPs ───────
                // Runs before UsernamePasswordAuthenticationFilter so BCrypt
                // is never called for a locked-out IP (saves ~100ms/request).
                .addFilterBefore(loginLockoutFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }

    // ── Infrastructure beans ──────────────────────────────────────────────────

    /**
     * JDBC-backed authorization service (prod/idp profiles).
     * Persists auth codes, access tokens, and refresh tokens across restarts and instances.
     * Schema: {@code V2__oauth2_authorization_tables.sql}. Expired rows are purged by
     * {@link com.akhester.smartfhir.server.maintenance.TokenCleanupJob}.
     */
    @Bean
    @org.springframework.context.annotation.Profile("!dev")
    public OAuth2AuthorizationService authorizationService(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationService(jdbcTemplate, registeredClientRepository);
    }

    /**
     * Dev-only in-memory authorization service — no database required.
     * Replaced by the JDBC variant in prod and idp profiles.
     */
    @Bean
    @org.springframework.context.annotation.Profile("dev")
    public OAuth2AuthorizationService authorizationServiceDev() {
        return new org.springframework.security.oauth2.server.authorization
                .InMemoryOAuth2AuthorizationService();
    }

    /**
     * Stores consent decisions (which scopes a clinician approved for a given app).
     * JDBC-backed in prod so consent survives restarts — clinicians are not
     * re-prompted on every SMART launch.
     *
     * REQUIRED even when requireAuthorizationConsent(false) — throws NPE without it.
     */
    @Bean
    @org.springframework.context.annotation.Profile("!dev")
    public OAuth2AuthorizationConsentService authorizationConsentService(
            JdbcTemplate jdbcTemplate,
            RegisteredClientRepository registeredClientRepository) {
        return new JdbcOAuth2AuthorizationConsentService(jdbcTemplate, registeredClientRepository);
    }

    /**
     * Dev-only in-memory consent service.
     */
    @Bean
    @org.springframework.context.annotation.Profile("dev")
    public OAuth2AuthorizationConsentService authorizationConsentServiceDev() {
        return new org.springframework.security.oauth2.server.authorization
                .InMemoryOAuth2AuthorizationConsentService();
    }

    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer(serverProperties.issuerUrl())
                .authorizationEndpoint("/oauth2/authorize")
                .tokenEndpoint("/oauth2/token")
                .jwkSetEndpoint("/oauth2/jwks")
                .tokenRevocationEndpoint("/oauth2/revoke")
                .tokenIntrospectionEndpoint("/oauth2/introspect")
                .build();
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * Highest-priority servlet filter: normalises {@code RemoteAddr} from
     * {@code X-Forwarded-For} before any application filter runs, then removes
     * the raw XFF header so downstream code cannot see it.
     *
     * Security: rate-limit and login-lockout filters call {@code getRemoteAddr()}
     * safely because this filter has already resolved it. Without this, clients
     * behind a proxy could spoof their IP by crafting the XFF header directly.
     * Must only be deployed behind a trusted reverse proxy (nginx, ALB).
     */
    @Bean
    public jakarta.servlet.Filter forwardedHeaderFilter() {
        return new ForwardedHeaderFilter();
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    /**
     * Checks whether the {@code idp} Spring profile is currently active.
     * Uses Spring's {@link Environment} — reliable at bean construction time.
     */
    private boolean isIdpProfileActive() {
        return environment.acceptsProfiles(Profiles.of("idp"));
    }
}
