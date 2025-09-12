package com.akhester.smartfhir.server.auth;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.List;

/**
 * CORS policy for browser-based SMART clients.
 *
 * Two tiers:
 *   public  — discovery ({@code /.well-known/smart-configuration}) and JWKS:
 *             any origin, GET only, no credentials
 *   token   — {@code /oauth2/token|revoke|introspect}: configured origins only,
 *             credentials allowed (set {@code smart.server.cors.allowed-origins})
 */
@Configuration
public class CorsConfig {

    /**
     * Allowed origins for CORS. Defaults to localhost:8081 for local dev.
     * Override in production via {@code smart.server.cors.allowed-origins}.
     */
    @Value("${smart.server.cors.allowed-origins:http://localhost:8081,http://localhost:3000}")
    private List<String> allowedOrigins;

    /**
     * Global CORS configuration source — consumed by both Spring Security
     * filter chains via {@code http.cors(c -> c.configurationSource(corsConfigurationSource()))}.
     *
     * <p>Endpoint-specific rules:
     * <ul>
     *   <li>{@code /.well-known/smart-configuration} and {@code /oauth2/jwks} —
     *       fully public, any origin may fetch these (wildcard). JWKS is needed
     *       by resource servers and clients on any origin for token verification.</li>
     *   <li>{@code /oauth2/token}, {@code /oauth2/revoke}, {@code /oauth2/introspect} —
     *       restricted to configured allowed origins.</li>
     *   <li>{@code /portal}, {@code /login} — browser-native navigation, CORS
     *       not normally triggered, but configured for completeness.</li>
     * </ul>
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();

        // ── Public endpoints — any origin may read ────────────────────────────
        // Discovery and JWKS are public metadata. Any SMART client or resource
        // server must be able to fetch these regardless of origin.
        CorsConfiguration publicConfig = new CorsConfiguration();
        publicConfig.setAllowedOriginPatterns(List.of("*"));
        publicConfig.setAllowedMethods(List.of("GET", "OPTIONS"));
        publicConfig.setAllowedHeaders(List.of("*"));
        publicConfig.setMaxAge(3600L);

        source.registerCorsConfiguration("/.well-known/smart-configuration", publicConfig);
        source.registerCorsConfiguration("/oauth2/jwks", publicConfig);
        source.registerCorsConfiguration("/actuator/health", publicConfig);

        // ── Token / auth endpoints — restricted to configured origins ─────────
        // POST /oauth2/token, /oauth2/revoke, /oauth2/introspect are called
        // by browser SMART clients. Allow only the configured app origins.
        CorsConfiguration tokenConfig = new CorsConfiguration();
        tokenConfig.setAllowedOrigins(allowedOrigins);
        tokenConfig.setAllowedMethods(List.of("GET", "POST", "OPTIONS"));
        tokenConfig.setAllowedHeaders(List.of(
                "Authorization",
                "Content-Type",
                "Accept",
                "Cache-Control",
                "X-Requested-With"
        ));
        // NOTE: do NOT expose the Authorization response header — tokens are returned
        // in the JSON body, never in a response header. Exposing it adds no benefit
        // and broadens the surface visible to browser JavaScript.
        tokenConfig.setAllowCredentials(true);
        tokenConfig.setMaxAge(3600L);

        source.registerCorsConfiguration("/oauth2/token", tokenConfig);
        source.registerCorsConfiguration("/oauth2/authorize", tokenConfig);
        source.registerCorsConfiguration("/oauth2/revoke", tokenConfig);
        source.registerCorsConfiguration("/oauth2/introspect", tokenConfig);

        // ── Portal / login — same origin typically, but allow configured origins
        source.registerCorsConfiguration("/portal/**", tokenConfig);
        source.registerCorsConfiguration("/login", tokenConfig);

        return source;
    }
}
