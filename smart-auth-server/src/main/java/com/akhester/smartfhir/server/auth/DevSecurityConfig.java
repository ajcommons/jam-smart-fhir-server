package com.akhester.smartfhir.server.auth;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Dev-only security filter chain (Order 3) that permits {@code /h2-console/**},
 * relaxes frame options for the H2 iframe, and disables CSRF for H2 form posts.
 * Intentionally excluded from production — kept in a dedicated {@code @Configuration}
 * so the {@code @Profile("dev")} guard is unambiguous and cannot be accidentally
 * activated by a stray bean in the shared config.
 */
@Configuration
@Profile("dev")
public class DevSecurityConfig {

    /**
     * Permits the H2 console path and disables frame options + CSRF for it.
     * Order 3 — runs after the two production filter chains.
     */
    @Bean
    @Order(3)
    public SecurityFilterChain h2ConsoleSecurityFilterChain(HttpSecurity http)
            throws Exception {

        http
                .securityMatcher("/h2-console/**")
                .authorizeHttpRequests(auth -> auth
                        .anyRequest().permitAll()
                )
                // H2 console uses iframes — allow same-origin framing in dev only
                .headers(h -> h.frameOptions(f -> f.sameOrigin()))
                // H2 console form posts don't include CSRF tokens
                .csrf(csrf -> csrf.disable());

        return http.build();
    }
}
