package com.akhester.smartfhir.server.auth;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.web.cors.CorsConfigurationSource;

import java.util.Optional;

/**
 * Security filter chain for upstream IdP federation — active under the {@code idp} profile.
 *
 * Replaces the {@code formLogin()} chain in {@link AuthorizationServerConfig} with
 * {@code oauth2Login()}: clinicians authenticate via the configured upstream OIDC IdP
 * instead of the local login page. After IdP login, {@link PractitionerLookupService}
 * resolves the clinician's FHIR Practitioner ID so {@link FederatedIdentityIdTokenCustomizer}
 * can inject {@code fhirUser} into the SMART id_token.
 *
 * Profile matrix: {@code dev} → form login + H2; {@code prod} → form login + PostgreSQL;
 * {@code prod,idp} → IdP login + PostgreSQL.
 */
@Configuration
@Profile("idp")
public class FederatedIdentityConfig {

    private static final Logger log = LoggerFactory.getLogger(FederatedIdentityConfig.class);

    private final SmartIdpProperties      idpProperties;
    private final PractitionerLookupService practitionerLookupService;
    private final CorsConfigurationSource  corsConfigurationSource;

    public FederatedIdentityConfig(SmartIdpProperties        idpProperties,
                                    PractitionerLookupService practitionerLookupService,
                                    CorsConfigurationSource   corsConfigurationSource) {
        this.idpProperties           = idpProperties;
        this.practitionerLookupService = practitionerLookupService;
        this.corsConfigurationSource   = corsConfigurationSource;
    }

    /**
     * Replaces the form login filter chain with an OAuth2 Login filter chain.
     *
     * <p>Uses {@code @Order(2)} — same order as the base filter chain in
     * {@link AuthorizationServerConfig}. Since this class is only loaded under
     * the {@code idp} profile, there is no conflict.</p>
     */
    @Bean
    @Order(2)
    public SecurityFilterChain federatedSecurityFilterChain(HttpSecurity http)
            throws Exception {

        http
                // ── CORS: same shared source bean as the other two chains ──────
                .cors(cors -> cors.configurationSource(corsConfigurationSource))

                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(
                                "/.well-known/smart-configuration",
                                "/oauth2/jwks",
                                "/actuator/health",
                                "/error"
                        ).permitAll()
                        .anyRequest().authenticated()
                )
                // Replace formLogin with oauth2Login —
                // clinician is redirected to the upstream IdP
                .oauth2Login(oauth2 -> oauth2
                        // alwaysUse=false (default) — lets SavedRequestAwareAuthenticationSuccessHandler
                        // redirect back to the saved /oauth2/authorize request after IdP login.
                        // Using alwaysUse=true would drop the OAuth2 flow and always land on /portal.
                        .defaultSuccessUrl("/portal")
                        .userInfoEndpoint(userInfo -> userInfo
                                // Custom OidcUserService that resolves Practitioner ID
                                .oidcUserService(oidcUserService())
                        )
                );

        return http.build();
    }

    /**
     * Custom {@link OidcUserService} that intercepts the post-authentication step
     * to resolve the clinician's FHIR Practitioner resource ID.
     *
     * <p>After the upstream IdP authenticates the clinician and returns an
     * {@link OidcUser}, this service:</p>
     * <ol>
     *   <li>Extracts the configured {@link SmartIdpProperties#userIdClaim()} from
     *       the id_token claims</li>
     *   <li>Calls {@link PractitionerLookupService#lookupPractitionerId} to search
     *       HAPI FHIR for a matching Practitioner</li>
     *   <li>Adds the Practitioner ID as an additional claim so
     *       {@link FederatedIdentityIdTokenCustomizer} can pick it up</li>
     * </ol>
     */
    @Bean
    public OAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        OidcUserService delegate = new OidcUserService();

        return userRequest -> {
            // Let Spring Security do the standard OIDC user info fetch
            OidcUser oidcUser = delegate.loadUser(userRequest);

            // Extract the configured claim (e.g. "email", "employee_id")
            String claimValue = oidcUser.getClaimAsString(idpProperties.userIdClaim());

            if (claimValue == null || claimValue.isBlank()) {
                log.warn("Claim '{}' not found in IdP token for user '{}' — " +
                         "fhirUser will be absent. Check IDP_USER_ID_CLAIM.",
                        idpProperties.userIdClaim(), oidcUser.getName());
                return oidcUser;
            }

            // Look up the FHIR Practitioner ID
            Optional<String> practitionerId =
                    practitionerLookupService.lookupPractitionerId(claimValue);

            if (practitionerId.isEmpty()) {
                // Return user without fhirUser — still authenticated, portal works
                return oidcUser;
            }

            // Inject practitioner ID as a custom claim so the token customizer
            // can add it to the SMART id_token as fhirUser
            // We use a sub-map on the existing claims since OidcUser is immutable
            java.util.Map<String, Object> claims =
                    new java.util.HashMap<>(oidcUser.getClaims());
            claims.put("fhir_practitioner_id", practitionerId.get());

            log.info("Federated login — user={}, {}={}, practitioner={}",
                    oidcUser.getName(),
                    idpProperties.userIdClaim(), claimValue,
                    practitionerId.get());

            // Rebuild OidcUser with augmented claims
            return new DefaultOidcUser(
                    oidcUser.getAuthorities(),
                    oidcUser.getIdToken(),
                    new org.springframework.security.oauth2.core.oidc.OidcUserInfo(claims)
            );
        };
    }
}
