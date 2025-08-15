package com.akhester.smartfhir.server;

import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

/**
 * Typed binding for {@code smart.server.*} properties in {@code application.yml}.
 *
 * Validated at startup — the server refuses to start if required values are missing.
 */
@Validated
@ConfigurationProperties(prefix = "smart.server")
public record SmartServerProperties(

        /**
         * The FHIR base URL this auth server protects.
         * Clients use this URL as the ISS when launching.
         * Example: {@code http://localhost:8080/fhir}
         */
        @NotBlank(message = "smart.server.fhir-base-url must be set (FHIR_BASE_URL env var)")
        String fhirBaseUrl,

        /**
         * Issuer URL of this auth server — appears in id_token 'iss' claim
         * and in /.well-known/smart-configuration.
         * Example: {@code http://localhost:9000}
         */
        @NotBlank(message = "smart.server.issuer-url must be set (ISSUER_URL env var)")
        String issuerUrl,

        /**
         * How long issued access tokens live in seconds.
         *
         * <p>Production default: 300 (5 minutes) — set in {@code application-prod.yml}.
         * Short TTL limits stolen-token exposure. Apps refresh silently via the
         * refresh token; clinicians are not prompted again.
         *
         * <p>Pair with token introspection on the FHIR server
         * ({@code POST /oauth2/introspect}) to catch mid-session revocations.
         *
         * <p>Minimum enforced: 30 seconds. Values under 60 s are not recommended
         * for production — they cause frequent refresh traffic.
         */
        @Min(30)
        long accessTokenTtlSeconds,

        /**
         * How long issued refresh tokens live in seconds. Default 86400 (24 hours).
         */
        @Min(60)
        long refreshTokenTtlSeconds,

        /**
         * Default value for {@code need_patient_banner} when the launch context
         * does not specify it. True means apps must render a patient header.
         */
        boolean defaultNeedPatientBanner,

        /**
         * The full URL of the SMART client's /launch endpoint.
         * The portal redirects the clinician here after creating a launch token.
         * Example: {@code http://localhost:8080/launch}
         * Env var: {@code SMART_CLIENT_LAUNCH_URL}
         */
        @NotBlank(message = "smart.server.smart-client-launch-url must be set")
        String smartClientLaunchUrl,

        /**
         * The client_id of the default SMART app to launch from the portal.
         * Must match a RegisteredApp entry in the database.
         * Env var: {@code DEFAULT_CLIENT_ID}
         */
        @NotBlank(message = "smart.server.default-client-id must be set")
        String defaultClientId

) {}
