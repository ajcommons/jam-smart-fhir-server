package com.akhester.smartfhir.server.oidc;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.env.Environment;
import org.springframework.core.env.Profiles;
import org.springframework.core.io.Resource;

import java.security.KeyStore;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;

/**
 * Provides the RSA key pair ({@link JWKSource}) used to sign all JWTs issued by this server.
 * In production, loads a persistent key from a PKCS12 keystore configured via
 * {@code smart.server.keystore.path/password/alias} — required for clustered deployments
 * and for tokens to survive restarts. In dev, generates a fresh RSA-2048 key at startup
 * (tokens are invalid after restart; a warning is logged).
 */
@Configuration
public class RsaKeyConfig {

    private static final Logger log = LoggerFactory.getLogger(RsaKeyConfig.class);

    @Value("${smart.server.keystore.path:#{null}}")
    private Resource keystorePath;

    @Value("${smart.server.keystore.password:#{null}}")
    private String keystorePassword;

    @Value("${smart.server.keystore.alias:smart-fhir-server}")
    private String keystoreAlias;

    private final Environment environment;

    public RsaKeyConfig(Environment environment) {
        this.environment = environment;
    }

    /**
     * Provides the RSA key pair — loaded from keystore if configured,
     * otherwise generated at startup (dev mode only).
     *
     * <p>In the {@code prod} profile, an ephemeral key is never acceptable:
     * tokens become invalid on every restart, breaking active clinician sessions.
     * The server refuses to start if no keystore is configured in prod.</p>
     */
    @Bean
    public RSAKey rsaKey() {
        boolean isProd = environment.acceptsProfiles(Profiles.of("prod"));

        if (keystorePath != null && keystorePath.exists()) {
            try {
                keystorePath.getInputStream().close(); // verify accessible
            } catch (Exception e) {
                if (isProd) {
                    throw new IllegalStateException(
                        "Keystore configured but not accessible in prod — " +
                        "check KEYSTORE_PATH, KEYSTORE_PASSWORD: " + e.getMessage(), e);
                }
                log.warn("Keystore path configured but not accessible: {} — using ephemeral key", keystorePath);
                return generateEphemeral();
            }
            return loadFromKeystore();
        }

        // No keystore configured
        if (isProd) {
            throw new IllegalStateException(
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n" +
                "  SMART AUTH SERVER — PROD STARTUP BLOCKED\n" +
                "  No RSA signing keystore configured.\n" +
                "  An ephemeral key is NOT safe for production: all tokens\n" +
                "  become invalid on every restart.\n\n" +
                "  Generate a keystore:\n" +
                "    keytool -genkeypair -alias smart-fhir-server \\\n" +
                "      -keyalg RSA -keysize 2048 -storetype PKCS12 \\\n" +
                "      -keystore smart-fhir-server.p12 -validity 3650\n\n" +
                "  Then set env vars:\n" +
                "    KEYSTORE_PATH=/path/to/smart-fhir-server.p12\n" +
                "    KEYSTORE_PASSWORD=<your-password>\n" +
                "    KEYSTORE_ALIAS=smart-fhir-server\n" +
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            );
        }

        return generateEphemeral();
    }

    /**
     * JWKSource bean consumed by Spring Authorization Server for JWT signing.
     */
    @Bean
    public JWKSource<SecurityContext> jwkSource(RSAKey rsaKey) {
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    // ── private ───────────────────────────────────────────────────────────────

    /**
     * Loads the RSA key pair from a PKCS12 keystore.
     * Production-safe — key survives server restarts.
     */
    private RSAKey loadFromKeystore() {
        try {
            KeyStore ks = KeyStore.getInstance("PKCS12");
            char[] password = keystorePassword != null
                    ? keystorePassword.toCharArray() : new char[0];

            ks.load(keystorePath.getInputStream(), password);

            RSAPrivateKey privateKey =
                    (RSAPrivateKey) ks.getKey(keystoreAlias, password);
            RSAPublicKey publicKey =
                    (RSAPublicKey) ks.getCertificate(keystoreAlias).getPublicKey();

            if (privateKey == null) {
                throw new IllegalStateException(
                        "Alias '" + keystoreAlias + "' not found in keystore at "
                        + keystorePath);
            }

            RSAKey rsaKey = new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyID(keystoreAlias)
                    .build();

            log.info("RSA signing key loaded from keystore — alias={}, path={}",
                    keystoreAlias, keystorePath);
            return rsaKey;

        } catch (Exception e) {
            throw new IllegalStateException(
                    "Failed to load RSA signing key from keystore: " + e.getMessage(), e);
        }
    }

    /**
     * Generates an ephemeral RSA-2048 key pair.
     * For development and testing only — key is lost on restart.
     */
    private RSAKey generateEphemeral() {
        log.warn("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        log.warn("  RSA key is EPHEMERAL — generated at startup, lost on restart.");
        log.warn("  All tokens will be INVALID after a server restart.");
        log.warn("  Configure smart.server.keystore.* for production use.");
        log.warn("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        try {
            RSAKey rsaKey = new RSAKeyGenerator(2048)
                    .keyID(UUID.randomUUID().toString())
                    .generate();
            log.info("Ephemeral RSA-2048 signing key generated — kid={}", rsaKey.getKeyID());
            return rsaKey;
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate RSA signing key", e);
        }
    }
}
