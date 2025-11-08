package com.akhester.smartfhir.server.oidc;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Serves {@code GET /oauth2/jwks} — the public RSA key set for id_token verification.
 * Returns only the PUBLIC key components; the private key never leaves the server.
 */
@RestController
public class JwksController {

    private final RSAKey rsaKey;

    public JwksController(RSAKey rsaKey) {
        this.rsaKey = rsaKey;
    }

    @GetMapping(value = "/oauth2/jwks", produces = MediaType.APPLICATION_JSON_VALUE)
    public String jwks() {
        // toPublicJWK() strips the private key — only public components returned
        JWKSet publicJwkSet = new JWKSet(rsaKey.toPublicJWK());
        return publicJwkSet.toString();
    }
}
