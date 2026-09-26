package com.akhester.smartfhir.server.auth;

import ca.uhn.fhir.interceptor.api.Hook;
import ca.uhn.fhir.interceptor.api.Interceptor;
import ca.uhn.fhir.interceptor.api.Pointcut;
import ca.uhn.fhir.rest.api.RestOperationTypeEnum;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.exceptions.AuthenticationException;
import ca.uhn.fhir.rest.server.exceptions.ForbiddenOperationException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.JWSVerificationKeySelector;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.nimbusds.jwt.proc.DefaultJWTProcessor;
import com.nimbusds.jose.jwk.JWKSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;

/**
 * HAPI FHIR server interceptor that enforces SMART on FHIR v2 scope rules
 * ({@code patient/{ResourceType}.{operations}}) on every incoming request.
 * Verifies the Bearer JWT against this server's RSA public key (from {@code /oauth2/jwks}),
 * then checks the {@code scope} claim against the requested resource type and operation.
 * Must be registered with the HAPI FHIR JPA server, not this auth server.
 *
 * @see <a href="https://hl7.org/fhir/smart-app-launch/scopes-and-launch-context.html">SMART App Launch: Scopes</a>
 */
@Interceptor
public class SmartScopeAuthorizationInterceptor {

    private static final Logger log =
            LoggerFactory.getLogger(SmartScopeAuthorizationInterceptor.class);

    private final ConfigurableJWTProcessor<SecurityContext> jwtProcessor;

    public SmartScopeAuthorizationInterceptor(RSAKey rsaKey) {
        // Build a JWT processor that verifies RS256 signatures with our public key
        this.jwtProcessor = new DefaultJWTProcessor<>();
        JWKSource<SecurityContext> keySource =
                new ImmutableJWKSet<>(new JWKSet(rsaKey.toPublicJWK()));
        this.jwtProcessor.setJWSKeySelector(
                new JWSVerificationKeySelector<>(JWSAlgorithm.RS256, keySource));
    }

    /**
     * Fires before every incoming FHIR request.
     * Validates the bearer token and checks scope against the resource+operation.
     */
    @Hook(Pointcut.SERVER_INCOMING_REQUEST_PRE_HANDLED)
    public void authorizeRequest(RequestDetails requestDetails) {
        // Skip internal server calls (no Authorization header)
        String authHeader = requestDetails.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new AuthenticationException(
                    "Authorization header missing or not Bearer — "
                    + "all FHIR requests require a SMART access token");
        }

        String token = authHeader.substring(7).trim();
        JWTClaimsSet claims = verifyAndExtractClaims(token);

        String scope = (String) claims.getClaim("scope");
        if (scope == null || scope.isBlank()) {
            throw new ForbiddenOperationException("Access token has no scope claim");
        }

        List<String> grantedScopes = Arrays.asList(scope.split("\\s+"));

        String resourceType = requestDetails.getResourceName();
        // Use RestOperationTypeEnum to distinguish read (GET /Patient/123) from
        // search (GET /Patient?name=foo) — both are HTTP GET but need different scopes.
        RestOperationTypeEnum opType = requestDetails.getRestOperationType();

        if (resourceType != null && !isAllowed(resourceType, opType, grantedScopes)) {
            log.warn("Scope denied — resource={}, operation={}, scopes={}",
                    resourceType, opType, scope);
            throw new ForbiddenOperationException(
                    "Insufficient scope for " + opType + " on " + resourceType
                    + ". Required: patient/" + resourceType + ".rs or patient/*.rs");
        }

        log.debug("Scope check passed — resource={}, operation={}", resourceType, opType);
    }

    // ── private helpers ───────────────────────────────────────────────────────

    private JWTClaimsSet verifyAndExtractClaims(String token) {
        try {
            return jwtProcessor.process(token, null);
        } catch (Exception e) {
            throw new AuthenticationException(
                    "Invalid or expired access token: " + e.getMessage());
        }
    }

    /**
     * Checks whether any of the granted scopes permit the requested operation.
     *
     * SMART v2 scope grammar:
     *   {@code patient/{ResourceType}.{ops}}  — specific resource
     *   {@code patient/*.{ops}}               — all resources
     *
     * Operation letters: r=read, s=search, c=create, u=update, d=delete
     */
    private boolean isAllowed(String resourceType, RestOperationTypeEnum opType,
                              List<String> grantedScopes) {
        // Map HAPI operation type to SMART scope letter.
        // Search (GET /Patient?...) needs "s"; read (GET /Patient/123) needs "r".
        // Both are HTTP GET, so we must use RestOperationTypeEnum, not the HTTP method string.
        String requiredOp = switch (opType) {
            case SEARCH_TYPE, SEARCH_SYSTEM, SEARCH_SYSTEM_TYPE -> "s";
            case READ, VREAD                                     -> "r";
            case CREATE                                          -> "c";
            case UPDATE, PATCH                                   -> "u";
            case DELETE                                          -> "d";
            default                                              -> "r";
        };

        for (String scope : grantedScopes) {
            if (scopePermits(scope, resourceType, requiredOp)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if a single scope string permits the given resource + operation.
     *
     * Examples:
     * - {@code patient/Patient.rs}  permits read+search on Patient
     * - {@code patient/*.rs}        permits read+search on any resource
     * - {@code patient/Patient.cruds} permits all operations on Patient
     */
    private boolean scopePermits(String scope, String resourceType, String requiredOp) {
        // Must start with "patient/"
        if (!scope.startsWith("patient/")) return false;

        String rest = scope.substring("patient/".length());
        int dotIndex = rest.indexOf('.');
        if (dotIndex < 0) return false;

        String scopeResource = rest.substring(0, dotIndex);   // "Patient" or "*"
        String scopeOps      = rest.substring(dotIndex + 1);  // "rs", "cruds", etc.

        // Resource must match or be wildcard
        boolean resourceMatches = "*".equals(scopeResource)
                || scopeResource.equalsIgnoreCase(resourceType);
        if (!resourceMatches) return false;

        // Operation must be in the scope's ops string.
        // Note: scopeOps.equals("cruds") is redundant — if scopeOps is "cruds" then
        // contains(requiredOp) is already true for any single-char op in {c,r,u,d,s}.
        return scopeOps.contains(requiredOp);
    }
}
