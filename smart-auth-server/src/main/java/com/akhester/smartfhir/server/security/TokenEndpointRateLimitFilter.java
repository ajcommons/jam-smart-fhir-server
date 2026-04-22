package com.akhester.smartfhir.server.security;

import io.github.bucket4j.Bandwidth;
import io.github.bucket4j.Bucket;
import io.github.bucket4j.Refill;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Rate-limits {@code POST /oauth2/token} per client IP using Bucket4j token-bucket:
 * burst capacity of 20, refill of 10/min. Mitigates PKCE-verifier brute-force against
 * intercepted authorization codes and refresh-token probing. Responds with HTTP 429 +
 * {@code Retry-After} when the bucket is exhausted. State is in-process
 * ({@code ConcurrentHashMap}); replace with Bucket4j + Caffeine TTL for high traffic.
 */
@Component
public class TokenEndpointRateLimitFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(TokenEndpointRateLimitFilter.class);

    private static final String TOKEN_PATH      = "/oauth2/token";
    private static final String INTROSPECT_PATH = "/oauth2/introspect";
    private static final String REVOKE_PATH     = "/oauth2/revoke";

    // One bucket per IP — created lazily on first request
    private final Map<String, Bucket> buckets = new ConcurrentHashMap<>();

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        String path = request.getRequestURI();
        // Only rate-limit the OAuth2 sensitive endpoints
        return !path.equals(TOKEN_PATH)
            && !path.equals(INTROSPECT_PATH)
            && !path.equals(REVOKE_PATH);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        String clientIp = ClientIpExtractor.extract(request);
        Bucket bucket = buckets.computeIfAbsent(clientIp, this::newBucket);

        if (bucket.tryConsume(1)) {
            // Within rate limit — pass through
            chain.doFilter(request, response);
        } else {
            // Rate limit exceeded
            log.warn("Rate limit exceeded on {} — IP={}", request.getRequestURI(), clientIp);
            response.setStatus(HttpStatus.TOO_MANY_REQUESTS.value());
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.setHeader("Retry-After", "60");
            response.getWriter().write(
                "{\"error\":\"rate_limit_exceeded\"," +
                "\"error_description\":\"Too many requests. Please wait before retrying.\"}"
            );
        }
    }

    // ── private ───────────────────────────────────────────────────────────────

    /**
     * Creates a new token bucket for an IP address.
     * Capacity: 20 tokens. Refill: 10 tokens/minute (greedy = spread evenly).
     */
    private Bucket newBucket(String ip) {
        Bandwidth limit = Bandwidth.classic(
            20,                                      // capacity: 20 bursts
            Refill.greedy(10, Duration.ofMinutes(1)) // refill: 10/min
        );
        return Bucket.builder().addLimit(limit).build();
    }

}
