package com.akhester.smartfhir.server.discovery;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

/**
 * Proxies {@code GET /.well-known/smart-configuration} from the FHIR server (port 8080)
 * to the auth server (port 9000).
 *
 * SMART clients resolve the discovery document from the ISS (FHIR base URL).
 * This filter bridges the two servers so discovery works without an nginx proxy.
 * Enable with {@code smart.discovery-proxy.enabled=true}; in production an nginx
 * reverse proxy is preferred over this filter.
 */
@Component
@ConditionalOnProperty(name = "smart.discovery-proxy.enabled", havingValue = "true", matchIfMissing = false)
public class SmartDiscoveryProxyFilter extends OncePerRequestFilter {

    private static final Logger log =
            LoggerFactory.getLogger(SmartDiscoveryProxyFilter.class);

    private static final String WELL_KNOWN_PATH = "/.well-known/smart-configuration";

    private final String authServerUrl;
    private final HttpClient httpClient;

    public SmartDiscoveryProxyFilter(
            @Value("${smart.server.issuer-url:http://localhost:9000}") String authServerUrl) {
        this.authServerUrl = authServerUrl;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Only intercept /.well-known/smart-configuration
        String path = request.getRequestURI();
        return !path.endsWith(WELL_KNOWN_PATH);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                     HttpServletResponse response,
                                     FilterChain filterChain)
            throws ServletException, IOException {

        String targetUrl = authServerUrl + WELL_KNOWN_PATH;
        log.debug("Proxying discovery request to {}", targetUrl);

        try {
            HttpRequest proxyRequest = HttpRequest.newBuilder()
                    .uri(URI.create(targetUrl))
                    .header("Accept", "application/json")
                    .GET()
                    .timeout(Duration.ofSeconds(5))
                    .build();

            HttpResponse<String> proxyResponse = httpClient.send(
                    proxyRequest, HttpResponse.BodyHandlers.ofString());

            response.setStatus(proxyResponse.statusCode());
            response.setContentType("application/json");
            response.getWriter().write(proxyResponse.body());

        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            log.error("Discovery proxy interrupted: {}", e.getMessage());
            response.setStatus(HttpServletResponse.SC_SERVICE_UNAVAILABLE);
        } catch (Exception e) {
            log.error("Discovery proxy failed — auth server may be down at {}: {}",
                    authServerUrl, e.getMessage());
            response.setStatus(HttpServletResponse.SC_BAD_GATEWAY);
            response.setContentType("application/json;charset=UTF-8");
            // authServerUrl intentionally omitted from response body (server-internal config)
            response.getWriter().write(
                    "{\"error\":\"smart_discovery_unavailable\"," +
                    "\"message\":\"Auth server unavailable\"}");
        }
    }
}
