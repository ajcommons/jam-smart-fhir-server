package com.akhester.smartfhir.server.security;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Returns the real client IP from a request.
 *
 * Security note: reads only {@code getRemoteAddr()} — never the raw
 * {@code X-Forwarded-For} header. {@code ForwardedHeaderFilter} (registered in
 * {@code AuthorizationServerConfig}) rewrites RemoteAddr from XFF before our
 * filters run. Reading the raw header here would let any client spoof their IP.
 */
final class ClientIpExtractor {

    private ClientIpExtractor() {}

    static String extract(HttpServletRequest request) {
        return request.getRemoteAddr();
    }
}
