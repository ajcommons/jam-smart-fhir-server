package com.akhester.smartfhir.server.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Rejects {@code POST /login} from locked-out IP addresses before Spring Security
 * invokes the BCrypt password check, avoiding unnecessary CPU cost.
 * Redirects to {@code /login?locked}. Runs ahead of
 * {@code UsernamePasswordAuthenticationFilter} in the Order-2 filter chain;
 * lock state is managed by {@link LoginAttemptService}.
 */
@Component
public class LoginLockoutFilter extends OncePerRequestFilter {

    private static final Logger log = LoggerFactory.getLogger(LoginLockoutFilter.class);

    private final LoginAttemptService loginAttemptService;

    public LoginLockoutFilter(LoginAttemptService loginAttemptService) {
        this.loginAttemptService = loginAttemptService;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        // Only intercept POST /login — GET /login (page load) is always allowed
        return !(request.getMethod().equalsIgnoreCase("POST")
                && request.getRequestURI().equals("/login"));
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        String ip = ClientIpExtractor.extract(request);

        if (loginAttemptService.isLockedOut(ip)) {
            log.warn("Blocked login attempt from locked-out IP={}", ip);
            response.sendRedirect("/login?locked");
            return;
        }

        chain.doFilter(request, response);
    }

}
