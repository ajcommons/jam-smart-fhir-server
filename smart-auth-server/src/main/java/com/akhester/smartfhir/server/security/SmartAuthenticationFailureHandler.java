package com.akhester.smartfhir.server.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Records failed login attempts via {@link LoginAttemptService} and redirects to
 * {@code /login?error} for wrong credentials or {@code /login?locked} once the IP
 * is locked out. Registered as the {@code formLogin} failure handler in
 * {@link com.akhester.smartfhir.server.auth.AuthorizationServerConfig}.
 */
@Component
public class SmartAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private static final Logger log =
            LoggerFactory.getLogger(SmartAuthenticationFailureHandler.class);

    private final LoginAttemptService loginAttemptService;

    public SmartAuthenticationFailureHandler(LoginAttemptService loginAttemptService) {
        super("/login?error");
        this.loginAttemptService = loginAttemptService;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request,
                                        HttpServletResponse response,
                                        AuthenticationException exception)
            throws IOException, ServletException {

        String ip = ClientIpExtractor.extract(request);
        loginAttemptService.recordFailure(ip);

        if (loginAttemptService.isLockedOut(ip)) {
            log.warn("Login rejected — IP locked out: {}", ip);
            getRedirectStrategy().sendRedirect(request, response, "/login?locked");
        } else {
            log.debug("Login failure for IP={}: {}", ip, exception.getMessage());
            super.onAuthenticationFailure(request, response, exception);
        }
    }
}
