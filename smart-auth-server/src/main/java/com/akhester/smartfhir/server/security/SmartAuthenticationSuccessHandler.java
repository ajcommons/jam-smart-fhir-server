package com.akhester.smartfhir.server.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

/**
 * Handles successful logins — clears the IP's failure counter so a legitimate
 * user who previously mis-typed their password doesn't get stuck in lockout
 * during the same session.
 *
 * Extends {@link SavedRequestAwareAuthenticationSuccessHandler} so that the
 * clinician is redirected back to whatever protected page they were trying to
 * reach before being sent to the login page (e.g. if they navigate to
 * {@code /portal} while logged out, they land back at {@code /portal} after
 * login rather than always at the default URL).
 */
@Component
public class SmartAuthenticationSuccessHandler
        extends SavedRequestAwareAuthenticationSuccessHandler {

    private final LoginAttemptService loginAttemptService;

    public SmartAuthenticationSuccessHandler(LoginAttemptService loginAttemptService) {
        this.loginAttemptService = loginAttemptService;
        setDefaultTargetUrl("/portal");
        setAlwaysUseDefaultTargetUrl(false); // prefer saved request URL
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication)
            throws IOException, ServletException {

        String ip = ClientIpExtractor.extract(request);
        loginAttemptService.recordSuccess(ip);

        super.onAuthenticationSuccess(request, response, authentication);
    }
}
