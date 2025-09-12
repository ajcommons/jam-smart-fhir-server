package com.akhester.smartfhir.server.auth;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * Serves the login page template.
 *
 * Spring Security's formLogin() handles POST /login (credential verification)
 * automatically. This controller handles GET /login to render the Thymeleaf
 * login.html template.
 */
@Controller
public class LoginController {

    @GetMapping("/login")
    public String loginPage() {
        return "login";
    }
}
