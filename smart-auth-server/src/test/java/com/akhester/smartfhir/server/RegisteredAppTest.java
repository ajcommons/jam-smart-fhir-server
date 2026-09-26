package com.akhester.smartfhir.server;

import com.akhester.smartfhir.server.auth.RegisteredApp;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for RegisteredApp entity.
 */
class RegisteredAppTest {

    @Test
    void registeredApp_storesFields() {
        RegisteredApp app = new RegisteredApp(
                "my-client",
                "My SMART App",
                "http://localhost:8081/callback",
                "launch, openid, patient/Patient.rs"
        );

        assertThat(app.getClientId()).isEqualTo("my-client");
        assertThat(app.getAppName()).isEqualTo("My SMART App");
        assertThat(app.getRedirectUri()).isEqualTo("http://localhost:8081/callback");
        assertThat(app.getAllowedScopes()).isEqualTo("launch, openid, patient/Patient.rs");
        assertThat(app.isActive()).isTrue();
    }

    @Test
    void allowedScopeList_splitsOnCommaSpace() {
        RegisteredApp app = new RegisteredApp(
                "my-client", "My App",
                "http://localhost:8081/callback",
                "launch, openid, patient/Patient.rs, offline_access"
        );

        List<String> scopes = app.allowedScopeList();

        assertThat(scopes).containsExactly(
                "launch", "openid", "patient/Patient.rs", "offline_access");
    }

    @Test
    void allowedScopeList_handlesNoSpaces() {
        RegisteredApp app = new RegisteredApp(
                "my-client", "My App",
                "http://localhost:8081/callback",
                "launch,openid,patient/Patient.rs"
        );

        List<String> scopes = app.allowedScopeList();

        assertThat(scopes).containsExactly("launch", "openid", "patient/Patient.rs");
    }

    @Test
    void registeredApp_defaultsToActive() {
        RegisteredApp app = new RegisteredApp(
                "my-client", "My App",
                "http://localhost:8081/callback",
                "launch, openid"
        );

        assertThat(app.isActive()).isTrue();
    }

    @Test
    void registeredApp_accessTokenTtlNullByDefault() {
        RegisteredApp app = new RegisteredApp(
                "my-client", "My App",
                "http://localhost:8081/callback",
                "launch, openid"
        );

        // null means: use the server-wide default from SmartServerProperties
        assertThat(app.getAccessTokenTtlSeconds()).isNull();
    }
}
