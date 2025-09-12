package com.akhester.smartfhir.server.auth;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

/**
 * Spring Data JPA repository for {@link RegisteredApp}.
 *
 * Used by:
 * - {@link JpaRegisteredClientRepository} — looks up apps by client_id during OAuth2 flows
 * - {@link DataInitializer} — seeds default apps on first startup
 */
public interface RegisteredAppRepository extends JpaRepository<RegisteredApp, String> {
    Optional<RegisteredApp> findByClientId(String clientId);
}
