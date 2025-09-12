-- ─────────────────────────────────────────────────────────────────────────────
-- V2__oauth2_authorization_tables.sql
-- Spring Authorization Server — OAuth2 authorization and consent tables.
--
-- Required by JdbcOAuth2AuthorizationService and JdbcOAuth2AuthorizationConsentService.
-- These replace the InMemory variants used in dev so that:
--   - Authorization codes survive a server restart during the /authorize → /token flow
--   - Refresh tokens persist across restarts (users don't have to re-login)
--   - Multi-instance deployments share authorization state via the database
--
-- Schema source: spring-authorization-server/oauth2-authorization-schema.sql
-- (reproduced here so deployment has no external dependency)
--
-- Managed by Flyway. Never edit this file after it has been applied.
-- ─────────────────────────────────────────────────────────────────────────────

-- ── OAuth2 Authorization ──────────────────────────────────────────────────────
-- One row per active OAuth2 authorization (authorize code, access token,
-- refresh token and OIDC id_token are all stored here as separate columns).
-- Rows are inserted at /oauth2/authorize and updated at /oauth2/token.
-- Expired / revoked rows should be cleaned up by a scheduled task (see notes
-- in AuthorizationServerConfig).

CREATE TABLE IF NOT EXISTS oauth2_authorization (
    id                            VARCHAR(100)  NOT NULL,
    registered_client_id          VARCHAR(100)  NOT NULL,
    principal_name                VARCHAR(200)  NOT NULL,
    authorization_grant_type      VARCHAR(100)  NOT NULL,
    authorized_scopes             VARCHAR(1000) DEFAULT NULL,
    attributes                    TEXT          DEFAULT NULL,
    state                         VARCHAR(500)  DEFAULT NULL,

    -- Authorization code grant
    authorization_code_value      TEXT          DEFAULT NULL,
    authorization_code_issued_at  TIMESTAMP     DEFAULT NULL,
    authorization_code_expires_at TIMESTAMP     DEFAULT NULL,
    authorization_code_metadata   TEXT          DEFAULT NULL,

    -- Access token
    access_token_value            TEXT          DEFAULT NULL,
    access_token_issued_at        TIMESTAMP     DEFAULT NULL,
    access_token_expires_at       TIMESTAMP     DEFAULT NULL,
    access_token_metadata         TEXT          DEFAULT NULL,
    access_token_type             VARCHAR(100)  DEFAULT NULL,
    access_token_scopes           VARCHAR(1000) DEFAULT NULL,

    -- OIDC id_token
    oidc_id_token_value           TEXT          DEFAULT NULL,
    oidc_id_token_issued_at       TIMESTAMP     DEFAULT NULL,
    oidc_id_token_expires_at      TIMESTAMP     DEFAULT NULL,
    oidc_id_token_metadata        TEXT          DEFAULT NULL,

    -- Refresh token
    refresh_token_value           TEXT          DEFAULT NULL,
    refresh_token_issued_at       TIMESTAMP     DEFAULT NULL,
    refresh_token_expires_at      TIMESTAMP     DEFAULT NULL,
    refresh_token_metadata        TEXT          DEFAULT NULL,

    -- Device authorization grant (included for spec completeness; not used by SMART)
    user_code_value               TEXT          DEFAULT NULL,
    user_code_issued_at           TIMESTAMP     DEFAULT NULL,
    user_code_expires_at          TIMESTAMP     DEFAULT NULL,
    user_code_metadata            TEXT          DEFAULT NULL,
    device_code_value             TEXT          DEFAULT NULL,
    device_code_issued_at         TIMESTAMP     DEFAULT NULL,
    device_code_expires_at        TIMESTAMP     DEFAULT NULL,
    device_code_metadata          TEXT          DEFAULT NULL,

    PRIMARY KEY (id)
);

-- Index: look up by authorization code value (used at /oauth2/token)
CREATE INDEX IF NOT EXISTS idx_oauth2_auth_code
    ON oauth2_authorization (authorization_code_value);

-- Index: look up by refresh token value (used on refresh grant)
CREATE INDEX IF NOT EXISTS idx_oauth2_refresh_token
    ON oauth2_authorization (refresh_token_value);

-- Index: look up by access token value (used at /oauth2/introspect and /oauth2/revoke)
CREATE INDEX IF NOT EXISTS idx_oauth2_access_token
    ON oauth2_authorization (access_token_value);

-- Index: clean up expired rows per principal (useful for admin queries)
CREATE INDEX IF NOT EXISTS idx_oauth2_principal
    ON oauth2_authorization (principal_name, registered_client_id);


-- ── OAuth2 Authorization Consent ──────────────────────────────────────────────
-- Remembers which scopes a clinician has already approved for a given app so
-- the consent prompt is not shown on every launch.
-- One row per (client, principal) pair.

CREATE TABLE IF NOT EXISTS oauth2_authorization_consent (
    registered_client_id VARCHAR(100)  NOT NULL,
    principal_name       VARCHAR(200)  NOT NULL,
    authorities          VARCHAR(1000) NOT NULL,   -- space-separated approved scopes
    PRIMARY KEY (registered_client_id, principal_name)
);
