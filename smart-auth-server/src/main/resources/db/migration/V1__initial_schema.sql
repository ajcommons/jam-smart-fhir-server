-- ─────────────────────────────────────────────────────────────────────────────
-- V1__initial_schema.sql
-- SMART on FHIR Authorization Server — initial schema
-- Managed by Flyway. Never edit this file after it has been applied.
-- Add changes in V2__*.sql, V3__*.sql etc.
-- ─────────────────────────────────────────────────────────────────────────────

-- ── Clinicians ────────────────────────────────────────────────────────────────
-- Clinicians who can log in to this auth server to authorise SMART apps.
-- Each row maps to a FHIR Practitioner resource in the HAPI FHIR server.
CREATE TABLE clinicians (
    id            VARCHAR(36)  PRIMARY KEY,          -- UUID assigned by JPA
    username      VARCHAR(100) NOT NULL UNIQUE,      -- login username
    password_hash VARCHAR(255) NOT NULL,             -- BCrypt hash
    display_name  VARCHAR(200),                      -- shown in portal
    fhir_user_id  VARCHAR(100),                      -- FHIR Practitioner resource ID
    enabled       BOOLEAN      NOT NULL DEFAULT TRUE -- soft-disable without deleting
);

-- ── Registered Apps ───────────────────────────────────────────────────────────
-- SMART client apps authorised to use this auth server.
-- Each row corresponds to a Spring Authorization Server RegisteredClient.
CREATE TABLE registered_apps (
    id                     VARCHAR(36)   PRIMARY KEY,     -- UUID assigned by JPA
    client_id              VARCHAR(100)  NOT NULL UNIQUE, -- OAuth2 client_id
    app_name               VARCHAR(200)  NOT NULL,        -- human-readable name
    redirect_uri           VARCHAR(500)  NOT NULL,        -- allowed redirect URI
    allowed_scopes         VARCHAR(1000) NOT NULL,        -- comma-separated SMART scopes
    access_token_ttl_seconds BIGINT,                      -- NULL = use server default
    active                 BOOLEAN       NOT NULL DEFAULT TRUE
);

-- ── Launch Contexts ───────────────────────────────────────────────────────────
-- Short-lived tokens that bind a clinical session to a specific patient/encounter.
-- Created by the clinician portal when launching a SMART app.
-- Single-use: once consumed in a token exchange, used=TRUE prevents replay.
CREATE TABLE launch_contexts (
    id                  VARCHAR(36)  PRIMARY KEY,           -- UUID assigned by JPA
    token               VARCHAR(255) NOT NULL UNIQUE,       -- opaque launch token (256-bit)
    patient_fhir_id     VARCHAR(100) NOT NULL,              -- FHIR Patient resource ID
    encounter_fhir_id   VARCHAR(100),                       -- FHIR Encounter resource ID (optional)
    need_patient_banner BOOLEAN      NOT NULL DEFAULT TRUE, -- whether app must show patient header
    client_id           VARCHAR(100) NOT NULL,              -- which RegisteredApp initiated launch
    launched_by         VARCHAR(100) NOT NULL,              -- clinician username
    expires_at          TIMESTAMP    NOT NULL,              -- typically now + 5 minutes
    used                BOOLEAN      NOT NULL DEFAULT FALSE,-- true after token exchange
    created_at          TIMESTAMP    NOT NULL DEFAULT NOW()
);

-- ── Indexes ───────────────────────────────────────────────────────────────────
-- LaunchContextService.resolveLaunchToken() looks up by token
CREATE INDEX idx_launch_contexts_token      ON launch_contexts (token);
-- LaunchContextService.purgeExpiredTokens() deletes by expires_at
CREATE INDEX idx_launch_contexts_expires_at ON launch_contexts (expires_at);
-- purgeExpiredTokens also filters used=TRUE rows to skip already-consumed tokens
CREATE INDEX idx_launch_contexts_used       ON launch_contexts (used);
