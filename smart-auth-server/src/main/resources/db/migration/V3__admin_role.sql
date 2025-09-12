-- V3__admin_role.sql
-- Adds a role column to the clinicians table to support ROLE_ADMIN accounts.
-- Existing rows get CLINICIAN (the previous implicit default) so there is no
-- behaviour change for any currently-deployed clinician.

ALTER TABLE clinicians
    ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'CLINICIAN';
