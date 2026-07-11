package com.akhester.smartfhir.server.maintenance;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Component;

import java.time.Instant;

/**
 * Purges expired {@code oauth2_authorization} rows and orphaned consent records.
 *
 * Spring AS does not expire these automatically; this job prevents unbounded table growth.
 * Active refresh tokens are preserved so clinicians are not forced to re-authenticate.
 * Inactive on the {@code dev} profile. Schedule: {@code smart.server.cleanup.cron}
 * (default: nightly 02:00). Errors are logged but not re-thrown — cleanup failure
 * does not affect the running server.
 */
@Component
@Profile("!dev")
public class TokenCleanupJob {

    private static final Logger log = LoggerFactory.getLogger(TokenCleanupJob.class);

    /**
     * Deletes authorizations where:
     *   - the access token is expired, AND
     *   - there is no refresh token OR the refresh token is also expired.
     *
     * The {@code ?} is a JDBC placeholder filled with the current UTC instant by
     * {@link JdbcTemplate}.
     */
    private static final String DELETE_EXPIRED_AUTHORIZATIONS = """
            DELETE FROM oauth2_authorization
            WHERE access_token_expires_at IS NOT NULL
              AND access_token_expires_at < ?
              AND (
                    refresh_token_value IS NULL
                    OR (refresh_token_expires_at IS NOT NULL
                        AND refresh_token_expires_at < ?)
              )
            """;

    /**
     * Deletes consent records whose registered_client_id no longer corresponds to
     * any row in registered_apps.  Spring AS stores the client's internal UUID in
     * this column (matching registered_apps.id, not client_id).
     */
    private static final String DELETE_ORPHANED_CONSENTS = """
            DELETE FROM oauth2_authorization_consent
            WHERE registered_client_id NOT IN (
                SELECT id FROM registered_apps
            )
            """;

    private final JdbcTemplate jdbcTemplate;

    public TokenCleanupJob(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    /**
     * Main cleanup task.  Default schedule: daily at 02:00.
     * Override with property {@code smart.server.cleanup.cron} if needed.
     */
    @Scheduled(cron = "${smart.server.cleanup.cron:0 0 2 * * ?}")
    public void purgeExpiredTokens() {
        log.info("TokenCleanupJob: starting expired-token purge");

        Instant now = Instant.now();

        try {
            int authDeleted = jdbcTemplate.update(
                    DELETE_EXPIRED_AUTHORIZATIONS,
                    now, now);
            log.info("TokenCleanupJob: deleted {} expired authorization row(s)", authDeleted);
        } catch (Exception e) {
            log.error("TokenCleanupJob: failed to delete expired authorizations", e);
        }

        try {
            int consentDeleted = jdbcTemplate.update(DELETE_ORPHANED_CONSENTS);
            if (consentDeleted > 0) {
                log.info("TokenCleanupJob: deleted {} orphaned consent record(s)", consentDeleted);
            }
        } catch (Exception e) {
            log.error("TokenCleanupJob: failed to delete orphaned consent records", e);
        }

        log.info("TokenCleanupJob: purge complete");
    }
}
