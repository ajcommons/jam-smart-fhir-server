package com.akhester.smartfhir.server.launch;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.time.Instant;
import java.util.Optional;

/**
 * Spring Data JPA repository for {@link LaunchContext}.
 *
 * All token lookups use the opaque {@code token} string (not the UUID primary key)
 * since the token is what the SMART client sends in the authorize and token requests.
 */
public interface LaunchContextRepository extends JpaRepository<LaunchContext, String> {

    /**
     * Find a launch context by its opaque token.
     * Returns empty if the token doesn't exist, is already used, or has expired.
     */
    Optional<LaunchContext> findByTokenAndUsedFalse(String token);

    /**
     * Find by token for any state (used for audit/admin queries).
     */
    Optional<LaunchContext> findByToken(String token);

    /**
     * Atomically marks a launch token as used in a single UPDATE statement.
     *
     * <p>This is the correct way to enforce single-use semantics. A read-then-write
     * pattern (findByTokenAndUsedFalse → markUsed → save) has a race condition window
     * where two concurrent requests could both pass the read step and both get the
     * context — e.g. a clinician double-clicking Launch App.</p>
     *
     * <p>The database enforces atomicity: only one UPDATE will match
     * {@code used = false AND expiresAt > now}. The second concurrent request
     * gets {@code updated = 0} and throws {@link LaunchTokenException}.</p>
     *
     * @return 1 if the token was found unused and not expired; 0 otherwise
     */
    @Modifying
    @Query("UPDATE LaunchContext lc SET lc.used = true " +
           "WHERE lc.token = :token AND lc.used = false AND lc.expiresAt > :now")
    int markUsedAtomic(@Param("token") String token, @Param("now") Instant now);

    /**
     * Purge expired launch tokens older than the given cutoff.
     * Run periodically (e.g. scheduled task every 10 minutes).
     */
    @Modifying
    @Query("DELETE FROM LaunchContext lc WHERE lc.expiresAt < :cutoff")
    int deleteExpiredBefore(Instant cutoff);
}
