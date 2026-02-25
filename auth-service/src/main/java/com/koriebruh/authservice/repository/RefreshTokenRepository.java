package com.koriebruh.authservice.repository;

import com.koriebruh.authservice.entity.RefreshToken;
import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.data.repository.reactive.ReactiveCrudRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.ZonedDateTime;
import java.util.UUID;

@Repository
public interface RefreshTokenRepository extends ReactiveCrudRepository<RefreshToken, UUID> {

    Mono<RefreshToken> findByTokenHash(String tokenHash);

    @Query("SELECT * FROM refresh_tokens WHERE token_hash = :tokenHash AND revoked = false AND expires_at > :now")
    Mono<RefreshToken> findValidTokenByHash(@Param("tokenHash") String tokenHash,
                                            @Param("now") ZonedDateTime now);

    // Relasi User tidak bisa langsung di R2DBC, query by userId aja
    @Query("SELECT * FROM refresh_tokens WHERE user_id = :userId")
    Flux<RefreshToken> findByUserId(@Param("userId") UUID userId);

    @Query("SELECT * FROM refresh_tokens WHERE user_id = :userId AND revoked = false AND expires_at > :now")
    Flux<RefreshToken> findValidTokensByUserId(@Param("userId") UUID userId,
                                               @Param("now") ZonedDateTime now);

    @Modifying
    @Query("UPDATE refresh_tokens SET revoked = true, revoked_at = :revokedAt WHERE token_hash = :tokenHash")
    Mono<Void> revokeToken(@Param("tokenHash") String tokenHash,
                           @Param("revokedAt") ZonedDateTime revokedAt);

    @Modifying
    @Query("UPDATE refresh_tokens SET revoked = true, revoked_at = :revokedAt WHERE user_id = :userId AND revoked = false")
    Mono<Void> revokeAllUserTokens(@Param("userId") UUID userId,
                                   @Param("revokedAt") ZonedDateTime revokedAt);

    @Modifying
    @Query("DELETE FROM refresh_tokens WHERE expires_at < :now")
    Mono<Void> deleteExpiredTokens(@Param("now") ZonedDateTime now);

    @Modifying
    @Query("DELETE FROM refresh_tokens WHERE revoked = true AND revoked_at < :threshold")
    Mono<Void> deleteRevokedTokensOlderThan(@Param("threshold") ZonedDateTime threshold);

    @Query("SELECT COUNT(*) FROM refresh_tokens WHERE user_id = :userId AND revoked = false AND expires_at > :now")
    Mono<Long> countValidTokensByUserId(@Param("userId") UUID userId,
                                        @Param("now") ZonedDateTime now);

    Mono<Boolean> existsByTokenHashAndRevokedFalse(String tokenHash);
}