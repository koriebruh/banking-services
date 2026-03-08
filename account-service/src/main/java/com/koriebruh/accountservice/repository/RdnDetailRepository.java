package com.koriebruh.accountservice.repository;

import com.koriebruh.accountservice.entity.RdnDetail;
import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.UUID;

/**
 * Reactive repository for RdnDetail entity.
 * Provides RDN-specific query methods for investor fund account management.
 */
@Repository
public interface RdnDetailRepository extends R2dbcRepository<RdnDetail, UUID> {

    /**
     * Find RDN detail by account ID.
     * One-to-one relationship with Account.
     */
    Mono<RdnDetail> findByAccountId(UUID accountId);

    /**
     * Check if RDN detail exists for an account.
     */
    Mono<Boolean> existsByAccountId(UUID accountId);

    /**
     * Find RDN by Single Investor ID (SID).
     * SID is unique per investor, issued by KSEI.
     */
    Mono<RdnDetail> findBySid(String sid);

    /**
     * Check if SID already exists.
     * Used during account creation validation.
     */
    Mono<Boolean> existsBySid(String sid);

    /**
     * Find all RDN accounts by securities company.
     * Used for partner reporting.
     */
    Flux<RdnDetail> findBySecuritiesCompany(String securitiesCompany);

    /**
     * Find all unverified RDN accounts.
     * Used for verification queue processing.
     */
    @Query("""
            SELECT * FROM rdn_detail
            WHERE verified_at IS NULL
            ORDER BY created_at ASC
            """)
    Flux<RdnDetail> findAllUnverified();

    /**
     * Find all verified RDN accounts.
     */
    @Query("""
            SELECT * FROM rdn_detail
            WHERE verified_at IS NOT NULL
            """)
    Flux<RdnDetail> findAllVerified();

    /**
     * Mark RDN as verified.
     * Called after securities company verification.
     */
    @Modifying
    @Query("""
            UPDATE rdn_detail
            SET verified_at = :verifiedAt
            WHERE account_id = :accountId AND verified_at IS NULL
            """)
    Mono<Long> verifyRdn(UUID accountId, Instant verifiedAt);

    /**
     * Find RDN accounts pending verification for more than X hours.
     * Used for escalation/reminder processing.
     */
    @Query("""
            SELECT * FROM rdn_detail
            WHERE verified_at IS NULL
              AND created_at < :cutoffTime
            ORDER BY created_at ASC
            """)
    Flux<RdnDetail> findPendingVerificationBefore(Instant cutoffTime);

    /**
     * Delete RDN detail by account ID.
     * Used when closing an RDN account.
     */
    Mono<Void> deleteByAccountId(UUID accountId);
}

