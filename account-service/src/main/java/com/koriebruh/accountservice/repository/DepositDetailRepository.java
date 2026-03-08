package com.koriebruh.accountservice.repository;

import com.koriebruh.accountservice.entity.DepositDetail;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.LocalDate;
import java.util.UUID;

/**
 * Reactive repository for DepositDetail entity.
 * Provides deposit-specific query methods for time deposit management.
 */
@Repository
public interface DepositDetailRepository extends R2dbcRepository<DepositDetail, UUID> {

    /**
     * Find deposit detail by account ID.
     * One-to-one relationship with Account.
     */
    Mono<DepositDetail> findByAccountId(UUID accountId);

    /**
     * Check if deposit detail exists for an account.
     */
    Mono<Boolean> existsByAccountId(UUID accountId);

    /**
     * Find all deposits maturing on a specific date.
     * Used for batch processing of matured deposits.
     */
    Flux<DepositDetail> findByMaturityDate(LocalDate maturityDate);

    /**
     * Find all deposits maturing within a date range.
     * Used for reminder notifications and reports.
     */
    @Query("""
            SELECT * FROM deposit_detail
            WHERE maturity_date BETWEEN :startDate AND :endDate
            ORDER BY maturity_date ASC
            """)
    Flux<DepositDetail> findByMaturityDateBetween(LocalDate startDate, LocalDate endDate);

    /**
     * Find deposits maturing today with auto-rollover enabled.
     * Used for automatic rollover processing.
     */
    @Query("""
            SELECT * FROM deposit_detail
            WHERE maturity_date = :today AND auto_rollover = TRUE
            """)
    Flux<DepositDetail> findMaturingTodayWithAutoRollover(LocalDate today);

    /**
     * Find deposits maturing today without auto-rollover.
     * Used for withdrawal processing.
     */
    @Query("""
            SELECT * FROM deposit_detail
            WHERE maturity_date = :today AND auto_rollover = FALSE
            """)
    Flux<DepositDetail> findMaturingTodayWithoutAutoRollover(LocalDate today);

    /**
     * Find all active deposits for reporting.
     * Joins with account table to filter by status.
     */
    @Query("""
            SELECT dd.* FROM deposit_detail dd
            INNER JOIN account a ON dd.account_id = a.id
            WHERE a.status = 'ACTIVE'
            ORDER BY dd.maturity_date ASC
            """)
    Flux<DepositDetail> findAllActiveDeposits();

    /**
     * Find deposits by tenor months.
     */
    Flux<DepositDetail> findByTenorMonths(Short tenorMonths);

    /**
     * Delete deposit detail by account ID.
     * Used when closing a deposit account.
     */
    Mono<Void> deleteByAccountId(UUID accountId);
}

