package com.koriebruh.accountservice.repository;

import com.koriebruh.accountservice.entity.AccountTransaction;
import com.koriebruh.accountservice.entity.enums.TransactionType;
import org.springframework.data.domain.Pageable;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.Instant;
import java.util.UUID;

/**
 * Reactive repository for AccountTransaction entity.
 * Provides transaction-specific query methods for audit and reporting.
 * <p>
 * Note: This table is append-only. No update/delete operations are allowed
 * to maintain audit trail integrity.
 */
@Repository
public interface AccountTransactionRepository extends R2dbcRepository<AccountTransaction, UUID> {

    /**
     * Find all transactions for an account (paginated).
     */
    Flux<AccountTransaction> findByAccountIdOrderByCreatedAtDesc(UUID accountId, Pageable pageable);

    /**
     * Find all transactions for an account (no pagination).
     */
    Flux<AccountTransaction> findByAccountIdOrderByCreatedAtDesc(UUID accountId);

    /**
     * Find transaction by reference ID (idempotency check).
     * Used to prevent double-posting on gRPC retries.
     */
    Mono<AccountTransaction> findByReferenceId(String referenceId);

    /**
     * Check if reference ID already exists.
     */
    Mono<Boolean> existsByReferenceId(String referenceId);

    /**
     * Find transactions by account and type (CREDIT or DEBIT).
     */
    Flux<AccountTransaction> findByAccountIdAndTypeOrderByCreatedAtDesc(
            UUID accountId, TransactionType type, Pageable pageable);

    /**
     * Find transactions within a date range.
     * Used for statement generation.
     */
    @Query("""
            SELECT * FROM account_transaction
            WHERE account_id = :accountId
              AND created_at >= :startDate
              AND created_at < :endDate
            ORDER BY created_at DESC
            """)
    Flux<AccountTransaction> findByAccountIdAndDateRange(
            UUID accountId, Instant startDate, Instant endDate);

    /**
     * Find recent transactions (last N transactions).
     */
    @Query("""
            SELECT * FROM account_transaction
            WHERE account_id = :accountId
            ORDER BY created_at DESC
            LIMIT :limit
            """)
    Flux<AccountTransaction> findRecentTransactions(UUID accountId, int limit);

    /**
     * Calculate total credits for an account within date range.
     */
    @Query("""
            SELECT COALESCE(SUM(amount), 0)
            FROM account_transaction
            WHERE account_id = :accountId
              AND type = 'CREDIT'
              AND created_at >= :startDate
              AND created_at < :endDate
            """)
    Mono<BigDecimal> sumCreditsByAccountIdAndDateRange(
            UUID accountId, Instant startDate, Instant endDate);

    /**
     * Calculate total debits for an account within date range.
     */
    @Query("""
            SELECT COALESCE(SUM(amount), 0)
            FROM account_transaction
            WHERE account_id = :accountId
              AND type = 'DEBIT'
              AND created_at >= :startDate
              AND created_at < :endDate
            """)
    Mono<BigDecimal> sumDebitsByAccountIdAndDateRange(
            UUID accountId, Instant startDate, Instant endDate);

    /**
     * Count transactions for an account.
     */
    Mono<Long> countByAccountId(UUID accountId);

    /**
     * Count transactions by type for an account.
     */
    Mono<Long> countByAccountIdAndType(UUID accountId, TransactionType type);

    /**
     * Find the last transaction for an account.
     * Used to get latest balance_after for verification.
     */
    @Query("""
            SELECT * FROM account_transaction
            WHERE account_id = :accountId
            ORDER BY created_at DESC
            LIMIT 1
            """)
    Mono<AccountTransaction> findLatestByAccountId(UUID accountId);

    /**
     * Find transactions by description pattern.
     * Used for searching/filtering transactions.
     */
    @Query("""
            SELECT * FROM account_transaction
            WHERE account_id = :accountId
              AND description ILIKE :pattern
            ORDER BY created_at DESC
            """)
    Flux<AccountTransaction> findByAccountIdAndDescriptionContaining(
            UUID accountId, String pattern);
}

