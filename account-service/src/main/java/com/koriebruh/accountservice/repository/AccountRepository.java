package com.koriebruh.accountservice.repository;

import com.koriebruh.accountservice.entity.Account;
import com.koriebruh.accountservice.entity.enums.AccountStatus;
import com.koriebruh.accountservice.entity.enums.AccountType;
import org.springframework.data.r2dbc.repository.Modifying;
import org.springframework.data.r2dbc.repository.Query;
import org.springframework.data.r2dbc.repository.R2dbcRepository;
import org.springframework.stereotype.Repository;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.math.BigDecimal;
import java.util.List;
import java.util.UUID;

/**
 * Reactive repository for Account entity.
 * Provides banking-specific query methods for account management.
 */
@Repository
public interface AccountRepository extends R2dbcRepository<Account, UUID> {

    /**
     * Find account by unique account number.
     * Used for transfers and account lookups.
     */
    Mono<Account> findByAccountNumber(String accountNumber);

    /**
     * Check if account number already exists.
     * Used during account creation to ensure uniqueness.
     */
    Mono<Boolean> existsByAccountNumber(String accountNumber);

    Mono<Boolean> existsByUserIdAndAccountTypeAndStatusIn(
            UUID userId,
            AccountType accountType,
            List<AccountStatus> statuses
    );

    Flux<Account> findAllByUserId(UUID userId);

    Mono<Account> findByAccountNumberAndUserId(String accountNumber, UUID userId);

    /**
     * Find all accounts belonging to a user.
     */
    Flux<Account> findByUserId(UUID userId);

    /**
     * Find all accounts by user and type.
     * Example: Get all savings accounts for a user.
     */
    Flux<Account> findByUserIdAndAccountType(UUID userId, AccountType accountType);

    /**
     * Find all accounts by status.
     * Used for admin monitoring.
     */
    Flux<Account> findByStatus(AccountStatus status);

    /**
     * Find active accounts by user.
     * Most common query for customer-facing operations.
     */
    Flux<Account> findByUserIdAndStatus(UUID userId, AccountStatus status);

    /**
     * Update account balance atomically with optimistic locking.
     * Returns affected rows count for verification.
     *
     * @param id              Account UUID
     * @param newBalance      New balance after transaction
     * @param expectedBalance Expected current balance (for optimistic locking)
     * @return Number of rows updated (1 if successful, 0 if concurrent modification)
     */
    @Modifying
    @Query("""
            UPDATE account
            SET balance = :newBalance, updated_at = NOW()
            WHERE id = :id AND balance = :expectedBalance
            """)
    Mono<Long> updateBalanceWithOptimisticLock(UUID id, BigDecimal newBalance, BigDecimal expectedBalance);

    /**
     * Update account status (ACTIVE, FROZEN, CLOSED).
     */
    @Modifying
    @Query("""
            UPDATE account
            SET status = :status, updated_at = NOW()
            WHERE id = :id
            """)
    Mono<Long> updateStatus(UUID id, String status);

    /**
     * Find account for update (used with explicit locking in transactions).
     * Returns account with current balance for atomic operations.
     */
    @Query("""
            SELECT * FROM account
            WHERE id = :id AND status = 'ACTIVE'
            FOR UPDATE
            """)
    Mono<Account> findByIdForUpdate(UUID id);


    /**
     * Find account by account number for update.
     */
    @Query("""
            SELECT * FROM account
            WHERE account_number = :accountNumber AND status = 'ACTIVE'
            FOR UPDATE
            """)
    Mono<Account> findByAccountNumberForUpdate(String accountNumber);

    /**
     * Count accounts by user (for limit validation).
     */
    Mono<Long> countByUserId(UUID userId);

    /**
     * Count accounts by user and type.
     */
    Mono<Long> countByUserIdAndAccountType(UUID userId, AccountType accountType);

    /**
     * Get total balance across all accounts for a user (for reporting).
     */
    @Query("""
            SELECT COALESCE(SUM(balance), 0)
            FROM account
            WHERE user_id = :userId AND status = 'ACTIVE' AND currency = :currency
            """)
    Mono<BigDecimal> getTotalBalanceByUserIdAndCurrency(UUID userId, String currency);
}

