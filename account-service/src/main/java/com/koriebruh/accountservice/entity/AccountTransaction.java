package com.koriebruh.accountservice.entity;

import com.koriebruh.accountservice.entity.enums.TransactionType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

/**
 * Immutable ledger of all balance mutations for each account.
 * Records are append-only - never updated or deleted (audit trail).
 * <p>
 * Banking Best Practices Applied:
 * - BigDecimal for all monetary values
 * - balance_before/balance_after captured at write time for auditability
 * - reference_id for idempotency (prevents double-posting)
 * - Immutable record design
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table("account_transaction")
public class AccountTransaction {

    @Id
    private UUID id;

    /**
     * Reference to the account this transaction belongs to
     */
    @Column("account_id")
    private UUID accountId;

    /**
     * Direction of fund movement (CREDIT or DEBIT)
     */
    @Column("type")
    private TransactionType type;

    /**
     * Transaction amount (always positive).
     * The direction is determined by the type field.
     * NUMERIC(19,4) for banking precision.
     */
    @Column("amount")
    private BigDecimal amount;

    /**
     * Account balance before this transaction.
     * Captured at write time for auditability.
     */
    @Column("balance_before")
    private BigDecimal balanceBefore;

    /**
     * Account balance after this transaction.
     * Captured at write time for auditability.
     */
    @Column("balance_after")
    private BigDecimal balanceAfter;

    /**
     * Idempotency key provided by transfer-service.
     * UNIQUE constraint prevents double-posting on gRPC retries.
     */
    @Column("reference_id")
    private String referenceId;

    /**
     * Human-readable description of the transaction
     */
    @Column("description")
    private String description;

    /**
     * Timestamp when transaction was created (immutable)
     */
    @CreatedDate
    @Column("created_at")
    private Instant createdAt;

    /**
     * Validate that balance_after is correctly calculated
     */
    public boolean isBalanceConsistent() {
        if (balanceBefore == null || balanceAfter == null || amount == null || type == null) {
            return false;
        }
        BigDecimal expectedAfter = switch (type) {
            case CREDIT -> balanceBefore.add(amount);
            case DEBIT -> balanceBefore.subtract(amount);
        };
        return balanceAfter.compareTo(expectedAfter) == 0;
    }
}

