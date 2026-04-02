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


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Table("balance_ledger")
public class BalanceLedger {

    @Id
    private UUID id;

    /**
     * Reference to the account this transaction belongs to
     */
    @Column("account_id")
    private UUID accountId;

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
     * Timestamp when transaction was created (immutable)
     */
    @CreatedDate
    @Column("created_at")
    private Instant createdAt;

    /**
     * Validates that balance_after == balance_before + amount.
     * amount is signed: positive = CREDIT, negative = DEBIT.
     */
    public boolean isBalanceConsistent() {
        if (balanceBefore == null || balanceAfter == null || amount == null) return false;
        return balanceAfter.compareTo(balanceBefore.add(amount)) == 0;
    }
}

