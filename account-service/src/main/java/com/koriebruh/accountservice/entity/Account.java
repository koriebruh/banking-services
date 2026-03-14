package com.koriebruh.accountservice.entity;

import com.koriebruh.accountservice.entity.enums.AccountStatus;
import com.koriebruh.accountservice.entity.enums.AccountType;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;
import org.springframework.data.annotation.Id;
import org.springframework.data.annotation.LastModifiedDate;
import org.springframework.data.relational.core.mapping.Column;
import org.springframework.data.relational.core.mapping.Table;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;

/**
 * Core record for all bank accounts regardless of type.
 * Accounts of type DEPOSIT and RDN will have a corresponding row in
 * deposit_detail or rdn_detail respectively.
 * <p>
 * Banking Best Practices Applied:
 * - BigDecimal for monetary values (precision NUMERIC(19,4))
 * - Instant for createdAt/updatedAt (UTC timestamps)
 * - UUID for primary key (secure, non-sequential)
 * - Immutable audit fields
 */
@Data
@Builder(toBuilder = true)
@NoArgsConstructor
@AllArgsConstructor
@Table("account")
public class Account {

    @Id
    private UUID id;

    /**
     * 10-digit unique account number generated at creation.
     * Format: Numeric string for banking compatibility.
     */
    @Column("account_number")
    private String accountNumber;

    /**
     * References the owner in auth-service.
     * No FK constraint - cross-service boundary.
     */
    @Column("user_id")
    private UUID userId;

    @Column("account_type")
    private AccountType accountType;

    /**
     * Current account balance.
     * NUMERIC(19,4) - supports up to 999,999,999,999,999.9999
     * Using BigDecimal to prevent floating-point precision errors.
     */
    @Column("balance")
    private BigDecimal balance;

    /**
     * ISO 4217 currency code (e.g., IDR, USD)
     */
    @Column("currency")
    private String currency;

    @Column("status")
    private AccountStatus status;

    @CreatedDate
    @Column("created_at")
    private Instant createdAt;

    @LastModifiedDate
    @Column("updated_at")
    private Instant updatedAt;

    /**
     * Check if the account can perform transactions
     */
    public boolean isOperational() {
        return status == AccountStatus.ACTIVE;
    }

    /**
     * Check if sufficient balance for debit operation
     */
    public boolean hasSufficientBalance(BigDecimal amount) {
        return balance.compareTo(amount) >= 0;
    }
}

