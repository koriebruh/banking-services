package com.koriebruh.accountservice.entity.enums;

/**
 * Direction of a fund movement.
 * Maps to PostgreSQL ENUM: transaction_type
 */
public enum TransactionType {
    /**
     * Funds received (balance increases)
     */
    CREDIT,

    /**
     * Funds sent (balance decreases)
     */
    DEBIT
}

