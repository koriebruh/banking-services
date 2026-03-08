package com.koriebruh.accountservice.entity.enums;

/**
 * Lifecycle status of a bank account.
 * Maps to PostgreSQL ENUM: account_status
 */
public enum AccountStatus {
    /**
     * Account is operational
     */
    ACTIVE,

    /**
     * Temporarily suspended by admin
     */
    FROZEN,

    /**
     * Permanently closed, no further transactions allowed
     */
    CLOSED
}

