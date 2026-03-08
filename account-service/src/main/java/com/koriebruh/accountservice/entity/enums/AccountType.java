package com.koriebruh.accountservice.entity.enums;

/**
 * Supported bank account types.
 * Maps to PostgreSQL ENUM: account_type
 */
public enum AccountType {
    /**
     * Regular savings account (Tabungan)
     */
    SAVINGS,

    /**
     * Business/corporate current account (Giro)
     */
    CURRENT,

    /**
     * Fixed-term time deposit (Deposito)
     */
    DEPOSIT,

    /**
     * Investor fund account for capital market (Rekening Dana Nasabah)
     */
    RDN
}

