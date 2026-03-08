package com.koriebruh.accountservice.entity.enums;

/**
 * Interest disbursement schedule for DEPOSIT accounts.
 * Maps to PostgreSQL ENUM: interest_payout_type
 */
public enum InterestPayoutType {
    /**
     * Interest paid in full at maturity date
     */
    END_OF_TERM,

    /**
     * Interest paid every month during the tenor
     */
    MONTHLY
}

