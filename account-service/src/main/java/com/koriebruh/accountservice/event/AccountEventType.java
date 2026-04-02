package com.koriebruh.accountservice.event;

/**
 * Constants for all account domain event types published to Kafka.
 *
 * <p>Naming convention: {domain}.{entity}.{action}
 * Consumers (audit-service, notif-service) filter by these values.
 *
 * <p><b>Published by AccountService:</b>
 * <ul>
 *   <li>ACCOUNT_OPENED    — new account created by customer.</li>
 *   <li>ACCOUNT_FROZEN    — account suspended by admin.</li>
 *   <li>ACCOUNT_CLOSED    — account permanently closed.</li>
 *   <li>ACCOUNT_CREDITED  — funds added via transfer (gRPC Debit/Credit).</li>
 *   <li>ACCOUNT_DEBITED   — funds deducted via transfer (gRPC Debit/Credit).</li>
 *   <li>DEPOSIT_MATURED   — time deposit reached maturity date.</li>
 *   <li>RDN_VERIFIED      — RDN account verified by securities company.</li>
 * </ul>
 */
public final class AccountEventType {

    private AccountEventType() {
    }

    // -------------------------------------------------------------------------
    // Account lifecycle
    // -------------------------------------------------------------------------

    /**
     * Fired when a new account is successfully opened.
     */
    public static final String ACCOUNT_OPENED = "account.opened";

    /**
     * Fired when an account is frozen by admin.
     */
    public static final String ACCOUNT_FROZEN = "account.frozen";

    /**
     * Fired when an account is permanently closed.
     */
    public static final String ACCOUNT_CLOSED = "account.closed";

    public static final String ACCOUNT_UNFROZEN = "account.unfrozen";


    // -------------------------------------------------------------------------
    // Deposit
    // -------------------------------------------------------------------------

    /**
     * Fired when a DEPOSIT account reaches its maturity date.
     */
    public static final String DEPOSIT_MATURED = "account.deposit.matured";

    // -------------------------------------------------------------------------
    // RDN
    // -------------------------------------------------------------------------

    /**
     * Fired when an RDN account is verified by the securities company.
     */
    public static final String RDN_VERIFIED = "account.rdn.verified";
}