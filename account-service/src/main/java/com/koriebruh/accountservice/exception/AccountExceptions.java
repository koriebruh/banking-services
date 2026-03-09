package com.koriebruh.accountservice.exception;

/**
 * Domain-specific exceptions for account-service.
 *
 * <p>All exceptions extend {@link AccountExceptions} so they are caught
 * by the single {@code @ExceptionHandler(AccountExceptions.class)} in
 * {@link GlobalException}, with correct HTTP status per exception type.
 *
 * <p><b>HTTP status mapping (handle in GlobalException):</b>
 * <ul>
 *   <li>404 NOT_FOUND          — AccountNotFoundException, TransactionNotFoundException</li>
 *   <li>409 CONFLICT           — AccountNumberAlreadyExistsException, DuplicateSidException</li>
 *   <li>422 UNPROCESSABLE      — InsufficientBalanceException, AccountNotActiveException,
 *                                DepositNotMaturedException</li>
 *   <li>403 FORBIDDEN          — AccountOwnershipException</li>
 * </ul>
 */
public class AccountExceptions extends RuntimeException {

    public AccountExceptions(String message) {
        super(message);
    }

    // -------------------------------------------------------------------------
    // 404 — Not Found
    // -------------------------------------------------------------------------

    /**
     * Thrown when an account is not found or does not belong to the requesting user.
     * Generic message prevents leaking existence of other users' accounts.
     */
    public static class AccountNotFoundException extends AccountExceptions {
        public AccountNotFoundException(String accountNumber) {
            super("Account not found: " + accountNumber);
        }
    }

    /**
     * Thrown when a transaction record cannot be found by ID.
     */
    public static class TransactionNotFoundException extends AccountExceptions {
        public TransactionNotFoundException(String id) {
            super("Transaction not found: " + id);
        }
    }

    // -------------------------------------------------------------------------
    // 409 — Conflict
    // -------------------------------------------------------------------------

    /**
     * Thrown when a generated account number collides with an existing one.
     * Should be extremely rare — triggers a regeneration attempt in service layer.
     */
    public static class AccountNumberAlreadyExistsException extends AccountExceptions {
        public AccountNumberAlreadyExistsException() {
            super("Account number already exists. Please try again.");
        }
    }

    /**
     * Thrown when a customer tries to open an RDN account with a SID
     * that is already registered to another account.
     */
    public static class DuplicateSidException extends AccountExceptions {
        public DuplicateSidException(String sid) {
            super("SID already registered: " + sid);
        }
    }

    // -------------------------------------------------------------------------
    // 422 — Unprocessable
    // -------------------------------------------------------------------------

    /**
     * Thrown by gRPC Debit handler when account balance is less than requested amount.
     */
    public static class InsufficientBalanceException extends AccountExceptions {
        public InsufficientBalanceException(String accountNumber) {
            super("Insufficient balance for account: " + accountNumber);
        }
    }

    /**
     * Thrown by gRPC Debit/Credit handlers when the target account
     * is FROZEN or CLOSED and cannot accept transactions.
     */
    public static class AccountNotActiveException extends AccountExceptions {
        public AccountNotActiveException(String accountNumber) {
            super("Account is not active: " + accountNumber);
        }
    }

    /**
     * Thrown when an attempt is made to close a DEPOSIT account before its maturity date
     * and auto_rollover is false.
     */
    public static class DepositNotMaturedException extends AccountExceptions {
        public DepositNotMaturedException(String accountNumber) {
            super("Deposit has not reached maturity date: " + accountNumber);
        }
    }

    // -------------------------------------------------------------------------
    // 403 — Forbidden
    // -------------------------------------------------------------------------

    /**
     * Thrown when an authenticated user attempts to access an account
     * that belongs to a different user.
     * Uses a generic message to avoid leaking account ownership information.
     */
    public static class AccountOwnershipException extends AccountExceptions {
        public AccountOwnershipException() {
            super("Access denied");
        }
    }
}