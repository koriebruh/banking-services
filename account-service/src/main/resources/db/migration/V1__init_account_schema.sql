-- =============================================================================
-- V1__init_account_schema.sql
-- Account Service — Initial Schema
--
-- Tables:
--   1. account             — Core bank account records for all account types
--   2. deposit_detail      — Extended attributes for DEPOSIT accounts
--   3. rdn_detail          — Extended attributes for RDN accounts
--   4. balance_ledger      — Debit/credit mutations for audit and reconciliation (internal use only)
-- =============================================================================

-- -----------------------------------------------------------------------------
-- ENUM TYPES
-- -----------------------------------------------------------------------------

-- Supported bank account types
CREATE TYPE account_type AS ENUM (
    'SAVINGS',   -- Regular savings account (Tabungan)
    'CURRENT',   -- Business/corporate current account (Giro)
    'DEPOSIT',   -- Fixed-term time deposit (Deposito)
    'RDN'        -- Investor fund account for capital market (Rekening Dana Nasabah)
);

-- Lifecycle status of a bank account
CREATE TYPE account_status AS ENUM (
    'ACTIVE',    -- Account is operational
    'FROZEN',    -- Temporarily suspended by admin
    'CLOSED'     -- Permanently closed, no further transactions allowed
);

-- Interest disbursement schedule for DEPOSIT accounts
CREATE TYPE interest_payout_type AS ENUM (
    'END_OF_TERM',  -- Interest paid in full at maturity date
    'MONTHLY'       -- Interest paid every month during the tenor
);

-- -----------------------------------------------------------------------------
-- TABLE: account
--
-- Core record for all bank accounts regardless of type.
-- Accounts of type DEPOSIT and RDN will have a corresponding row in
-- deposit_detail or rdn_detail respectively.
--
-- Notes:
--   - user_id references the owner in auth-service. No FK constraint is applied
--     because the users table lives in a separate database (cross-service boundary).
--   - balance is stored as NUMERIC(19,4) to avoid floating-point precision errors.
--   - account_number is a 10-digit string generated at account creation.
-- -----------------------------------------------------------------------------

CREATE TABLE account
(
    id             UUID PRIMARY KEY        DEFAULT gen_random_uuid(),
    account_number VARCHAR(10)    NOT NULL UNIQUE,
    user_id        UUID           NOT NULL,
    account_type   account_type   NOT NULL,
    balance        NUMERIC(19, 4) NOT NULL DEFAULT 0,
    currency       VARCHAR(3)     NOT NULL DEFAULT 'IDR',
    status         account_status NOT NULL DEFAULT 'ACTIVE',
    created_at     TIMESTAMPTZ    NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ    NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_account_user_id ON account (user_id);
CREATE INDEX idx_account_number ON account (account_number);
CREATE INDEX idx_account_status ON account (status);

-- -----------------------------------------------------------------------------
-- TABLE: deposit_detail
--
-- Stores extended attributes specific to DEPOSIT accounts.
-- One-to-one with account (each DEPOSIT account has exactly one row here).
--
-- Notes:
--   - principal_amount is the initial locked amount at account opening.
--   - interest_rate is expressed as annual percentage (e.g., 5.25 = 5.25% p.a.).
--   - maturity_date is calculated at opening: created_at + tenor_months.
--   - auto_rollover = true means the deposit renews automatically at maturity.
-- -----------------------------------------------------------------------------

CREATE TABLE deposit_detail
(
    id               UUID PRIMARY KEY              DEFAULT gen_random_uuid(),
    account_id       UUID                 NOT NULL UNIQUE REFERENCES account (id) ON DELETE CASCADE,
    principal_amount NUMERIC(19, 4)       NOT NULL,
    interest_rate    NUMERIC(5, 2)        NOT NULL,
    tenor_months     SMALLINT             NOT NULL CHECK (tenor_months IN (1, 3, 6, 12, 24)),
    maturity_date    DATE                 NOT NULL,
    interest_payout  interest_payout_type NOT NULL DEFAULT 'END_OF_TERM',
    auto_rollover    BOOLEAN              NOT NULL DEFAULT FALSE,
    created_at       TIMESTAMPTZ          NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- TABLE: rdn_detail
--
-- Stores extended attributes specific to RDN (Rekening Dana Nasabah) accounts.
-- One-to-one with account (each RDN account has exactly one row here).
--
-- Notes:
--   - sid (Single Investor ID) is issued by KSEI and must be unique per investor.
--   - verified_at is null until the account is validated by the securities company.
--   - An unverified RDN account cannot be used for capital market transactions.
-- -----------------------------------------------------------------------------

CREATE TABLE rdn_detail
(
    id                 UUID PRIMARY KEY      DEFAULT gen_random_uuid(),
    account_id         UUID         NOT NULL UNIQUE REFERENCES account (id) ON DELETE CASCADE,
    sid                VARCHAR(15)  NOT NULL UNIQUE,
    securities_company VARCHAR(100) NOT NULL,
    verified_at        TIMESTAMPTZ,
    created_at         TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- TABLE: balance_ledger
--
-- Internal append-only ledger for account balance mutations.
-- NOT user-facing — transaction history lives in transaction-service.
--
-- Written by the Kafka consumer (transaction.completed event) after
-- account.balance is updated.
--
-- Notes:
--   - reference_id is the idempotency key from transaction-service.
--     UNIQUE constraint prevents double-posting on Kafka redelivery.
--   - amount sign convention: positive = CREDIT, negative = DEBIT.
--   - balance_before / balance_after captured at write time for audit.
--   - Rows are never updated or deleted (append-only).
-- -----------------------------------------------------------------------------

CREATE TABLE balance_ledger (
    id             UUID PRIMARY KEY     DEFAULT gen_random_uuid(),
    account_id     UUID        NOT NULL REFERENCES account (id),
    amount         NUMERIC(19, 4) NOT NULL,  -- positif = credit, negatif = debit
    balance_before NUMERIC(19, 4) NOT NULL,
    balance_after  NUMERIC(19, 4) NOT NULL,
    reference_id   VARCHAR(100) UNIQUE,      -- idempotency key from tx-service
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_txn_account_id ON balance_ledger (account_id);
CREATE INDEX idx_txn_created_at ON balance_ledger (created_at DESC);
CREATE INDEX idx_txn_reference ON balance_ledger (reference_id);