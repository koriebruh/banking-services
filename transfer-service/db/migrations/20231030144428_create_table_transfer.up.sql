-- =============================================================================
-- create_table_transfer.sql
-- Transfer Service — Initial Schema
--
-- Tables:
--   1. transfer — Core transfer record (source of truth for all transactions)
-- =============================================================================

-- -----------------------------------------------------------------------------
-- ENUM TYPES
-- -----------------------------------------------------------------------------

-- Current state of a transfer in its lifecycle
CREATE TYPE transfer_status AS ENUM (
    'PENDING',    -- Created, awaiting account validation
    'PROCESSING', -- Account validated, balance update in progress
    'COMPLETED',  -- Successfully settled, Kafka event published
    'FAILED',     -- Rejected due to validation failure or system error
    'REVERSED'    -- Completed but subsequently reversed
);

-- Classification of transfer by business intent
CREATE TYPE transfer_type AS ENUM (
    'INTERNAL',   -- Between two accounts within this bank
    'EXTERNAL',   -- Outbound to another bank (future: BI-FAST, RTGS, SWIFT)
    'TOP_UP',     -- Inbound funding from external source
    'WITHDRAWAL'  -- Outbound cash withdrawal
);

-- -----------------------------------------------------------------------------
-- TABLE: transfer
--
-- Immutable record of every fund movement initiated by a customer or system.
-- This is the source of truth for transaction history — account-service only
-- stores internal balance mutations, not the full transfer context.
--
-- Notes:
--   - reference_id is a globally unique idempotency key generated at creation.
--     Format: TXN-{YYYYMMDD}-{UUID8}. Published to Kafka and stored in
--     account-service.balance_ledger for double-posting prevention.
--   - source and target account numbers are stored as strings (no FK) because
--     account-service owns account data — cross-service boundary.
--   - exchange_rate is captured at execution time (not recalculated later).
--     NULL if source and target currencies are the same.
--   - settled_at is set when status transitions to COMPLETED.
--   - failure_reason is set when status transitions to FAILED.
--   - Rows are never deleted. Status transitions are the audit trail.
-- -----------------------------------------------------------------------------

CREATE TABLE transfer
(
    id                    UUID PRIMARY KEY         DEFAULT gen_random_uuid(),
    reference_id          VARCHAR(50)     NOT NULL UNIQUE, -- idempotency key
    user_id               UUID            NOT NULL,        -- owner, from auth-service
    transfer_type         transfer_type   NOT NULL,
    status                transfer_status NOT NULL DEFAULT 'PENDING',

    -- Account references (no FK — cross-service boundary)
    source_account_number VARCHAR(10)     NOT NULL,
    target_account_number VARCHAR(10)     NOT NULL,

    -- Monetary fields
    amount                NUMERIC(19, 4)  NOT NULL CHECK (amount > 0),
    source_currency       VARCHAR(3)      NOT NULL,        -- ISO 4217, e.g. IDR
    target_currency       VARCHAR(3)      NOT NULL,        -- ISO 4217, e.g. USD
    exchange_rate         NUMERIC(19, 8),                  -- NULL if same currency
    converted_amount      NUMERIC(19, 4),                  -- NULL if same currency

    -- Context
    description           VARCHAR(255),
    failure_reason        VARCHAR(500),

    -- Timestamps
    created_at            TIMESTAMPTZ     NOT NULL DEFAULT NOW(),
    settled_at            TIMESTAMPTZ,
    updated_at            TIMESTAMPTZ     NOT NULL DEFAULT NOW()
);

-- -----------------------------------------------------------------------------
-- INDEXES
-- -----------------------------------------------------------------------------

CREATE INDEX idx_transfer_reference_id ON transfer (reference_id);
CREATE INDEX idx_transfer_user_id ON transfer (user_id);
CREATE INDEX idx_transfer_source_account ON transfer (source_account_number);
CREATE INDEX idx_transfer_target_account ON transfer (target_account_number);
CREATE INDEX idx_transfer_status ON transfer (status);
CREATE INDEX idx_transfer_created_at ON transfer (created_at DESC);