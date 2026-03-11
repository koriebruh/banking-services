-- =============================================================================
-- V2__convert_enum_to_varchar_with_check.sql
-- =============================================================================

-- -----------------------------------------------------------------------------
-- STEP 1: Drop default values yang terikat ke enum type
-- -----------------------------------------------------------------------------
ALTER TABLE account
    ALTER COLUMN status DROP DEFAULT;
ALTER TABLE deposit_detail
    ALTER COLUMN interest_payout DROP DEFAULT;

-- -----------------------------------------------------------------------------
-- STEP 2: Convert kolom ke VARCHAR
-- -----------------------------------------------------------------------------
ALTER TABLE account
ALTER
COLUMN account_type TYPE VARCHAR(20),
    ALTER
COLUMN status TYPE VARCHAR(20);

ALTER TABLE deposit_detail
ALTER
COLUMN interest_payout TYPE VARCHAR(20);

ALTER TABLE account_transaction
ALTER
COLUMN type TYPE VARCHAR(20);

-- -----------------------------------------------------------------------------
-- STEP 3: Restore default values (sekarang sebagai plain string)
-- -----------------------------------------------------------------------------
ALTER TABLE account
    ALTER COLUMN status SET DEFAULT 'ACTIVE';
ALTER TABLE deposit_detail
    ALTER COLUMN interest_payout SET DEFAULT 'END_OF_TERM';

-- -----------------------------------------------------------------------------
-- STEP 4: Add CHECK constraints
-- -----------------------------------------------------------------------------
ALTER TABLE account
    ADD CONSTRAINT chk_account_type
        CHECK (account_type IN ('SAVINGS', 'CURRENT', 'DEPOSIT', 'RDN')),
    ADD CONSTRAINT chk_account_status
        CHECK (status IN ('ACTIVE', 'FROZEN', 'CLOSED'));

ALTER TABLE deposit_detail
    ADD CONSTRAINT chk_interest_payout_type
        CHECK (interest_payout IN ('END_OF_TERM', 'MONTHLY'));

ALTER TABLE account_transaction
    ADD CONSTRAINT chk_transaction_type
        CHECK (type IN ('CREDIT', 'DEBIT'));


-- CONSTRAINT tambahan untuk memastikan tidak ada duplikasi account_type per user_id
ALTER TABLE account
    ADD CONSTRAINT uq_user_account_type UNIQUE (user_id, account_type);

ALTER TABLE rdn_detail
DROP CONSTRAINT IF EXISTS rdn_detail_sid_key,
    ADD CONSTRAINT uq_rdn_sid UNIQUE (sid);

-- -----------------------------------------------------------------------------
-- STEP 5: Drop enum types (aman setelah semua dependency dilepas)
-- -----------------------------------------------------------------------------
DROP TYPE IF EXISTS account_type;
DROP TYPE IF EXISTS account_status;
DROP TYPE IF EXISTS interest_payout_type;
DROP TYPE IF EXISTS transaction_type;