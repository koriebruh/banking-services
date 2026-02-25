## Schema per Service

---

### 1. Auth Service

```sql
-- User credentials
CREATE TABLE users (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username        VARCHAR(50) UNIQUE NOT NULL,
    password        VARCHAR(255) NOT NULL,  -- bcrypt
    email           VARCHAR(100) UNIQUE NOT NULL,
    phone           VARCHAR(20) UNIQUE NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'ACTIVE', -- ACTIVE, INACTIVE, LOCKED
    failed_attempts INT DEFAULT 0,
    locked_at       TIMESTAMP,
    created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Refresh token
CREATE TABLE refresh_tokens (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id     UUID NOT NULL REFERENCES users(id),
    token       VARCHAR(500) UNIQUE NOT NULL,
    device_id   VARCHAR(100),  -- dari mana login (HP, web, dll)
    ip_address  VARCHAR(50),
    is_revoked  BOOLEAN DEFAULT FALSE,
    expired_at  TIMESTAMP NOT NULL,
    created_at  TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);
CREATE INDEX idx_refresh_tokens_token ON refresh_tokens(token);
```

---

### 2. Account Service

```sql
-- Data rekening
CREATE TABLE accounts (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_number  VARCHAR(20) UNIQUE NOT NULL,
    user_id         UUID NOT NULL,  -- reference ke auth service (tidak FK, beda DB)
    account_name    VARCHAR(100) NOT NULL,
    account_type    VARCHAR(20) NOT NULL,  -- SAVINGS, GIRO
    status          VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',  -- ACTIVE, INACTIVE, FROZEN, CLOSED
    currency        VARCHAR(3) NOT NULL DEFAULT 'IDR',
    created_at      TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Saldo rekening (dipisah dari accounts untuk locking yang lebih granular)
CREATE TABLE account_balances (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id      UUID NOT NULL REFERENCES accounts(id),
    available       BIGINT NOT NULL DEFAULT 0,  -- dalam sen/rupiah terkecil
    current         BIGINT NOT NULL DEFAULT 0,
    hold            BIGINT NOT NULL DEFAULT 0,
    version         BIGINT NOT NULL DEFAULT 0,  -- optimistic locking
    updated_at      TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Limit transaksi per rekening
CREATE TABLE account_limits (
    id                      UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    account_id              UUID NOT NULL REFERENCES accounts(id),
    daily_transfer_limit    BIGINT NOT NULL DEFAULT 50000000,   -- 50jt
    per_trx_limit           BIGINT NOT NULL DEFAULT 25000000,   -- 25jt
    daily_used              BIGINT NOT NULL DEFAULT 0,
    reset_at                TIMESTAMP,  -- kapan daily_used di-reset
    updated_at              TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_accounts_account_number ON accounts(account_number);
CREATE INDEX idx_accounts_user_id ON accounts(user_id);
CREATE INDEX idx_account_balances_account_id ON account_balances(account_id);
```

---

### 3. Transfer Service

```sql
-- Inquiry (sebelum transfer)
CREATE TABLE inquiries (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    inquiry_id                  VARCHAR(50) UNIQUE NOT NULL,
    source_account_number       VARCHAR(20) NOT NULL,
    destination_account_number  VARCHAR(20) NOT NULL,
    destination_account_name    VARCHAR(100) NOT NULL,
    amount                      BIGINT NOT NULL,
    currency                    VARCHAR(3) NOT NULL DEFAULT 'IDR',
    fee                         BIGINT NOT NULL DEFAULT 0,
    total_amount                BIGINT NOT NULL,
    note                        VARCHAR(255),
    status                      VARCHAR(20) NOT NULL DEFAULT 'ACTIVE',  -- ACTIVE, USED, EXPIRED
    expired_at                  TIMESTAMP NOT NULL,
    created_at                  TIMESTAMP NOT NULL DEFAULT NOW()
);

-- Data transfer
CREATE TABLE transfers (
    id                          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transfer_id                 VARCHAR(50) UNIQUE NOT NULL,
    reference_number            VARCHAR(50) UNIQUE NOT NULL,
    inquiry_id                  VARCHAR(50) NOT NULL,
    idempotency_key             VARCHAR(100) UNIQUE NOT NULL,
    source_account_number       VARCHAR(20) NOT NULL,
    destination_account_number  VARCHAR(20) NOT NULL,
    amount                      BIGINT NOT NULL,
    currency                    VARCHAR(3) NOT NULL DEFAULT 'IDR',
    fee                         BIGINT NOT NULL DEFAULT 0,
    total_amount                BIGINT NOT NULL,
    note                        VARCHAR(255),
    status                      VARCHAR(20) NOT NULL DEFAULT 'PROCESSING',
    -- PROCESSING, COMPLETED, FAILED, CANCELLED
    failure_reason              VARCHAR(255),
    user_id                     UUID NOT NULL,
    initiated_at                TIMESTAMP NOT NULL DEFAULT NOW(),
    processed_at                TIMESTAMP,
    completed_at                TIMESTAMP,
    cancelled_at                TIMESTAMP
);

CREATE INDEX idx_transfers_transfer_id ON transfers(transfer_id);
CREATE INDEX idx_transfers_reference_number ON transfers(reference_number);
CREATE INDEX idx_transfers_source_account ON transfers(source_account_number);
CREATE INDEX idx_transfers_destination_account ON transfers(destination_account_number);
CREATE INDEX idx_transfers_user_id ON transfers(user_id);
CREATE INDEX idx_transfers_status ON transfers(status);
CREATE INDEX idx_inquiries_inquiry_id ON inquiries(inquiry_id);
```

---

### 4. Audit Service

```sql
-- Journal entry keuangan (immutable)
CREATE TABLE journal_entries (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    journal_id      VARCHAR(50) UNIQUE NOT NULL,
    transfer_id     VARCHAR(50) NOT NULL,
    type            VARCHAR(10) NOT NULL,  -- DEBIT, CREDIT
    account_number  VARCHAR(20) NOT NULL,
    amount          BIGINT NOT NULL,
    balance_before  BIGINT NOT NULL,
    balance_after   BIGINT NOT NULL,
    currency        VARCHAR(3) NOT NULL DEFAULT 'IDR',
    created_at      TIMESTAMP NOT NULL DEFAULT NOW()
    -- tidak ada updated_at, immutable!
);

-- Audit trail semua event (immutable)
CREATE TABLE audit_trails (
    id          UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    transfer_id VARCHAR(50) NOT NULL,
    event_type  VARCHAR(50) NOT NULL,
    -- TRANSFER_INITIATED, TRANSFER_COMPLETED, TRANSFER_FAILED, TRANSFER_CANCELLED
    actor       VARCHAR(100),   -- userId atau 'SYSTEM'
    ip_address  VARCHAR(50),
    payload     JSONB NOT NULL, -- raw event dari Kafka
    created_at  TIMESTAMP NOT NULL DEFAULT NOW()
    -- tidak ada updated_at, immutable!
);

CREATE INDEX idx_journal_entries_transfer_id ON journal_entries(transfer_id);
CREATE INDEX idx_journal_entries_account_number ON journal_entries(account_number);
CREATE INDEX idx_audit_trails_transfer_id ON audit_trails(transfer_id);
CREATE INDEX idx_audit_trails_event_type ON audit_trails(event_type);
CREATE INDEX idx_audit_trails_created_at ON audit_trails(created_at);
```

---

### 5. Notification Service

```
Tidak ada DB ✅
Cukup consume Kafka → kirim notif → selesai
```

---

## Catatan Penting

**Tidak ada FK antar service** — karena beda DB. Relasi antar service hanya lewat `account_number`, `transfer_id`, `user_id` sebagai reference biasa (bukan foreign key).

**Semua amount pakai BIGINT** — bukan DECIMAL/FLOAT, untuk hindari floating point error di kalkulasi uang. Simpan dalam satuan terkecil (rupiah, bukan juta).

**Optimistic locking di `account_balances`** — pakai kolom `version` untuk hindari race condition saat concurrent update saldo.

---

Mau lanjut docker compose per service atau langsung ke struktur kode Spring WebFlux nya?