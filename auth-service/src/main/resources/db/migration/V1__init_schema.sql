CREATE
EXTENSION IF NOT EXISTS "uuid-ossp";

CREATE SEQUENCE user_code_seq
    START WITH 1
    INCREMENT BY 1;

CREATE TABLE users
(
    id             UUID PRIMARY KEY      DEFAULT uuid_generate_v4(),
    user_code      VARCHAR(30)  NOT NULL UNIQUE,
    full_name      VARCHAR(150) NOT NULL,
    email          VARCHAR(100) NOT NULL UNIQUE,
    phone_number   VARCHAR(20)  NOT NULL UNIQUE,
    password_hash  VARCHAR(255) NOT NULL,
    nik            CHAR(16)     NOT NULL UNIQUE,
    address        TEXT,
    date_of_birth  DATE,
    role           VARCHAR(100) NOT NULL DEFAULT 'CUSTOMER',             -- ('CUSTOMER', 'ADMIN', 'TELLER');
    status         VARCHAR(100) NOT NULL DEFAULT 'PENDING_VERIFICATION', -- ('ACTIVE', 'INACTIVE', 'SUSPENDED', 'PENDING_VERIFICATION');
    email_verified BOOLEAN      NOT NULL DEFAULT FALSE,
    failed_login   SMALLINT     NOT NULL DEFAULT 0,
    locked_until   TIMESTAMPTZ,
    last_login_at  TIMESTAMPTZ,
    created_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    deleted_at     TIMESTAMPTZ
);

CREATE INDEX idx_users_email ON users (email) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_nik ON users (nik) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_phone ON users (phone_number) WHERE deleted_at IS NULL;
CREATE INDEX idx_users_status ON users (status);

COMMENT
ON TABLE users
IS 'Master data for customers and internal system users';

COMMENT
ON COLUMN users.nik
IS 'Indonesian National ID Number (16 digits)';

COMMENT
ON COLUMN users.failed_login
IS 'Reset to 0 after a successful login. Account is locked when value >= 5';

COMMENT
ON COLUMN users.password_hash
IS 'BCrypt hashed password — NEVER store plain text passwords';


CREATE TABLE refresh_tokens
(
    id         UUID PRIMARY KEY      DEFAULT uuid_generate_v4(),
    user_id    UUID         NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL UNIQUE, -- make sure hash
    expires_at TIMESTAMPTZ  NOT NULL,
    revoked    BOOLEAN      NOT NULL DEFAULT FALSE,
    revoked_at TIMESTAMPTZ,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_refresh_tokens_user ON refresh_tokens (user_id);
CREATE INDEX idx_refresh_tokens_hash ON refresh_tokens (token_hash) WHERE revoked = FALSE;
