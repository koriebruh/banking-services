-- ==========================================================================
-- Audit Service — Append-Only Audit Trail
-- Banking Best Practice:
--   * event_id UNIQUE → idempotent insert (ON CONFLICT DO NOTHING)
--   * JSONB payload → schema-evolution friendly
--   * occurred_at vs received_at → clear event-time vs processing-time
--   * TIMESTAMPTZ → timezone-aware, mandatory for multi-region banking
--   * CHECK constraint pada event_source → data-integrity at DB level
-- ==========================================================================

CREATE TABLE IF NOT EXISTS audit_logs (
    id              BIGSERIAL       PRIMARY KEY,
    event_id        VARCHAR(64)     NOT NULL UNIQUE,
    event_type      VARCHAR(64)     NOT NULL,
    event_source    VARCHAR(32)     NOT NULL,
    user_code       VARCHAR(64)     NOT NULL,
    resource_type   VARCHAR(32),
    resource_id     VARCHAR(128),
    ip_address      VARCHAR(45),
    user_agent      TEXT,
    payload         JSONB           NOT NULL DEFAULT '{}',
    occurred_at     TIMESTAMPTZ     NOT NULL,
    received_at     TIMESTAMPTZ     NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_event_source CHECK (event_source IN ('AUTH', 'ACCOUNT', 'TRANSFER'))
);

-- ── Indexes for Banking Audit Query Patterns ──────────────────────────────

-- Lookup by user
CREATE INDEX idx_audit_logs_user_code    ON audit_logs (user_code);

-- Filter by event classification
CREATE INDEX idx_audit_logs_event_type   ON audit_logs (event_type);
CREATE INDEX idx_audit_logs_event_source ON audit_logs (event_source);

-- Time-range queries (regulatory reporting, investigation)
CREATE INDEX idx_audit_logs_occurred_at  ON audit_logs (occurred_at);

-- Resource lookup (e.g. "all events for account X")
CREATE INDEX idx_audit_logs_resource     ON audit_logs (resource_type, resource_id);

-- Composite: "all events for user X ordered by time" — most common audit query
CREATE INDEX idx_audit_logs_user_time    ON audit_logs (user_code, occurred_at DESC);
