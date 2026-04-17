package event

import (
	"time"

	"github.com/shopspring/decimal"
)

// Topic names consumed by this service.
const (
	TopicTransfer = "transfer.events"
	TopicAuth     = "auth.events"
	TopicAccount  = "account.events"
)

// EventSource constants — digunakan untuk klasifikasi audit log.
const (
	SourceAuth     = "AUTH"
	SourceAccount  = "ACCOUNT"
	SourceTransfer = "TRANSFER"
)

// ── Auth events ───────────────────────────────────────────────────────────────

type AuthEventType string

const (
	AuthUserRegistered AuthEventType = "user.registered"
	AuthLoginSuccess   AuthEventType = "user.login.success"
	AuthLoginFailed    AuthEventType = "user.login.failed"
	AuthPasswordChange AuthEventType = "user.password.changed"
	AuthPasswordReset  AuthEventType = "user.password.reset"
	AuthMfaEnabled     AuthEventType = "user.mfa.enabled"
	AuthMfaValidated   AuthEventType = "user.mfa.validated"
	AuthAccountLocked  AuthEventType = "user.account.locked"
	AuthLogout         AuthEventType = "user.logout"
)

// AuthEvent merepresentasikan payload dari auth-service.
type AuthEvent struct {
	EventID      string                 `json:"event_id"`
	EventType    AuthEventType          `json:"event_type"`
	EventVersion string                 `json:"event_version"`
	OccurredAt   time.Time              `json:"occurred_at"`
	UserCode     string                 `json:"user_code"`
	Email        string                 `json:"email"`
	IPAddress    string                 `json:"ip_address"`
	UserAgent    string                 `json:"user_agent"`
	Metadata     map[string]interface{} `json:"metadata"`
}

// ── Account events ────────────────────────────────────────────────────────────

type AccountEventType string

const (
	AccountOpened   AccountEventType = "account.opened"
	AccountFrozen   AccountEventType = "account.frozen"
	AccountClosed   AccountEventType = "account.closed"
	AccountUnfrozen AccountEventType = "account.unfrozen"
	DepositMatured  AccountEventType = "account.deposit.matured"
	RdnVerified     AccountEventType = "account.rdn.verified"
)

// AccountEvent merepresentasikan payload dari account-service.
type AccountEvent struct {
	EventID       string                 `json:"event_id"`
	EventType     AccountEventType       `json:"event_type"`
	EventVersion  string                 `json:"event_version"`
	OccurredAt    time.Time              `json:"occurred_at"`
	UserCode      string                 `json:"user_code"`
	AccountNumber string                 `json:"account_number"`
	AccountType   string                 `json:"account_type"`
	Metadata      map[string]interface{} `json:"metadata"`
}

// ── Transfer events ───────────────────────────────────────────────────────────

// TransferEvent merepresentasikan payload dari transfer-service (format flat).
type TransferEvent struct {
	UserCode            string          `json:"user_code"`
	ReferenceID         string          `json:"reference_id"`
	SourceAccountNumber string          `json:"source_account_number"`
	TargetAccountNumber string          `json:"target_account_number"`
	Amount              decimal.Decimal `json:"amount"`
	Currency            string          `json:"currency"`
	OccurredAt          time.Time       `json:"occurred_at"`
}
