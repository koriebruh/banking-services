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

// Banking Best Practice: 
// - Gunakan struct tag yang eksplisit (`json:"..."`)
// - Gunakan tipe data time.Time untuk kolom waktu agar mudah di validasi/formatting.
// - Gunakan raw json / `map[string]interface{}` untuk metadata yang dinamis, 
//   memudahkan extensibility (schema evolution).
// - Untuk currency/uang, lebih aman menggunakan Decimal dibandingkan float64 untuk menghindari masalah presisi.

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

// AuthEvent merepresentasikan payload dari auth-service (sesuai struktur AccountEvent.java)
type AuthEvent struct {
	EventID      string                 `json:"event_id"`
	EventType    AuthEventType          `json:"event_type"` // e.g. user.login.success
	EventVersion string                 `json:"event_version"`
	OccurredAt   time.Time              `json:"occurred_at"`
	UserCode     string                 `json:"user_code"` // Identitas non-sensitive/Business ID
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

// AccountEvent merepresentasikan payload dari account-service (sesuai struktur AccountEvent.java)
type AccountEvent struct {
	EventID       string                 `json:"event_id"`
	EventType     AccountEventType       `json:"event_type"` // e.g. account.opened
	EventVersion  string                 `json:"event_version"`
	OccurredAt    time.Time              `json:"occurred_at"`
	UserCode      string                 `json:"user_code"` // Business identifier dari user
	AccountNumber string                 `json:"account_number"`
	AccountType   string                 `json:"account_type"` // SAVINGS | CURRENT | DEPOSIT | RDN
	Metadata      map[string]interface{} `json:"metadata"`
}

// ── Transfer events ───────────────────────────────────────────────────────────

type NotificationType string

const (
	NotificationTransferConfirmed NotificationType = "TRANSFER_CONFIRMED"
	NotificationTopUpSuccess      NotificationType = "TOP_UP_SUCCESS"
)

// TransferEventData menampung detail asli dari transfer (Sesuai go struct TransferEvent)
type TransferEventData struct {
	ReferenceID         string          `json:"reference_id"`
	SourceAccountNumber string          `json:"source_account_number"`
	TargetAccountNumber string          `json:"target_account_number"`
	Amount              decimal.Decimal `json:"amount"`
	Currency            string          `json:"currency"`
	Note                string          `json:"note,omitempty"` // Menyesuaikan json contoh
}

// StructuredTransferEvent adalah wrapper kasar sesuai format JSON endpoint Websocket atau payload transfer Notification
type StructuredTransferEvent struct {
	Type      NotificationType  `json:"type"` // e.g TRANSFER_CONFIRMED
	Data      TransferEventData `json:"data"`
	Timestamp time.Time         `json:"timestamp"`
}

// Catatan: Jika Kafka topic transfer.events masih mengirim struktur flat (TransferEvent go murni):
type TransferEvent struct {
	ReferenceID         string          `json:"reference_id"`
	SourceAccountNumber string          `json:"source_account_number"`
	TargetAccountNumber string          `json:"target_account_number"`
	Amount              decimal.Decimal `json:"amount"`
	Currency            string          `json:"currency"`
	OccurredAt          time.Time       `json:"occurred_at"`
}
