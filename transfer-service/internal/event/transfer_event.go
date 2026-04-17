package event

import (
	"time"

	"github.com/shopspring/decimal"
)

// TransferEvent is published to Kafka topic: transfer.event
// Consumed by account-service to update balances.
type TransferEvent struct {
	UserCode            string          `json:"user_code"`             // for bushiness logic like send email
	ReferenceID         string          `json:"reference_id"`          // idempotency key
	SourceAccountNumber string          `json:"source_account_number"` // account to debit
	TargetAccountNumber string          `json:"target_account_number"` // account to credit
	Amount              decimal.Decimal `json:"amount"`                // always positive
	Currency            string          `json:"currency"`              // source currency
	OccurredAt          time.Time       `json:"occurred_at"`
}
