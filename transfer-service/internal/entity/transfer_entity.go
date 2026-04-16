package entity

import (
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// TransferStatus represents the lifecycle state of a transfer
type TransferStatus string

const (
	TransferStatusPending    TransferStatus = "PENDING"
	TransferStatusProcessing TransferStatus = "PROCESSING"
	TransferStatusCompleted  TransferStatus = "COMPLETED"
	TransferStatusFailed     TransferStatus = "FAILED"
	TransferStatusReversed   TransferStatus = "REVERSED"
)

// TransferType classifies the transfer by business intent
type TransferType string

const (
	TransferTypeInternal   TransferType = "INTERNAL"
	TransferTypeExternal   TransferType = "EXTERNAL"
	TransferTypeTopUp      TransferType = "TOP_UP"
	TransferTypeWithdrawal TransferType = "WITHDRAWAL"
)

// Transfer is the core record of every fund movement.
// Source of truth for transaction history — account-service only
// stores internal balance mutations, not the full transfer context.
type Transfer struct {
	ID           uuid.UUID      `gorm:"column:id;primaryKey"`
	ReferenceID  string         `gorm:"column:reference_id;uniqueIndex"` // idempotency key, format: TXN-{YYYYMMDD}-{UUID8}
	UserID       uuid.UUID      `gorm:"column:user_id"`      // owner, from auth-service from claim with JWT
	TransferType TransferType   `gorm:"column:transfer_type"`
	Status       TransferStatus `gorm:"column:status"`

	// Account references (no FK — cross-service boundary), validate account get from grpc call to account-service
	SourceAccountNumber string `gorm:"column:source_account_number"`
	TargetAccountNumber string `gorm:"column:target_account_number"`

	// Monetary fields
	Amount          decimal.Decimal  `gorm:"column:amount"`           // NUMERIC(19,4) → string to preserve precision
	SourceCurrency  string           `gorm:"column:source_currency"`  // ISO 4217, e.g. IDR
	TargetCurrency  string           `gorm:"column:target_currency"`  // ISO 4217, e.g. USD
	ExchangeRate    *decimal.Decimal `gorm:"column:exchange_rate"`    // NULL if same currency
	ConvertedAmount *decimal.Decimal `gorm:"column:converted_amount"` // NULL if same currency

	// Context
	Description   *string `gorm:"column:description"`
	FailureReason *string `gorm:"column:failure_reason"`

	// Timestamps
	CreatedAt time.Time  `gorm:"column:created_at"`
	SettledAt *time.Time `gorm:"column:settled_at"` // set when COMPLETED
	UpdatedAt time.Time  `gorm:"column:updated_at"`
}

func (Transfer) TableName() string {
	return "transfer"
}
