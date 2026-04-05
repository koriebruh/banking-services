package model

import (
	"fmt"
	"golang-clean-architecture/internal/entity"
	"time"

	"github.com/google/uuid"
	"github.com/shopspring/decimal"
)

// ------------------------------------
// REQUEST DTOs
// ------------------------------------

type TopUpRequest struct {
	TargetAccountNumber string          `json:"target_account_number" validate:"required,len=10,numeric"`
	Amount              decimal.Decimal `json:"amount"                validate:"required,gt=0"`
	Currency            string          `json:"currency"              validate:"required,len=3,uppercase"`
	Description         *string         `json:"description"           validate:"omitempty,max=255"`
}

type TopUpResponse struct {
	ReferenceID         string          `json:"reference_id"`
	Status              string          `json:"status"`
	TargetAccountNumber string          `json:"target_account_number"`
	Amount              decimal.Decimal `json:"amount"`
	Currency            string          `json:"currency"`
	Description         *string         `json:"description"`
	SettledAt           *time.Time      `json:"settled_at"`
}

func (r *TopUpRequest) ToEntity(userID uuid.UUID) *entity.Transfer {
	desc := r.Description
	settledAt := time.Now().UTC()
	return &entity.Transfer{
		ID:                  uuid.New(),
		ReferenceID:         generateReferenceID(),
		UserID:              userID,
		TransferType:        entity.TransferTypeTopUp,
		Status:              entity.TransferStatusCompleted, // langsung COMPLETED
		SourceAccountNumber: "EXTERNAL",
		TargetAccountNumber: r.TargetAccountNumber,
		Amount:              r.Amount,
		SourceCurrency:      r.Currency,
		TargetCurrency:      r.Currency,
		Description:         desc,
		SettledAt:           &settledAt,
		CreatedAt:           time.Now().UTC(),
		UpdatedAt:           time.Now().UTC(),
	}
}

type InitiateTransferRequest struct {
	SourceAccountNumber string          `json:"source_account_number" validate:"required,len=10,numeric"`
	TargetAccountNumber string          `json:"target_account_number" validate:"required,len=10,numeric,nefield=SourceAccountNumber"`
	Amount              decimal.Decimal `json:"amount"                validate:"required,gt=0"`
	SourceCurrency      string          `json:"source_currency"       validate:"required,len=3,uppercase"`
	TargetCurrency      string          `json:"target_currency"       validate:"required,len=3,uppercase"`
	Description         *string         `json:"description"           validate:"omitempty,max=255"`
}

// ToEntity converts the request user into entity
func (r *InitiateTransferRequest) ToEntity(userID uuid.UUID) *entity.Transfer {
	return &entity.Transfer{
		ID:                  uuid.New(),
		ReferenceID:         generateReferenceID(),
		UserID:              userID,
		TransferType:        entity.TransferTypeInternal,
		Status:              entity.TransferStatusPending,
		SourceAccountNumber: r.SourceAccountNumber,
		TargetAccountNumber: r.TargetAccountNumber,
		Amount:              r.Amount,
		SourceCurrency:      r.SourceCurrency,
		TargetCurrency:      r.TargetCurrency,
		Description:         r.Description,
		CreatedAt:           time.Now().UTC(),
		UpdatedAt:           time.Now().UTC(),
	}
}

func generateReferenceID() string {
	return fmt.Sprintf("TXN-%s-%s",
		time.Now().UTC().Format("20060102"),
		uuid.New().String()[:8],
	)
}

type CancelTransferRequest struct {
	Reason *string `json:"reason" validate:"omitempty,max=255"`
}

// ------------------------------------
// RESPONSE DTOs
// ------------------------------------

type InitiateTransferResponse struct {
	ReferenceID         string           `json:"reference_id"`
	Status              string           `json:"status"`
	TransferType        string           `json:"transfer_type"`
	SourceAccountNumber string           `json:"source_account_number"`
	TargetAccountNumber string           `json:"target_account_number"`
	Amount              decimal.Decimal  `json:"amount"`
	SourceCurrency      string           `json:"source_currency"`
	TargetCurrency      string           `json:"target_currency"`
	ExchangeRate        *decimal.Decimal `json:"exchange_rate"`
	ConvertedAmount     *decimal.Decimal `json:"converted_amount"`
	Description         *string          `json:"description"`
	CreatedAt           time.Time        `json:"created_at"`
}

type ConfirmTransferResponse struct {
	ReferenceID string     `json:"reference_id"`
	Status      string     `json:"status"`
	SettledAt   *time.Time `json:"settled_at"`
}

type CancelTransferResponse struct {
	ReferenceID   string  `json:"reference_id"`
	Status        string  `json:"status"`
	FailureReason *string `json:"failure_reason"`
}

type TransferDetailResponse struct {
	ReferenceID         string           `json:"reference_id"`
	Status              string           `json:"status"`
	TransferType        string           `json:"transfer_type"`
	SourceAccountNumber string           `json:"source_account_number"`
	TargetAccountNumber string           `json:"target_account_number"`
	Amount              decimal.Decimal  `json:"amount"`
	SourceCurrency      string           `json:"source_currency"`
	TargetCurrency      string           `json:"target_currency"`
	ExchangeRate        *decimal.Decimal `json:"exchange_rate"`
	ConvertedAmount     *decimal.Decimal `json:"converted_amount"`
	Description         *string          `json:"description"`
	FailureReason       *string          `json:"failure_reason"`
	CreatedAt           time.Time        `json:"created_at"`
	SettledAt           *time.Time       `json:"settled_at"`
	UpdatedAt           time.Time        `json:"updated_at"`
}

type TransferHistoryItem struct {
	ReferenceID              string          `json:"reference_id"`
	Direction                string          `json:"direction"` // DEBIT | CREDIT
	Amount                   decimal.Decimal `json:"amount"`
	Currency                 string          `json:"currency"`
	CounterpartAccountNumber string          `json:"counterpart_account_number"`
	Description              *string         `json:"description"`
	Status                   string          `json:"status"`
	SettledAt                *time.Time      `json:"settled_at"`
}

type TransferListResponse struct {
	Data       []TransferDetailResponse `json:"data"`
	Pagination Pagination               `json:"pagination"`
}

type TransferHistoryResponse struct {
	AccountNumber string                `json:"account_number"`
	Data          []TransferHistoryItem `json:"data"`
	Pagination    Pagination            `json:"pagination"`
}

// ------------------------------------
// SHARED
// ------------------------------------

type TransferQueryParams struct {
	Status string `form:"status"`
	From   string `form:"from"`
	To     string `form:"to"`
	Page   int    `form:"page,default=0"`
	Size   int    `form:"size,default=20"`
}

type Pagination struct {
	Page       int   `json:"page"`
	Limit      int   `json:"limit"`
	TotalItems int64 `json:"total_items"`
	TotalPages int64 `json:"total_pages"`
}
