package usecase

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"golang-clean-architecture/internal/entity"
	"golang-clean-architecture/internal/event"
	"golang-clean-architecture/internal/gateway/grpc"
	"golang-clean-architecture/internal/gateway/messaging"
	"golang-clean-architecture/internal/model"
	"golang-clean-architecture/internal/repository"
	"golang-clean-architecture/internal/shared/exception"

	"github.com/go-playground/validator/v10"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"gorm.io/gorm"
)

type TransferUseCase struct {
	DB                 *gorm.DB
	Log                *logrus.Logger
	Validate           *validator.Validate
	TransferRepository *repository.TransferRepository
	TransferProducer   *messaging.TransferEventPublisher
	AccountGrpcClient  *grpc.AccountGrpcClient
}

func NewTransferUseCase(
	DB *gorm.DB,
	log *logrus.Logger,
	validate *validator.Validate,
	transferRepository *repository.TransferRepository,
	transferProducer *messaging.TransferEventPublisher,
	AccountGrpcClient *grpc.AccountGrpcClient,
) *TransferUseCase {
	return &TransferUseCase{
		DB:                 DB,
		Log:                log,
		Validate:           validate,
		TransferRepository: transferRepository,
		TransferProducer:   transferProducer,
		AccountGrpcClient:  AccountGrpcClient,
	}
}

func (uc *TransferUseCase) TopUp(ctx context.Context, userID uuid.UUID, req *model.TopUpRequest) (*model.TopUpResponse, error) {
	if err := uc.Validate.Struct(req); err != nil {
		return nil, err
	}

	// Validasi target account — cek ACTIVE
	targetResp, err := uc.AccountGrpcClient.GetAccountDetail(ctx, req.TargetAccountNumber)
	if err != nil {
		return nil, err
	}

	if targetResp.Status != "ACTIVE" {
		return nil, exception.ErrTargetAccountNotActive
	}

	transfer := req.ToEntity(userID)

	tx := uc.DB.Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	defer tx.Rollback()

	if err := uc.TransferRepository.Create(tx, transfer); err != nil {
		return nil, err
	}

	// Insert ke outbox table (Transactional Outbox) 
	// Event Kafka dibuat bareng dengan insert transfer dalam satu transaksi DB.
	kafkaEvent := event.TransferEvent{
		ReferenceID:         transfer.ReferenceID,
		SourceAccountNumber: "EXTERNAL",
		TargetAccountNumber: transfer.TargetAccountNumber,
		Amount:              transfer.Amount,
		Currency:            transfer.SourceCurrency,
	}
	
	payloadBytes, _ := json.Marshal(kafkaEvent)
	outbox := entity.OutboxEvent{
		ID:        uuid.New(),
		Topic:     "transfer.events", 
		Payload:   string(payloadBytes),
		Status:    entity.OutboxStatusPending,
		CreatedAt: time.Now().UTC(),
	}

	if err := tx.Create(&outbox).Error; err != nil {
		return nil, err
	}

	if err := tx.Commit().Error; err != nil {
		return nil, err
	}

	return &model.TopUpResponse{
		ReferenceID:         transfer.ReferenceID,
		Status:              string(transfer.Status),
		TargetAccountNumber: transfer.TargetAccountNumber,
		Amount:              transfer.Amount,
		Currency:            transfer.SourceCurrency,
		Description:         transfer.Description,
		SettledAt:           transfer.SettledAt,
	}, nil
}

// Initiate validates input, calls gRPC to validate both accounts,
// persists transfer as PENDING, and returns the draft for user review.
func (uc *TransferUseCase) Initiate(ctx context.Context, userID uuid.UUID, req *model.InitiateTransferRequest) (*model.InitiateTransferResponse, error) {
	if err := uc.Validate.Struct(req); err != nil {
		return nil, err
	}

	// Menggunakan errgroup untuk melakukan 2 gRPC call (source dan target) secara paralel (concurrently).
	// Ini akan menghemat waktu response sebesar selisih latency terlama diantara dua service. Sangat penting saat traffic payload tinggi.
	g, gCtx := errgroup.WithContext(ctx)

	// Goroutine 1: Validasi account source melalui gRPC
	g.Go(func() error {
		_, err := uc.AccountGrpcClient.ValidateAccount(gCtx,
			req.SourceAccountNumber,
			req.Amount.String(),
			req.SourceCurrency,
		)
		return err
	})

	// Goroutine 2: Get detail account target melalui gRPC
	g.Go(func() error {
		targetResp, err := uc.AccountGrpcClient.GetAccountDetail(gCtx, req.TargetAccountNumber)
		if err != nil {
			return err
		}
		if targetResp.Status != "ACTIVE" {
			return exception.ErrAccountNotActive
		}
		return nil
	})

	// Tunggu kedua goroutine selesai dieksekusi
	if err := g.Wait(); err != nil {
		return nil, err
	}

	transfer := req.ToEntity(userID)

	if err := uc.TransferRepository.Create(uc.DB, transfer); err != nil {
		uc.Log.Errorf("Failed to create transfer referenceId=%s: %v", transfer.ReferenceID, err)
		return nil, err
	}

	return toInitiateResponse(transfer), nil
}

// Confirm executes the transfer — transitions PENDING → COMPLETED and publishes Kafka event.
func (uc *TransferUseCase) Confirm(ctx context.Context, userID uuid.UUID, referenceID string) (*model.ConfirmTransferResponse, error) {
	tx := uc.DB.Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	defer tx.Rollback()

	// Gunakan FindByReferenceIDLocked untuk mengaplikasikan SELECT ... FOR UPDATE (Pessimistic locking)
	transfer, err := uc.TransferRepository.FindByReferenceIDLocked(tx, referenceID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, exception.ErrTransferNotFound
		}
		return nil, err
	}

	// Ownership check — prevent IDOR
	if transfer.UserID != userID {
		return nil, exception.ErrTransferNotFound
	}

	if transfer.Status != entity.TransferStatusPending {
		return nil, exception.ErrTransferNotConfirmable
	}

	settledAt := time.Now().UTC()

	if err := uc.TransferRepository.UpdateStatus(tx, referenceID, entity.TransferStatusCompleted, map[string]interface{}{
		"settled_at": settledAt,
	}); err != nil {
		uc.Log.Errorf("Failed to update transfer status referenceId=%s: %v", referenceID, err)
		return nil, err
	}

	// Publish Kafka event after status committed (Pindah ke Outbox)
	kafkaEvent := event.TransferEvent{
		ReferenceID:         transfer.ReferenceID,
		SourceAccountNumber: transfer.SourceAccountNumber,
		TargetAccountNumber: transfer.TargetAccountNumber,
		Amount:              transfer.Amount,
		Currency:            transfer.SourceCurrency,
	}

	payloadBytes, _ := json.Marshal(kafkaEvent)
	outbox := entity.OutboxEvent{
		ID:        uuid.New(),
		Topic:     "transfer.events",
		Payload:   string(payloadBytes),
		Status:    entity.OutboxStatusPending,
		CreatedAt: time.Now().UTC(),
	}

	if err := tx.Create(&outbox).Error; err != nil {
		return nil, err
	}

	if err := tx.Commit().Error; err != nil {
		return nil, err
	}

	return &model.ConfirmTransferResponse{
		ReferenceID: referenceID,
		Status:      string(entity.TransferStatusCompleted),
		SettledAt:   &settledAt,
	}, nil
}

// Cancel transitions PENDING → FAILED with reason.
func (uc *TransferUseCase) Cancel(ctx context.Context, userID uuid.UUID, referenceID string, req *model.CancelTransferRequest) (*model.CancelTransferResponse, error) {
	tx := uc.DB.Begin()
	if tx.Error != nil {
		return nil, tx.Error
	}
	defer tx.Rollback()

	// Gunakan FindByReferenceIDLocked (Pessimistic locking) agar tidak berbenturan dengan Confirm
	transfer, err := uc.TransferRepository.FindByReferenceIDLocked(tx, referenceID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, exception.ErrTransferNotFound
		}
		return nil, err
	}

	// Ownership check
	if transfer.UserID != userID {
		return nil, exception.ErrTransferNotFound
	}

	if transfer.Status != entity.TransferStatusPending {
		return nil, exception.ErrTransferNotCancellable
	}

	reason := "CANCELLED_BY_USER"
	if req.Reason != nil && *req.Reason != "" {
		reason = "CANCELLED_BY_USER: " + *req.Reason
	}

	if err := uc.TransferRepository.UpdateStatus(tx, referenceID, entity.TransferStatusFailed, map[string]interface{}{
		"failure_reason": reason,
	}); err != nil {
		return nil, err
	}

	if err := tx.Commit().Error; err != nil {
		return nil, err
	}

	return &model.CancelTransferResponse{
		ReferenceID:   referenceID,
		Status:        string(entity.TransferStatusFailed),
		FailureReason: &reason,
	}, nil
}

// GetDetail returns full transfer detail — ownership validated.
func (uc *TransferUseCase) GetDetail(ctx context.Context, userID uuid.UUID, referenceID string) (*model.TransferDetailResponse, error) {
	transfer, err := uc.TransferRepository.FindByReferenceID(uc.DB, referenceID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, exception.ErrTransferNotFound
		}
		return nil, err
	}

	if transfer.UserID != userID {
		return nil, exception.ErrTransferNotFound
	}

	return toDetailResponse(transfer), nil
}

// GetMyTransfers returns paginated list of transfers for the authenticated user.
func (uc *TransferUseCase) GetMyTransfers(ctx context.Context, userID uuid.UUID, params *model.TransferQueryParams) (*model.TransferListResponse, error) {
	from, to := parseDateRange(params.From, params.To)
	offset := params.Page * params.Size

	transfers, total, err := uc.TransferRepository.FindByUserID(uc.DB, userID.String(), params.Status, from, to, offset, params.Size)
	if err != nil {
		return nil, err
	}

	data := make([]model.TransferDetailResponse, len(transfers))
	for i, t := range transfers {
		data[i] = *toDetailResponse(&t)
	}

	return &model.TransferListResponse{
		Data: data,
		Pagination: model.Pagination{
			Page:       params.Page,
			Limit:      params.Size,
			TotalItems: total,
			TotalPages: int64(totalPages(total, params.Size)),
		},
	}, nil
}

// GetAccountHistory returns paginated mutation history for an account number.
// Direction is derived: source = DEBIT, target = CREDIT.
func (uc *TransferUseCase) GetAccountHistory(ctx context.Context, userID uuid.UUID, accountNumber string, params *model.TransferQueryParams) (*model.TransferHistoryResponse, error) {
	from, to := parseDateRange(params.From, params.To)
	offset := params.Page * params.Size

	transfers, total, err := uc.TransferRepository.FindByAccountNumber(uc.DB, accountNumber, from, to, offset, params.Size)
	if err != nil {
		return nil, err
	}

	data := make([]model.TransferHistoryItem, len(transfers))
	for i, t := range transfers {
		direction := "CREDIT"
		counterpart := t.TargetAccountNumber
		if t.SourceAccountNumber == accountNumber {
			direction = "DEBIT"
			counterpart = t.TargetAccountNumber
		} else {
			counterpart = t.SourceAccountNumber
		}

		data[i] = model.TransferHistoryItem{
			ReferenceID:              t.ReferenceID,
			Direction:                direction,
			Amount:                   t.Amount,
			Currency:                 t.SourceCurrency,
			CounterpartAccountNumber: counterpart,
			Description:              t.Description,
			Status:                   string(t.Status),
			SettledAt:                t.SettledAt,
		}
	}

	return &model.TransferHistoryResponse{
		AccountNumber: accountNumber,
		Data:          data,
		Pagination: model.Pagination{
			Page:       params.Page,
			Limit:      params.Size,
			TotalItems: total,
			TotalPages: int64(totalPages(total, params.Size)),
		},
	}, nil
}

//-----------------------------------------------------------------------
// Private helpers
// -----------------------------------------------------------------------

func toInitiateResponse(t *entity.Transfer) *model.InitiateTransferResponse {
	return &model.InitiateTransferResponse{
		ReferenceID:         t.ReferenceID,
		Status:              string(t.Status),
		TransferType:        string(t.TransferType),
		SourceAccountNumber: t.SourceAccountNumber,
		TargetAccountNumber: t.TargetAccountNumber,
		Amount:              t.Amount,
		SourceCurrency:      t.SourceCurrency,
		TargetCurrency:      t.TargetCurrency,
		ExchangeRate:        t.ExchangeRate,
		ConvertedAmount:     t.ConvertedAmount,
		Description:         t.Description,
		CreatedAt:           t.CreatedAt,
	}
}

func toDetailResponse(t *entity.Transfer) *model.TransferDetailResponse {
	return &model.TransferDetailResponse{
		ReferenceID:         t.ReferenceID,
		Status:              string(t.Status),
		TransferType:        string(t.TransferType),
		SourceAccountNumber: t.SourceAccountNumber,
		TargetAccountNumber: t.TargetAccountNumber,
		Amount:              t.Amount,
		SourceCurrency:      t.SourceCurrency,
		TargetCurrency:      t.TargetCurrency,
		ExchangeRate:        t.ExchangeRate,
		ConvertedAmount:     t.ConvertedAmount,
		Description:         t.Description,
		FailureReason:       t.FailureReason,
		CreatedAt:           t.CreatedAt,
		SettledAt:           t.SettledAt,
		UpdatedAt:           t.UpdatedAt,
	}
}

func parseDateRange(from, to string) (time.Time, time.Time) {
	layout := "2006-01-02"
	fromTime, _ := time.Parse(layout, from)
	toTime, _ := time.Parse(layout, to)
	return fromTime, toTime
}

func totalPages(total int64, size int) int {
	if size == 0 {
		return 0
	}
	return int((total + int64(size) - 1) / int64(size))
}
