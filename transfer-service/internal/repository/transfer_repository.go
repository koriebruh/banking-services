package repository

import (
	"golang-clean-architecture/internal/entity"
	"time"

	"github.com/sirupsen/logrus"
	"golang.org/x/sync/errgroup"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type TransferRepository struct {
	Repository[entity.Transfer]
	Log *logrus.Logger
}

func NewTransferRepository(log *logrus.Logger) *TransferRepository {
	return &TransferRepository{
		Log: log,
	}
}

func (r *TransferRepository) FindByReferenceID(db *gorm.DB, referenceID string) (*entity.Transfer, error) {
	var transfer entity.Transfer
	err := db.Where("reference_id = ?", referenceID).Take(&transfer).Error
	return &transfer, err
}

func (r *TransferRepository) FindByReferenceIDLocked(db *gorm.DB, referenceID string) (*entity.Transfer, error) {
	var transfer entity.Transfer
	err := db.Clauses(clause.Locking{Strength: "UPDATE"}).Where("reference_id = ?", referenceID).Take(&transfer).Error
	return &transfer, err
}

func (r *TransferRepository) FindByUserID(db *gorm.DB, userID string, status string, from, to time.Time, offset, limit int) ([]entity.Transfer, int64, error) {
	var transfers []entity.Transfer
	var total int64

	query := db.Model(&entity.Transfer{}).Where("user_id = ?", userID)

	if status != "" {
		query = query.Where("status = ?", status)
	}
	if !from.IsZero() {
		query = query.Where("created_at >= ?", from)
	}
	if !to.IsZero() {
		query = query.Where("created_at <= ?", to)
	}

	g := new(errgroup.Group)

	countQuery := query.Session(&gorm.Session{})
	findQuery := query.Session(&gorm.Session{})

	g.Go(func() error {
		return countQuery.Count(&total).Error
	})

	g.Go(func() error {
		return findQuery.Order("created_at DESC").Offset(offset).Limit(limit).Find(&transfers).Error
	})

	if err := g.Wait(); err != nil {
		return nil, 0, err
	}

	return transfers, total, nil
}

func (r *TransferRepository) FindByAccountNumber(db *gorm.DB, accountNumber string, from, to time.Time, offset, limit int) ([]entity.Transfer, int64, error) {
	var transfers []entity.Transfer
	var total int64

	query := db.Model(&entity.Transfer{}).
		Where("source_account_number = ? OR target_account_number = ?", accountNumber, accountNumber).
		Where("status = ?", entity.TransferStatusCompleted)

	if !from.IsZero() {
		query = query.Where("created_at >= ?", from)
	}
	if !to.IsZero() {
		query = query.Where("created_at <= ?", to)
	}

	g := new(errgroup.Group)

	countQuery := query.Session(&gorm.Session{})
	findQuery := query.Session(&gorm.Session{})

	g.Go(func() error {
		return countQuery.Count(&total).Error
	})

	g.Go(func() error {
		return findQuery.Order("created_at DESC").Offset(offset).Limit(limit).Find(&transfers).Error
	})

	if err := g.Wait(); err != nil {
		return nil, 0, err
	}

	return transfers, total, nil
}

func (r *TransferRepository) UpdateStatus(db *gorm.DB, referenceID string, status entity.TransferStatus, extra map[string]interface{}) error {
	updates := map[string]interface{}{
		"status":     status,
		"updated_at": time.Now().UTC(),
	}
	for k, v := range extra {
		updates[k] = v
	}
	return db.Model(&entity.Transfer{}).
		Where("reference_id = ?", referenceID).
		Updates(updates).Error
}
