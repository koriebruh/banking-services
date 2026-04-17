package repository

import (
	"context"

	"golang-clean-architecture/internal/model"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// AuditRepository menangani operasi database untuk audit_logs menggunakan GORM.
// Design: append-only — tidak ada UPDATE atau DELETE.
//
// Banking Best Practice:
//   - Insert menggunakan ON CONFLICT DO NOTHING → idempotent (Kafka at-least-once safe)
//   - FindAll membangun query secara dinamis dari filter → aman dari SQL injection
//   - Pagination wajib untuk mencegah full-table scan pada data audit yang besar
type AuditRepository struct {
	DB  *gorm.DB
	Log *logrus.Logger
}

// NewAuditRepository membuat instance AuditRepository.
func NewAuditRepository(db *gorm.DB, log *logrus.Logger) *AuditRepository {
	return &AuditRepository{DB: db, Log: log}
}

// Insert menyimpan satu AuditLog ke database.
// Menggunakan ON CONFLICT (event_id) DO NOTHING untuk idempotent insert —
// jika event_id sudah ada (misal karena Kafka retry), row tidak di-duplicate.
func (r *AuditRepository) Insert(ctx context.Context, log *model.AuditLog) error {
	result := r.DB.WithContext(ctx).
		Clauses(clause.OnConflict{
			Columns:   []clause.Column{{Name: "event_id"}},
			DoNothing: true,
		}).
		Create(log)

	if result.Error != nil {
		r.Log.WithError(result.Error).WithField("event_id", log.EventID).
			Error("Failed to insert audit log")
		return result.Error
	}

	return nil
}

// FindAll mengambil audit logs berdasarkan filter dengan pagination.
// GORM memastikan semua parameter di-bind secara aman (anti SQL injection).
// Mengembalikan slice AuditLog, total count, dan error.
func (r *AuditRepository) FindAll(ctx context.Context, filter model.AuditLogFilter) ([]model.AuditLog, int64, error) {
	filter.Normalize()

	// Build query dengan dynamic WHERE (GORM chain)
	query := r.DB.WithContext(ctx).Model(&model.AuditLog{})

	if filter.UserCode != "" {
		query = query.Where("user_code = ?", filter.UserCode)
	}
	if filter.EventType != "" {
		query = query.Where("event_type = ?", filter.EventType)
	}
	if filter.EventSource != "" {
		query = query.Where("event_source = ?", filter.EventSource)
	}
	if filter.ResourceType != "" {
		query = query.Where("resource_type = ?", filter.ResourceType)
	}
	if filter.ResourceID != "" {
		query = query.Where("resource_id = ?", filter.ResourceID)
	}
	if !filter.StartDate.IsZero() {
		query = query.Where("occurred_at >= ?", filter.StartDate)
	}
	if !filter.EndDate.IsZero() {
		query = query.Where("occurred_at <= ?", filter.EndDate)
	}

	// Count total (sebelum pagination)
	var totalElements int64
	if err := query.Count(&totalElements).Error; err != nil {
		r.Log.WithError(err).Error("Failed to count audit logs")
		return nil, 0, err
	}

	// Fetch page
	var results []model.AuditLog
	err := query.
		Order("occurred_at DESC").
		Limit(filter.Size).
		Offset(filter.Offset()).
		Find(&results).Error

	if err != nil {
		r.Log.WithError(err).Error("Failed to query audit logs")
		return nil, 0, err
	}

	return results, totalElements, nil
}
