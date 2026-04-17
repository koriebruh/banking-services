package usecase

import (
	"context"

	"golang-clean-architecture/internal/model"
	"golang-clean-architecture/internal/repository"

	"github.com/sirupsen/logrus"
)

// AuditUsecase menangani business logic untuk audit logs.
// Layer ini menjadi boundary antara delivery (controller) dan data (repository).
//
// Meskipun saat ini logic-nya masih sederhana (pass-through ke repository),
// layer ini penting untuk:
//   - Separation of concerns (clean architecture)
//   - Tempat menambahkan business rule di masa depan (e.g. role-based access, redaction)
//   - Testability — controller bisa di-mock lewat interface usecase
type AuditUsecase struct {
	Log  *logrus.Logger
	Repo *repository.AuditRepository
}

// NewAuditUsecase membuat instance AuditUsecase baru.
func NewAuditUsecase(log *logrus.Logger, repo *repository.AuditRepository) *AuditUsecase {
	return &AuditUsecase{
		Log:  log,
		Repo: repo,
	}
}

// Append menyimpan satu AuditLog ke database (append-only).
// Dipanggil oleh AuditWorker setelah normalize event dari Kafka.
//
// Business rules yang bisa ditambahkan di sini:
//   - Validasi event_source
//   - Enrichment (e.g. geo-location dari IP)
//   - Alerting untuk event tertentu (e.g. account.locked → trigger alert)
func (u *AuditUsecase) Append(ctx context.Context, log *model.AuditLog) error {
	if log.EventID == "" {
		u.Log.Warn("[usecase] Skipping audit log with empty event_id")
		return nil
	}

	return u.Repo.Insert(ctx, log)
}

// FindAll mengambil audit logs berdasarkan filter dengan pagination.
// Dipanggil oleh AuditController dari HTTP request.
//
// Business rules yang bisa ditambahkan di sini:
//   - Role-based filtering (e.g. user hanya bisa lihat log miliknya sendiri)
//   - Sensitive data redaction (e.g. mask IP address untuk role tertentu)
//   - Rate limiting per-user untuk query audit
func (u *AuditUsecase) FindAll(ctx context.Context, filter model.AuditLogFilter) (*model.PagedResult, error) {
	filter.Normalize()

	logs, total, err := u.Repo.FindAll(ctx, filter)
	if err != nil {
		return nil, err
	}

	// Ensure empty array instead of null in JSON
	if logs == nil {
		logs = []model.AuditLog{}
	}

	result := model.NewPagedResult(logs, filter.Page, filter.Size, total)
	return &result, nil
}
