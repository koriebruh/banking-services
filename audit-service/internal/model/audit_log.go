package model

import (
	"encoding/json"
	"math"
	"time"
)

// AuditLog merepresentasikan satu baris audit trail yang immutable (append-only).
// Setiap event dari Kafka di-normalize ke struct ini sebelum disimpan ke database.
//
// Banking Best Practice:
//   - EventID bersifat UNIQUE → menjamin idempotent insert (deduplicate)
//   - OccurredAt = waktu event terjadi di source service
//   - ReceivedAt = waktu event diterima oleh audit-service (processing time)
//   - Payload menyimpan raw JSON asli untuk forensic & compliance
type AuditLog struct {
	ID           int64           `json:"id" gorm:"primaryKey;autoIncrement"`
	EventID      string          `json:"event_id" gorm:"uniqueIndex;type:varchar(64);not null"`
	EventType    string          `json:"event_type" gorm:"type:varchar(64);not null;index"`
	EventSource  string          `json:"event_source" gorm:"type:varchar(32);not null;index"` // AUTH | ACCOUNT | TRANSFER
	UserCode     string          `json:"user_code" gorm:"type:varchar(64);not null;index"`
	ResourceType string          `json:"resource_type,omitempty" gorm:"type:varchar(32)"`
	ResourceID   string          `json:"resource_id,omitempty" gorm:"type:varchar(128)"`
	IPAddress    string          `json:"ip_address,omitempty" gorm:"type:varchar(45)"`
	UserAgent    string          `json:"user_agent,omitempty" gorm:"type:text"`
	Payload      json.RawMessage `json:"payload" gorm:"type:jsonb;not null;default:'{}'"`
	OccurredAt   time.Time       `json:"occurred_at" gorm:"not null;index"`
	ReceivedAt   time.Time       `json:"received_at" gorm:"autoCreateTime;not null"`
}

// TableName mengembalikan nama tabel untuk GORM.
func (AuditLog) TableName() string {
	return "audit_logs"
}

// AuditLogFilter berisi parameter filter untuk query audit logs.
// Semua field bersifat opsional — jika kosong/zero-value, filter tidak diterapkan.
type AuditLogFilter struct {
	UserCode     string
	EventType    string
	EventSource  string // AUTH | ACCOUNT | TRANSFER
	ResourceType string
	ResourceID   string
	StartDate    time.Time // occurred_at >= StartDate
	EndDate      time.Time // occurred_at <= EndDate
	Page         int
	Size         int
}

// Normalize memastikan Page dan Size memiliki default yang wajar.
func (f *AuditLogFilter) Normalize() {
	if f.Page < 1 {
		f.Page = 1
	}
	if f.Size < 1 {
		f.Size = 20
	}
	if f.Size > 100 {
		f.Size = 100
	}
}

// Offset mengembalikan offset SQL berdasarkan Page dan Size.
func (f *AuditLogFilter) Offset() int {
	return (f.Page - 1) * f.Size
}

// PagedResult membungkus hasil query dengan informasi pagination.
type PagedResult struct {
	Content       []AuditLog `json:"content"`
	Page          int        `json:"page"`
	Size          int        `json:"size"`
	TotalElements int64      `json:"total_elements"`
	TotalPages    int        `json:"total_pages"`
}

// NewPagedResult membuat PagedResult dari data, page, size, dan total count.
func NewPagedResult(content []AuditLog, page, size int, totalElements int64) PagedResult {
	totalPages := int(math.Ceil(float64(totalElements) / float64(size)))
	if totalPages < 1 {
		totalPages = 1
	}
	return PagedResult{
		Content:       content,
		Page:          page,
		Size:          size,
		TotalElements: totalElements,
		TotalPages:    totalPages,
	}
}
