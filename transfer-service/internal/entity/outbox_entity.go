package entity

import (
	"time"

	"github.com/google/uuid"
)

type OutboxStatus string

const (
	OutboxStatusPending   OutboxStatus = "PENDING"
	OutboxStatusPublished OutboxStatus = "PUBLISHED"
	OutboxStatusFailed    OutboxStatus = "FAILED"
)

type OutboxEvent struct {
	ID          uuid.UUID    `gorm:"column:id;primaryKey"`
	Topic       string       `gorm:"column:topic"`
	Payload     string       `gorm:"column:payload"`
	Status      OutboxStatus `gorm:"column:status"`
	ErrorReason *string      `gorm:"column:error_reason"`
	CreatedAt   time.Time    `gorm:"column:created_at"`
	PublishedAt *time.Time   `gorm:"column:published_at"`
}

func (OutboxEvent) TableName() string {
	return "outbox_events"
}
