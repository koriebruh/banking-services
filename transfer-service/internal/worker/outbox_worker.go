package worker

import (
	"context"
	"encoding/json"
	"golang-clean-architecture/internal/entity"
	"golang-clean-architecture/internal/event"
	"golang-clean-architecture/internal/gateway/messaging"
	"time"

	"github.com/sirupsen/logrus"
	"gorm.io/gorm"
)

type OutboxWorker struct {
	DB               *gorm.DB
	Log              *logrus.Logger
	TransferProducer *messaging.TransferEventPublisher
}

func NewOutboxWorker(db *gorm.DB, log *logrus.Logger, producer *messaging.TransferEventPublisher) *OutboxWorker {
	return &OutboxWorker{DB: db, Log: log, TransferProducer: producer}
}

func (w *OutboxWorker) Start(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Second)
	w.Log.Info("Starting Outbox Worker...")

	go func() {
		for {
			select {
			case <-ctx.Done():
				w.Log.Info("Stopping Outbox Worker...")
				return
			case <-ticker.C:
				w.processOutbox(ctx)
			}
		}
	}()
}

func (w *OutboxWorker) processOutbox(ctx context.Context) {
	// 1. Ambil event PENDING (limit batch)
	var events []entity.OutboxEvent
	// Gunakan simple query. Pada environment cluster, hindari race condition dengan FOR UPDATE SKIP LOCKED
	if err := w.DB.Where("status = ?", entity.OutboxStatusPending).Limit(100).Find(&events).Error; err != nil {
		w.Log.Errorf("OutboxWorker: Failed to fetch events: %v", err)
		return
	}

	if len(events) == 0 {
		return
	}

	// 2. Publish ke Kafka
	for _, outboxEvent := range events {
		var transferEvent event.TransferEvent
		if err := json.Unmarshal([]byte(outboxEvent.Payload), &transferEvent); err != nil {
			w.Log.Errorf("OutboxWorker: Failed to unmarshal payload %s: %v", outboxEvent.ID, err)
			w.markAsFailed(outboxEvent.ID, err.Error())
			continue
		}

		if err := w.TransferProducer.Publish(ctx, transferEvent); err != nil {
			w.Log.Errorf("OutboxWorker: Failed to publish %s: %v", outboxEvent.ID, err)
			// Biarkan PENDING agar diretries di cycle berikutnya
			continue
		}

		// 3. Mark as PUBLISHED
		w.markAsPublished(outboxEvent.ID)
	}
}

func (w *OutboxWorker) markAsPublished(id interface{}) {
	now := time.Now().UTC()
	w.DB.Model(&entity.OutboxEvent{}).Where("id = ?", id).Updates(map[string]interface{}{
		"status":       entity.OutboxStatusPublished,
		"published_at": &now,
	})
}

func (w *OutboxWorker) markAsFailed(id interface{}, reason string) {
	w.DB.Model(&entity.OutboxEvent{}).Where("id = ?", id).Updates(map[string]interface{}{
		"status":       entity.OutboxStatusFailed,
		"error_reason": reason,
	})
}
