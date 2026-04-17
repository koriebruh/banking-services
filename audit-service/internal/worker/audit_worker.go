package worker

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"golang-clean-architecture/internal/event"
	"golang-clean-architecture/internal/model"
	"golang-clean-architecture/internal/usecase"

	"github.com/IBM/sarama"
	"github.com/google/uuid"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// AuditWorker adalah Kafka consumer yang menerima event dari berbagai topic,
// me-normalize setiap event menjadi AuditLog, dan menyimpannya ke PostgreSQL.
//
// Design Principles (Banking Audit):
//   - Append-only: tidak pernah update atau delete
//   - Idempotent insert: ON CONFLICT (event_id) DO NOTHING
//   - Full payload preservation: raw JSON disimpan untuk forensic
//   - Source classification: AUTH | ACCOUNT | TRANSFER
type AuditWorker struct {
	Log     *logrus.Logger
	Config  *viper.Viper
	Usecase *usecase.AuditUsecase
}

// NewAuditWorker membuat instance AuditWorker baru.
func NewAuditWorker(
	log *logrus.Logger,
	config *viper.Viper,
	uc *usecase.AuditUsecase,
) *AuditWorker {
	return &AuditWorker{
		Log:     log,
		Config:  config,
		Usecase: uc,
	}
}

// Start menjalankan Kafka consumer group dalam goroutine terpisah.
// Consumer akan terus reconnect jika terjadi error.
func (w *AuditWorker) Start(ctx context.Context) {
	brokers := strings.Split(w.Config.GetString("kafka.bootstrap.servers"), ",")
	if len(brokers) == 0 || brokers[0] == "" {
		brokers = []string{"localhost:9092"}
	}

	config := sarama.NewConfig()
	config.Version = sarama.V2_0_0_0
	config.Consumer.Offsets.Initial = sarama.OffsetOldest
	config.Consumer.Return.Errors = true

	groupID := w.Config.GetString("kafka.consumer.group")
	if groupID == "" {
		groupID = "audit-service-group"
	}

	topicsStr := w.Config.GetString("kafka.consumer.topics")
	var topics []string
	if topicsStr != "" {
		topics = strings.Split(topicsStr, ",")
		for i, t := range topics {
			topics[i] = strings.TrimSpace(t)
		}
	} else {
		topics = []string{"auth.events", "account.events", "transfer.events"}
	}

	w.Log.Infof("[audit-worker] Starting Kafka Consumer Group=%s topics=%v brokers=%v", groupID, topics, brokers)

	go func() {
		for {
			client, err := sarama.NewConsumerGroup(brokers, groupID, config)
			if err != nil {
				w.Log.Errorf("[audit-worker] Error creating Kafka consumer group: %v", err)
				time.Sleep(5 * time.Second)
				continue
			}

			handler := &AuditConsumerHandler{Worker: w}

			for {
				if err := client.Consume(ctx, topics, handler); err != nil {
					w.Log.Errorf("[audit-worker] Kafka consume error: %v", err)
					break
				}
				if ctx.Err() != nil {
					w.Log.Info("[audit-worker] Kafka consumer context canceled")
					client.Close()
					return
				}
			}
			client.Close()
			time.Sleep(2 * time.Second)
		}
	}()
}

// ── Kafka ConsumerGroup Handler ───────────────────────────────────────────────

// AuditConsumerHandler implements sarama.ConsumerGroupHandler.
type AuditConsumerHandler struct {
	Worker *AuditWorker
}

func (h *AuditConsumerHandler) Setup(sarama.ConsumerGroupSession) error   { return nil }
func (h *AuditConsumerHandler) Cleanup(sarama.ConsumerGroupSession) error { return nil }

func (h *AuditConsumerHandler) ConsumeClaim(session sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for {
		select {
		case msg, ok := <-claim.Messages():
			if !ok {
				h.Worker.Log.Info("[audit-worker] Message channel closed")
				return nil
			}
			h.processMessage(session.Context(), msg)
			session.MarkMessage(msg, "")

		case <-session.Context().Done():
			return nil
		}
	}
}

// ── Message Processor ─────────────────────────────────────────────────────────

func (h *AuditConsumerHandler) processMessage(ctx context.Context, msg *sarama.ConsumerMessage) {
	w := h.Worker
	w.Log.Debugf("[audit-worker] Received topic=%s partition=%d offset=%d", msg.Topic, msg.Partition, msg.Offset)

	var auditLog *model.AuditLog

	switch msg.Topic {

	case event.TopicAuth:
		auditLog = h.normalizeAuthEvent(msg.Value)

	case event.TopicAccount:
		auditLog = h.normalizeAccountEvent(msg.Value)

	case event.TopicTransfer:
		auditLog = h.normalizeTransferEvent(msg.Value)

	default:
		w.Log.Warnf("[audit-worker] Unknown topic: %s", msg.Topic)
		return
	}

	if auditLog == nil {
		return
	}

	if err := w.Usecase.Append(ctx, auditLog); err != nil {
		w.Log.WithError(err).WithField("event_id", auditLog.EventID).
			Error("[audit-worker] Failed to persist audit log")
		return
	}

	w.Log.Infof("[audit-worker] Persisted audit log: event_id=%s type=%s source=%s user=%s",
		auditLog.EventID, auditLog.EventType, auditLog.EventSource, auditLog.UserCode)
}

// ── Normalizers ───────────────────────────────────────────────────────────────

func (h *AuditConsumerHandler) normalizeAuthEvent(raw []byte) *model.AuditLog {
	var e event.AuthEvent
	if err := json.Unmarshal(raw, &e); err != nil {
		h.Worker.Log.Errorf("[audit-worker] auth.events unmarshal error: %v", err)
		return nil
	}

	eventID := e.EventID
	if eventID == "" {
		eventID = uuid.New().String()
	}

	return &model.AuditLog{
		EventID:      eventID,
		EventType:    string(e.EventType),
		EventSource:  event.SourceAuth,
		UserCode:     e.UserCode,
		ResourceType: "USER",
		ResourceID:   e.UserCode,
		IPAddress:    e.IPAddress,
		UserAgent:    e.UserAgent,
		Payload:      raw,
		OccurredAt:   e.OccurredAt,
	}
}

func (h *AuditConsumerHandler) normalizeAccountEvent(raw []byte) *model.AuditLog {
	var e event.AccountEvent
	if err := json.Unmarshal(raw, &e); err != nil {
		h.Worker.Log.Errorf("[audit-worker] account.events unmarshal error: %v", err)
		return nil
	}

	eventID := e.EventID
	if eventID == "" {
		eventID = uuid.New().String()
	}

	return &model.AuditLog{
		EventID:      eventID,
		EventType:    string(e.EventType),
		EventSource:  event.SourceAccount,
		UserCode:     e.UserCode,
		ResourceType: "ACCOUNT",
		ResourceID:   e.AccountNumber,
		Payload:      raw,
		OccurredAt:   e.OccurredAt,
	}
}

func (h *AuditConsumerHandler) normalizeTransferEvent(raw []byte) *model.AuditLog {
	var e event.TransferEvent
	if err := json.Unmarshal(raw, &e); err != nil {
		h.Worker.Log.Errorf("[audit-worker] transfer.events unmarshal error: %v", err)
		return nil
	}

	// Transfer events mungkin tidak punya event_id, generate dari reference_id
	eventID := e.ReferenceID
	if eventID == "" {
		eventID = uuid.New().String()
	}

	return &model.AuditLog{
		EventID:      eventID,
		EventType:    "transfer.confirmed",
		EventSource:  event.SourceTransfer,
		UserCode:     e.UserCode,
		ResourceType: "TRANSFER",
		ResourceID:   e.ReferenceID,
		Payload:      raw,
		OccurredAt:   e.OccurredAt,
	}
}
