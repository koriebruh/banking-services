package worker

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"golang-clean-architecture/internal/event"
	"golang-clean-architecture/internal/hub"
	"golang-clean-architecture/internal/notification"

	"github.com/IBM/sarama"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

// NotificationWorker adalah Kafka consumer yang menerima event dari berbagai topic
// dan mendispatch notifikasi ke dua kanal: WebSocket (real-time) dan Email (SMTP).
type NotificationWorker struct {
	Log          *logrus.Logger
	Config       *viper.Viper
	Hub          *hub.Hub
	Email        *notification.EmailSender

	// AccountCache: account_number → user_code
	// Diisi dari account.events untuk resolusi transfer event.
	AccountCache map[string]string
	CacheMutex   sync.RWMutex

	// UserEmailCache: user_code → email
	// Diisi dari auth.events sehingga event lain bisa lookup email-nya.
	UserEmailCache map[string]string
	EmailMutex     sync.RWMutex
}

func NewNotificationWorker(
	log *logrus.Logger,
	config *viper.Viper,
	hub *hub.Hub,
	emailSender *notification.EmailSender,
) *NotificationWorker {
	return &NotificationWorker{
		Log:            log,
		Config:         config,
		Hub:            hub,
		Email:          emailSender,
		AccountCache:   make(map[string]string),
		UserEmailCache: make(map[string]string),
	}
}

func (w *NotificationWorker) Start(ctx context.Context) {
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
		groupID = "notification-service-group"
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

	w.Log.Infof("[worker] Starting Kafka Consumer Group=%s topics=%v brokers=%v", groupID, topics, brokers)

	go func() {
		for {
			client, err := sarama.NewConsumerGroup(brokers, groupID, config)
			if err != nil {
				w.Log.Errorf("[worker] Error creating Kafka consumer group: %v", err)
				time.Sleep(5 * time.Second)
				continue
			}

			handler := &ConsumerHandler{Worker: w}

			for {
				if err := client.Consume(ctx, topics, handler); err != nil {
					w.Log.Errorf("[worker] Kafka consume error: %v", err)
					break
				}
				if ctx.Err() != nil {
					w.Log.Info("[worker] Kafka consumer context canceled")
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

type ConsumerHandler struct {
	Worker *NotificationWorker
}

func (h *ConsumerHandler) Setup(sarama.ConsumerGroupSession) error   { return nil }
func (h *ConsumerHandler) Cleanup(sarama.ConsumerGroupSession) error { return nil }

func (h *ConsumerHandler) ConsumeClaim(session sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for {
		select {
		case msg, ok := <-claim.Messages():
			if !ok {
				h.Worker.Log.Info("[worker] Message channel closed")
				return nil
			}
			h.processMessage(msg)
			session.MarkMessage(msg, "")

		case <-session.Context().Done():
			return nil
		}
	}
}

// ── Message Processor ─────────────────────────────────────────────────────────

func (h *ConsumerHandler) processMessage(msg *sarama.ConsumerMessage) {
	w := h.Worker
	w.Log.Debugf("[worker] Received topic=%s value=%s", msg.Topic, string(msg.Value))

	var notifications []event.Notification

	switch msg.Topic {

	case event.TopicAuth:
		notifications = h.handleAuthEvent(msg.Value)

	case event.TopicAccount:
		notifications = h.handleAccountEvent(msg.Value)

	case event.TopicTransfer:
		notifications = h.handleTransferEvent(msg.Value)

	default:
		w.Log.Warnf("[worker] Unknown topic: %s", msg.Topic)
		return
	}

	h.dispatch(notifications)
}

// ── Topic Handlers ────────────────────────────────────────────────────────────

func (h *ConsumerHandler) handleAuthEvent(raw []byte) []event.Notification {
	w := h.Worker
	var e event.AuthEvent
	if err := json.Unmarshal(raw, &e); err != nil {
		w.Log.Errorf("[worker] auth.events unmarshal error: %v", err)
		return nil
	}

	// Cache user_code → email dari setiap auth event yang membawa email
	if e.UserCode != "" && e.Email != "" {
		w.EmailMutex.Lock()
		w.UserEmailCache[e.UserCode] = e.Email
		w.EmailMutex.Unlock()
		w.Log.Debugf("[worker] cached email for userCode=%s", e.UserCode)
	}

	email := h.lookupEmail(e.UserCode)
	return event.MapAuthEvent(e, email)
}

func (h *ConsumerHandler) handleAccountEvent(raw []byte) []event.Notification {
	w := h.Worker
	var e event.AccountEvent
	if err := json.Unmarshal(raw, &e); err != nil {
		w.Log.Errorf("[worker] account.events unmarshal error: %v", err)
		return nil
	}

	// Simpan account_number → user_code untuk resolusi transfer event
	if e.AccountNumber != "" && e.UserCode != "" {
		w.CacheMutex.Lock()
		w.AccountCache[e.AccountNumber] = e.UserCode
		w.CacheMutex.Unlock()
		w.Log.Debugf("[worker] cached account=%s → userCode=%s", e.AccountNumber, e.UserCode)
	}

	email := h.lookupEmail(e.UserCode)
	return event.MapAccountEvent(e, email)
}

func (h *ConsumerHandler) handleTransferEvent(raw []byte) []event.Notification {
	w := h.Worker

	// Coba parse sebagai StructuredTransferEvent terlebih dahulu
	var structured event.StructuredTransferEvent
	if err := json.Unmarshal(raw, &structured); err == nil && structured.Type != "" {
		email := h.lookupEmail(structured.Data.UserCode)
		return event.MapTransferEvent(structured, email)
	}

	// Fallback: parse sebagai flat TransferEvent
	var flat event.TransferEvent
	if err := json.Unmarshal(raw, &flat); err != nil {
		w.Log.Errorf("[worker] transfer.events unmarshal error: %v", err)
		return nil
	}

	// Resolusi user_code: ambil langsung dari payload, fallback ke AccountCache
	userCode := flat.UserCode
	if userCode == "" {
		userCode = h.resolveUserCodeFromAccount(flat.SourceAccountNumber)
		if userCode == "" {
			userCode = h.resolveUserCodeFromAccount(flat.TargetAccountNumber)
		}
		if userCode == "" {
			w.Log.Warnf("[worker] cannot resolve userCode for transfer ref=%s", flat.ReferenceID)
		}
	}
	email := h.lookupEmail(userCode)
	return event.MapFlatTransferEvent(flat, userCode, email)
}

// ── Dispatcher ────────────────────────────────────────────────────────────────

// dispatch mengirim setiap Notification ke kanal yang sesuai secara concurrent.
func (h *ConsumerHandler) dispatch(notifications []event.Notification) {
	w := h.Worker
	for _, n := range notifications {
		notif := n // capture
		go func() {
			switch notif.Channel {
			case event.ChannelWS:
				w.Hub.SendToUser(notif.To, notif.Data)
				w.Log.Debugf("[dispatch] WS → userCode=%s template=%s", notif.To, notif.Template)

			case event.ChannelEmail:
				if err := w.Email.Send(notif); err != nil {
					w.Log.Errorf("[dispatch] Email failed → %s: %v", notif.To, err)
				}
			}
		}()
	}
}

// ── Cache Helpers ─────────────────────────────────────────────────────────────

// lookupEmail mengambil email dari UserEmailCache berdasarkan user_code.
// Mengembalikan string kosong jika tidak ditemukan.
func (h *ConsumerHandler) lookupEmail(userCode string) string {
	if userCode == "" {
		return ""
	}
	h.Worker.EmailMutex.RLock()
	email := h.Worker.UserEmailCache[userCode]
	h.Worker.EmailMutex.RUnlock()
	return email
}

// resolveUserCodeFromAccount mengambil user_code dari AccountCache berdasarkan account_number.
func (h *ConsumerHandler) resolveUserCodeFromAccount(accountNumber string) string {
	if accountNumber == "" {
		return ""
	}
	h.Worker.CacheMutex.RLock()
	userCode := h.Worker.AccountCache[accountNumber]
	h.Worker.CacheMutex.RUnlock()
	return userCode
}
