package worker

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"golang-clean-architecture/internal/hub"

	"github.com/IBM/sarama"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type NotificationWorker struct {
	Log          *logrus.Logger
	Config       *viper.Viper
	Hub          *hub.Hub
	AccountCache map[string]string
	CacheMutex   sync.RWMutex
}

func NewNotificationWorker(log *logrus.Logger, config *viper.Viper, hub *hub.Hub) *NotificationWorker {
	return &NotificationWorker{
		Log:          log,
		Config:       config,
		Hub:          hub,
		AccountCache: make(map[string]string),
	}
}

func (w *NotificationWorker) Start(ctx context.Context) {
	brokers := strings.Split(w.Config.GetString("kafka.bootstrap.servers"), ",")
	if len(brokers) == 0 || brokers[0] == "" {
		brokers = []string{"localhost:9092"} // default
	}

	config := sarama.NewConfig()
	config.Version = sarama.V2_0_0_0
	config.Consumer.Offsets.Initial = sarama.OffsetOldest
	config.Consumer.Return.Errors = true

	// Load from config (Clean Code & Best Practice)
	groupID := w.Config.GetString("kafka.consumer.group")
	if groupID == "" {
		groupID = "notification-service-group" // fallback default
	}

	topicsStr := w.Config.GetString("kafka.consumer.topics")
	var topics []string
	if topicsStr != "" {
		topics = strings.Split(topicsStr, ",")
		for i, t := range topics {
			topics[i] = strings.TrimSpace(t)
		}
	} else {
		// fallback default topics
		topics = []string{"auth.events", "account.events", "transfer.events"}
	}

	w.Log.Infof("Starting Kafka Consumer Group %s for topics %v with brokers %v", groupID, topics, brokers)

	// Since we need to keep reconnecting if Kafka acts up
	go func() {
		for {
			client, err := sarama.NewConsumerGroup(brokers, groupID, config)
			if err != nil {
				w.Log.Errorf("Error creating Kafka consumer group client: %v", err)
				time.Sleep(5 * time.Second)
				continue
			}

			handler := &ConsumerHandler{
				Worker: w,
			}

			for {
				if err := client.Consume(ctx, topics, handler); err != nil {
					w.Log.Errorf("Error from Kafka consumer: %v", err)
					break
				}
				if ctx.Err() != nil {
					w.Log.Info("Kafka consumer context canceled")
					client.Close()
					return
				}
			}
			client.Close()
			time.Sleep(2 * time.Second)
		}
	}()
}

// ConsumerHandler represents a Sarama consumer group consumer
type ConsumerHandler struct {
	Worker *NotificationWorker
}

func (h *ConsumerHandler) Setup(sarama.ConsumerGroupSession) error {
	return nil
}

func (h *ConsumerHandler) Cleanup(sarama.ConsumerGroupSession) error {
	return nil
}

func (h *ConsumerHandler) ConsumeClaim(session sarama.ConsumerGroupSession, claim sarama.ConsumerGroupClaim) error {
	for {
		select {
		case msg, ok := <-claim.Messages():
			if !ok {
				h.Worker.Log.Info("Message channel closed")
				return nil
			}

			h.processMessage(msg)
			session.MarkMessage(msg, "")

		case <-session.Context().Done():
			return nil
		}
	}
}

func (h *ConsumerHandler) processMessage(msg *sarama.ConsumerMessage) {
	// Parse as generic map to find properties like "user_code" or "user_id"
	var payload map[string]interface{}
	if err := json.Unmarshal(msg.Value, &payload); err != nil {
		h.Worker.Log.Errorf("Failed to parse Kafka message payload: %v", err)
		return
	}

	h.Worker.Log.Debugf("Received message from topic %s: %s", msg.Topic, string(msg.Value))

	// Map account to userCode for future transfer resolution
	if msg.Topic == "account.events" {
		accNum, _ := payload["account_number"].(string)
		uc, _ := payload["user_code"].(string)
		if accNum != "" && uc != "" {
			h.Worker.CacheMutex.Lock()
			h.Worker.AccountCache[accNum] = uc
			h.Worker.CacheMutex.Unlock()
			h.Worker.Log.Debugf("Cached mapped account %s to userCode %s", accNum, uc)
		}
	}

	// Best-effort extraction to find the target user to notify
	targetID := extractTargetID(payload, msg.Topic, h.Worker)
	if targetID == "" {
		h.Worker.Log.Debugf("No target userId/userCode found in message from %s. Payload: %v", msg.Topic, payload)
		return
	}

	// Make use of goroutines for optimal processing
	go func(tID string, val map[string]interface{}) {
		h.Worker.Hub.SendToUser(tID, val)
	}(targetID, payload)
}

func extractTargetID(payload map[string]interface{}, topic string, w *NotificationWorker) string {
	// Root level: check for "user_id" or "userCode" or "userId"
	if code, ok := payload["user_code"].(string); ok && code != "" {
		return code
	}
	if id, ok := payload["user_id"].(string); ok && id != "" {
		return id
	}
	if id, ok := payload["userId"].(string); ok && id != "" {
		return id
	}

	// Try using the cached accounts mapping if it's a transfer event and target is available
	if topic == "transfer.events" {
		if tAcc, ok := payload["target_account_number"].(string); ok && tAcc != "" {
			w.CacheMutex.RLock()
			cachedID := w.AccountCache[tAcc]
			w.CacheMutex.RUnlock()
			if cachedID != "" {
				w.Log.Debugf("Resolved target_account_number %s to userCode %s via memory cache", tAcc, cachedID)
				return cachedID
			}
		}
	}

	// Check metadata nested
	if metadataRaw, ok := payload["metadata"].(map[string]interface{}); ok {
		if code, ok := metadataRaw["user_code"].(string); ok && code != "" {
			return code
		}
		if id, ok := metadataRaw["user_id"].(string); ok && id != "" {
			return id
		}
		if id, ok := metadataRaw["userId"].(string); ok && id != "" {
			return id
		}
	}

	return ""
}
