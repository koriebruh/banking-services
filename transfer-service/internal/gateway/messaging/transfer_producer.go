package messaging

import (
	"context"
	"encoding/json"
	"golang-clean-architecture/internal/event"
	"time"

	"github.com/IBM/sarama"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
)

type TransferEventPublisher struct {
	producer sarama.SyncProducer
	topic    string
	log      *logrus.Logger
}

func NewTransferEventPublisher(producer sarama.SyncProducer, log *logrus.Logger, Config *viper.Viper) *TransferEventPublisher {
	return &TransferEventPublisher{
		producer: producer,
		topic:    Config.GetString("kafka.producer.topic"),
		log:      log,
	}
}

// Publish sends a TransferEvent to Kafka topic: transfer.event
// Partition key = source_account_number — guarantees ordered delivery per account.
// Called ONLY after transfer status transitions to COMPLETED.
func (p *TransferEventPublisher) Publish(ctx context.Context, event event.TransferEvent) error {
	event.OccurredAt = time.Now().UTC()

	payload, err := json.Marshal(event)
	if err != nil {
		p.log.Errorf("Failed to marshal TransferEvent referenceId=%s: %v", event.ReferenceID, err)
		return err
	}

	msg := &sarama.ProducerMessage{
		Topic: p.topic,
		Key:   sarama.StringEncoder(event.SourceAccountNumber), // partition key
		Value: sarama.ByteEncoder(payload),
	}

	partition, offset, err := p.producer.SendMessage(msg)
	if err != nil {
		p.log.Errorf("Failed to publish TransferEvent referenceId=%s: %v", event.ReferenceID, err)
		return err
	}

	p.log.Debugf("TransferEvent published referenceId=%s partition=%d offset=%d",
		event.ReferenceID, partition, offset)

	return nil
}

func (p *TransferEventPublisher) Close() error {
	return p.producer.Close()
}
