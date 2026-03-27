package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	amqp091 "github.com/rabbitmq/amqp091-go"
)

// JobMessage is the JSON message published to the job queue.
// Fields must match exactly what the Python worker consumer expects.
type JobMessage struct {
	JobID            string `json:"job_id"`
	FileID           string `json:"file_id"`
	StorageKey       string `json:"storage_key"`
	SHA256           string `json:"sha256"`
	OriginalFilename string `json:"original_filename"`
}

// Channel abstracts amqp091.Channel for testing.
type Channel interface {
	QueueDeclare(name string, durable, autoDelete, exclusive, noWait bool, args amqp091.Table) (amqp091.Queue, error)
	Publish(exchange, key string, mandatory, immediate bool, msg amqp091.Publishing) error
}

// Publisher handles RabbitMQ queue declaration and message publishing.
type Publisher struct {
	ch             Channel
	queueName      string
	logger         *slog.Logger
	retryBaseDelay time.Duration // default 1s, overridden in tests to 1ms
}

// NewPublisher creates a Publisher with default retry settings.
func NewPublisher(ch Channel, queueName string, logger *slog.Logger) *Publisher {
	return &Publisher{
		ch:             ch,
		queueName:      queueName,
		logger:         logger,
		retryBaseDelay: 1 * time.Second,
	}
}

// DeclareQueue declares the job queue with DLQ configuration.
// The queue is durable with dead-letter routing to "malscan-dlq".
// Note: The DLQ queue ("malscan-dlq") must be declared separately (e.g., via infrastructure setup).
func (p *Publisher) DeclareQueue(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	_, err := p.ch.QueueDeclare(
		p.queueName, // "malscan.jobs"
		true,        // durable
		false,       // autoDelete
		false,       // exclusive
		false,       // noWait
		amqp091.Table{
			"x-dead-letter-exchange":    "",
			"x-dead-letter-routing-key": "malscan-dlq",
		},
	)
	return err
}

// Publish sends a JobMessage to the queue with exponential backoff retry.
// It attempts up to 5 times with delays of 1s, 2s, 4s, 8s, 16s (capped).
func (p *Publisher) Publish(ctx context.Context, msg JobMessage) error {
	const maxAttempts = 5
	maxDelay := 16 * p.retryBaseDelay

	body, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshal job message: %w", err)
	}

	for attempt := 1; attempt <= maxAttempts; attempt++ {
		err = p.ch.Publish(
			"",          // default exchange
			p.queueName, // routing key = queue name
			false,       // mandatory
			false,       // immediate
			amqp091.Publishing{
				DeliveryMode: amqp091.Persistent, // = 2
				ContentType:  "application/json",
				Body:         body,
			},
		)
		if err == nil {
			p.logger.Info("job_published",
				"job_id", msg.JobID,
				"file_id", msg.FileID,
				"queue", p.queueName)
			return nil
		}

		p.logger.Warn("rabbitmq_publish_retry",
			"attempt", attempt,
			"max_attempts", maxAttempts,
			"error", err.Error(),
			"job_id", msg.JobID)

		if attempt < maxAttempts {
			delay := p.retryBaseDelay * time.Duration(1<<(attempt-1)) // 1s, 2s, 4s, 8s, 16s
			if delay > maxDelay {
				delay = maxDelay
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(delay):
			}
		}
	}

	p.logger.Error("rabbitmq_publish_failed",
		"attempts", maxAttempts,
		"error", err.Error(),
		"job_id", msg.JobID)
	return fmt.Errorf("publish failed after %d attempts: %w", maxAttempts, err)
}
