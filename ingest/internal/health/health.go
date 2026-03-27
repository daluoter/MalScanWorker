package health

import (
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	amqp091 "github.com/rabbitmq/amqp091-go"
)

// Checker holds references to all backend clients for health verification.
type Checker struct {
	Pool     *pgxpool.Pool
	Minio    *minio.Client
	AmqpConn *amqp091.Connection
	Bucket   string
}

// NewChecker creates a Checker with all backend dependencies.
func NewChecker(pool *pgxpool.Pool, minioClient *minio.Client, amqpConn *amqp091.Connection, bucket string) *Checker {
	return &Checker{
		Pool:     pool,
		Minio:    minioClient,
		AmqpConn: amqpConn,
		Bucket:   bucket,
	}
}

// Handle responds with backend health status.
// Returns 200 + {"status":"ok"} when all healthy.
// Returns 503 + {"status":"unhealthy","details":{...}} when any backend is down.
func (c *Checker) Handle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	details := make(map[string]string)
	healthy := true

	// PostgreSQL — ping via pool
	if err := c.Pool.Ping(ctx); err != nil {
		details["postgres"] = err.Error()
		healthy = false
	} else {
		details["postgres"] = "ok"
	}

	// MinIO — verify bucket accessible
	if _, err := c.Minio.BucketExists(ctx, c.Bucket); err != nil {
		details["minio"] = err.Error()
		healthy = false
	} else {
		details["minio"] = "ok"
	}

	// RabbitMQ — check if connection is still open
	if c.AmqpConn.IsClosed() {
		details["rabbitmq"] = "connection closed"
		healthy = false
	} else {
		details["rabbitmq"] = "ok"
	}

	w.Header().Set("Content-Type", "application/json")
	if healthy {
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
		json.NewEncoder(w).Encode(map[string]any{"status": "unhealthy", "details": details})
	}
}
