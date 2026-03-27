package health

import (
	"context"
	"encoding/json"
	"net/http"
)

// PostgresPinger abstracts the PostgreSQL health check.
type PostgresPinger interface {
	Ping(ctx context.Context) error
}

// MinioBucketChecker abstracts the MinIO health check.
type MinioBucketChecker interface {
	BucketExists(ctx context.Context, bucketName string) (bool, error)
}

// RabbitMQChecker abstracts the RabbitMQ connection health check.
type RabbitMQChecker interface {
	IsClosed() bool
}

// Checker holds references to all backend clients for health verification.
type Checker struct {
	DB       PostgresPinger
	Minio    MinioBucketChecker
	RabbitMQ RabbitMQChecker
	Bucket   string
}

// NewChecker creates a Checker with all backend dependencies.
func NewChecker(db PostgresPinger, minioClient MinioBucketChecker, rmq RabbitMQChecker, bucket string) *Checker {
	return &Checker{
		DB:       db,
		Minio:    minioClient,
		RabbitMQ: rmq,
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
	if err := c.DB.Ping(ctx); err != nil {
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
	if c.RabbitMQ.IsClosed() {
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
