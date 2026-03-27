package health_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/daluoter/malscan-ingest/internal/health"
)

// --- Mock implementations ---

type mockDB struct{ err error }

func (m *mockDB) Ping(_ context.Context) error { return m.err }

type mockMinio struct{ err error }

func (m *mockMinio) BucketExists(_ context.Context, _ string) (bool, error) {
	if m.err != nil {
		return false, m.err
	}
	return true, nil
}

type mockRabbitMQ struct{ closed bool }

func (m *mockRabbitMQ) IsClosed() bool { return m.closed }

// --- Tests ---

func TestHealthAllHealthy(t *testing.T) {
	checker := health.NewChecker(
		&mockDB{err: nil},
		&mockMinio{err: nil},
		&mockRabbitMQ{closed: false},
		"uploads",
	)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	checker.Handle(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rec.Code)
	}

	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("expected status=ok, got %v", body["status"])
	}
}

func TestHealthPostgresDown(t *testing.T) {
	checker := health.NewChecker(
		&mockDB{err: errors.New("connection refused")},
		&mockMinio{err: nil},
		&mockRabbitMQ{closed: false},
		"uploads",
	)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	checker.Handle(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d", rec.Code)
	}

	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "unhealthy" {
		t.Errorf("expected status=unhealthy, got %v", body["status"])
	}

	details, ok := body["details"].(map[string]any)
	if !ok {
		t.Fatal("expected details map in response")
	}
	pgErr, ok := details["postgres"].(string)
	if !ok || pgErr != "connection refused" {
		t.Errorf("expected postgres=connection refused, got %v", details["postgres"])
	}
}

func TestHealthMinioDown(t *testing.T) {
	checker := health.NewChecker(
		&mockDB{err: nil},
		&mockMinio{err: errors.New("unreachable")},
		&mockRabbitMQ{closed: false},
		"uploads",
	)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	checker.Handle(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d", rec.Code)
	}

	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "unhealthy" {
		t.Errorf("expected status=unhealthy, got %v", body["status"])
	}

	details, ok := body["details"].(map[string]any)
	if !ok {
		t.Fatal("expected details map in response")
	}
	minioErr, ok := details["minio"].(string)
	if !ok || minioErr != "unreachable" {
		t.Errorf("expected minio=unreachable, got %v", details["minio"])
	}
}

func TestHealthRabbitMQDown(t *testing.T) {
	checker := health.NewChecker(
		&mockDB{err: nil},
		&mockMinio{err: nil},
		&mockRabbitMQ{closed: true},
		"uploads",
	)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	checker.Handle(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d", rec.Code)
	}

	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "unhealthy" {
		t.Errorf("expected status=unhealthy, got %v", body["status"])
	}

	details, ok := body["details"].(map[string]any)
	if !ok {
		t.Fatal("expected details map in response")
	}
	rmqErr, ok := details["rabbitmq"].(string)
	if !ok || rmqErr != "connection closed" {
		t.Errorf("expected rabbitmq=connection closed, got %v", details["rabbitmq"])
	}
}

func TestHealthMultipleDown(t *testing.T) {
	checker := health.NewChecker(
		&mockDB{err: errors.New("pg timeout")},
		&mockMinio{err: nil},
		&mockRabbitMQ{closed: true},
		"uploads",
	)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	rec := httptest.NewRecorder()

	checker.Handle(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected status 503, got %d", rec.Code)
	}

	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body["status"] != "unhealthy" {
		t.Errorf("expected status=unhealthy, got %v", body["status"])
	}

	details, ok := body["details"].(map[string]any)
	if !ok {
		t.Fatal("expected details map in response")
	}

	pgErr, ok := details["postgres"].(string)
	if !ok || pgErr != "pg timeout" {
		t.Errorf("expected postgres=pg timeout, got %v", details["postgres"])
	}

	rmqErr, ok := details["rabbitmq"].(string)
	if !ok || rmqErr != "connection closed" {
		t.Errorf("expected rabbitmq=connection closed, got %v", details["rabbitmq"])
	}
}
