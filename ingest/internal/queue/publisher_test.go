package queue

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	amqp091 "github.com/rabbitmq/amqp091-go"
)

func testLogger() *slog.Logger {
	return slog.Default()
}

// ---------------------------------------------------------------------------
// Mock infrastructure
// ---------------------------------------------------------------------------

// mockChannel implements Channel for unit testing.
type mockChannel struct {
	// QueueDeclare
	queueDeclareErr  error
	queueDeclareName string
	queueDeclareArgs amqp091.Table
	queueDurable     bool
	queueAutoDelete  bool
	queueExclusive   bool
	queueNoWait      bool

	// Publish
	publishErr      error
	publishExchange string
	publishKey      string
	publishMsg      amqp091.Publishing

	// For retry testing: returns errors until attemptThreshold is reached.
	attemptCounter   int
	attemptThreshold int // publish succeeds on this attempt (1-indexed)
	attemptErrors    []error
}

func (m *mockChannel) QueueDeclare(name string, durable, autoDelete, exclusive, noWait bool, args amqp091.Table) (amqp091.Queue, error) {
	m.queueDeclareName = name
	m.queueDurable = durable
	m.queueAutoDelete = autoDelete
	m.queueExclusive = exclusive
	m.queueNoWait = noWait
	m.queueDeclareArgs = args
	return amqp091.Queue{Name: name}, m.queueDeclareErr
}

func (m *mockChannel) Publish(exchange, key string, mandatory, immediate bool, msg amqp091.Publishing) error {
	m.attemptCounter++
	m.publishExchange = exchange
	m.publishKey = key
	m.publishMsg = msg

	// If threshold is set, fail until that attempt
	if m.attemptThreshold > 0 {
		if m.attemptCounter < m.attemptThreshold {
			return errors.New("connection reset")
		}
		return nil
	}

	// If attemptErrors slice is provided, use it
	if len(m.attemptErrors) > 0 {
		idx := m.attemptCounter - 1
		if idx < len(m.attemptErrors) {
			return m.attemptErrors[idx]
		}
		return nil
	}

	return m.publishErr
}

func testMsg() JobMessage {
	return JobMessage{
		JobID:            "job-001",
		FileID:           "file-001",
		StorageKey:       "abc123def456",
		SHA256:           "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		OriginalFilename: "malware.exe",
	}
}

// ---------------------------------------------------------------------------
// Test 1: DeclareQueue -- success
// ---------------------------------------------------------------------------

func TestDeclareQueue_Success(t *testing.T) {
	ch := &mockChannel{}
	pub := NewPublisher(ch, "malscan.jobs", testLogger())

	err := pub.DeclareQueue(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify queue name
	if ch.queueDeclareName != "malscan.jobs" {
		t.Errorf("queue name = %q, want %q", ch.queueDeclareName, "malscan.jobs")
	}

	// Verify durable=true
	if !ch.queueDurable {
		t.Error("expected durable=true")
	}

	// Verify autoDelete=false
	if ch.queueAutoDelete {
		t.Error("expected autoDelete=false")
	}

	// Verify exclusive=false
	if ch.queueExclusive {
		t.Error("expected exclusive=false")
	}

	// Verify noWait=false
	if ch.queueNoWait {
		t.Error("expected noWait=false")
	}

	// Verify DLQ arguments
	if ch.queueDeclareArgs == nil {
		t.Fatal("expected DLQ args, got nil")
	}
	dlx, ok := ch.queueDeclareArgs["x-dead-letter-exchange"]
	if !ok || dlx != "" {
		t.Errorf("x-dead-letter-exchange = %v, want empty string", dlx)
	}
	dlrk, ok := ch.queueDeclareArgs["x-dead-letter-routing-key"]
	if !ok || dlrk != "malscan-dlq" {
		t.Errorf("x-dead-letter-routing-key = %v, want %q", dlrk, "malscan-dlq")
	}
}

// ---------------------------------------------------------------------------
// Test 2: Publish -- success
// ---------------------------------------------------------------------------

func TestPublish_Success(t *testing.T) {
	ch := &mockChannel{}
	pub := NewPublisher(ch, "malscan.jobs", testLogger())
	pub.retryBaseDelay = 1 * time.Millisecond // fast tests

	msg := testMsg()
	err := pub.Publish(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Verify default exchange
	if ch.publishExchange != "" {
		t.Errorf("exchange = %q, want empty string (default exchange)", ch.publishExchange)
	}

	// Verify routing key = queue name
	if ch.publishKey != "malscan.jobs" {
		t.Errorf("routing key = %q, want %q", ch.publishKey, "malscan.jobs")
	}

	// Verify delivery mode = Persistent (2)
	if ch.publishMsg.DeliveryMode != amqp091.Persistent {
		t.Errorf("delivery mode = %d, want %d (Persistent)", ch.publishMsg.DeliveryMode, amqp091.Persistent)
	}

	// Verify content type
	if ch.publishMsg.ContentType != "application/json" {
		t.Errorf("content type = %q, want %q", ch.publishMsg.ContentType, "application/json")
	}
}

// ---------------------------------------------------------------------------
// Test 3: Publish -- message format matches Python exactly
// ---------------------------------------------------------------------------

func TestPublish_MessageFormat(t *testing.T) {
	ch := &mockChannel{}
	pub := NewPublisher(ch, "malscan.jobs", testLogger())
	pub.retryBaseDelay = 1 * time.Millisecond

	msg := testMsg()
	err := pub.Publish(context.Background(), msg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Parse published JSON body
	var body map[string]any
	if err := json.Unmarshal(ch.publishMsg.Body, &body); err != nil {
		t.Fatalf("body is not valid JSON: %v", err)
	}

	// Exact keys must match Python worker expectations
	expectedKeys := []string{"job_id", "file_id", "storage_key", "sha256", "original_filename"}
	if len(body) != len(expectedKeys) {
		t.Errorf("JSON has %d keys, want %d", len(body), len(expectedKeys))
	}
	for _, key := range expectedKeys {
		if _, ok := body[key]; !ok {
			t.Errorf("missing JSON key %q", key)
		}
	}

	// Verify values
	if body["job_id"] != msg.JobID {
		t.Errorf("job_id = %v, want %v", body["job_id"], msg.JobID)
	}
	if body["file_id"] != msg.FileID {
		t.Errorf("file_id = %v, want %v", body["file_id"], msg.FileID)
	}
	if body["storage_key"] != msg.StorageKey {
		t.Errorf("storage_key = %v, want %v", body["storage_key"], msg.StorageKey)
	}
	if body["sha256"] != msg.SHA256 {
		t.Errorf("sha256 = %v, want %v", body["sha256"], msg.SHA256)
	}
	if body["original_filename"] != msg.OriginalFilename {
		t.Errorf("original_filename = %v, want %v", body["original_filename"], msg.OriginalFilename)
	}
}

// ---------------------------------------------------------------------------
// Test 4: Publish -- retry on failure (succeeds on 4th attempt)
// ---------------------------------------------------------------------------

func TestPublish_RetryOnFailure(t *testing.T) {
	ch := &mockChannel{
		attemptThreshold: 4, // fail 3 times, succeed on 4th
	}
	pub := NewPublisher(ch, "malscan.jobs", testLogger())
	pub.retryBaseDelay = 1 * time.Millisecond // fast tests

	msg := testMsg()
	err := pub.Publish(context.Background(), msg)
	if err != nil {
		t.Fatalf("expected success after retries, got error: %v", err)
	}

	if ch.attemptCounter != 4 {
		t.Errorf("attempt count = %d, want 4", ch.attemptCounter)
	}
}

// ---------------------------------------------------------------------------
// Test 5: Publish -- all retries exhausted
// ---------------------------------------------------------------------------

func TestPublish_AllRetriesExhausted(t *testing.T) {
	ch := &mockChannel{
		publishErr: errors.New("connection refused"),
	}
	pub := NewPublisher(ch, "malscan.jobs", testLogger())
	pub.retryBaseDelay = 1 * time.Millisecond // fast tests

	msg := testMsg()
	err := pub.Publish(context.Background(), msg)
	if err == nil {
		t.Fatal("expected error after all retries exhausted")
	}

	// Should have attempted 5 times
	if ch.attemptCounter != 5 {
		t.Errorf("attempt count = %d, want 5", ch.attemptCounter)
	}

	// Error message should mention attempt count
	if !strings.Contains(err.Error(), "5 attempts") {
		t.Errorf("error should mention 5 attempts, got: %v", err)
	}

	// Should wrap the original error
	if !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("error should wrap original error, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test 6: Publish -- backoff timing (exponential delays)
// ---------------------------------------------------------------------------

func TestPublish_BackoffTiming(t *testing.T) {
	var attempts atomic.Int32
	ch := &mockChannel{
		publishErr: errors.New("unavailable"),
	}
	pub := NewPublisher(ch, "malscan.jobs", testLogger())
	pub.retryBaseDelay = 10 * time.Millisecond // measurable but fast

	// Track timing of each attempt
	timestamps := make([]time.Time, 0, 5)
	origPublish := ch.publishErr

	// Use a custom mock that records timestamps
	timingCh := &timingMockChannel{
		err:        origPublish,
		timestamps: &timestamps,
		attempts:   &attempts,
	}

	pub2 := NewPublisher(timingCh, "malscan.jobs", testLogger())
	pub2.retryBaseDelay = 10 * time.Millisecond

	msg := testMsg()
	_ = pub2.Publish(context.Background(), msg)

	if int(attempts.Load()) != 5 {
		t.Fatalf("expected 5 attempts, got %d", attempts.Load())
	}

	// Verify delays are approximately exponential: 10ms, 20ms, 40ms, 80ms
	// Between attempt 1->2: ~10ms, 2->3: ~20ms, 3->4: ~40ms, 4->5: ~80ms
	if len(*timingCh.timestamps) < 5 {
		t.Fatalf("expected 5 timestamps, got %d", len(*timingCh.timestamps))
	}

	ts := *timingCh.timestamps
	for i := 1; i < len(ts); i++ {
		delay := ts[i].Sub(ts[i-1])
		expectedDelay := pub2.retryBaseDelay * time.Duration(1<<(i-1)) // 10ms, 20ms, 40ms, 80ms
		// Allow 50% tolerance for timing jitter
		minDelay := expectedDelay / 2
		if delay < minDelay {
			t.Errorf("delay between attempt %d and %d = %v, expected >= %v (50%% of %v)",
				i, i+1, delay, minDelay, expectedDelay)
		}
	}
}

// timingMockChannel records timestamps for each Publish call.
type timingMockChannel struct {
	err        error
	timestamps *[]time.Time
	attempts   *atomic.Int32
}

func (m *timingMockChannel) QueueDeclare(name string, durable, autoDelete, exclusive, noWait bool, args amqp091.Table) (amqp091.Queue, error) {
	return amqp091.Queue{Name: name}, nil
}

func (m *timingMockChannel) Publish(exchange, key string, mandatory, immediate bool, msg amqp091.Publishing) error {
	*m.timestamps = append(*m.timestamps, time.Now())
	m.attempts.Add(1)
	return m.err
}

// ---------------------------------------------------------------------------
// Test 7: Publish -- context cancellation stops retries
// ---------------------------------------------------------------------------

func TestPublish_ContextCancellation(t *testing.T) {
	ch := &mockChannel{
		publishErr: errors.New("unavailable"),
	}
	pub := NewPublisher(ch, "malscan.jobs", testLogger())
	pub.retryBaseDelay = 100 * time.Millisecond // long enough to cancel

	ctx, cancel := context.WithCancel(context.Background())

	// Cancel after a short delay to interrupt retries
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()

	msg := testMsg()
	err := pub.Publish(ctx, msg)
	if err == nil {
		t.Fatal("expected error from context cancellation")
	}

	// Should have been cancelled before all 5 attempts
	if ch.attemptCounter >= 5 {
		t.Errorf("expected fewer than 5 attempts due to cancellation, got %d", ch.attemptCounter)
	}
}
