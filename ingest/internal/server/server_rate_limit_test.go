package server

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/daluoter/malscan-ingest/internal/health"
	"github.com/daluoter/malscan-ingest/internal/upload"
	"golang.org/x/time/rate"
)

type observedUploadHandler struct {
	calls atomic.Int32
}

func (h *observedUploadHandler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	h.calls.Add(1)
	if _, err := io.Copy(io.Discard, req.Body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusOK)
}

type trackedBody struct {
	reads atomic.Int32
}

func (b *trackedBody) Read([]byte) (int, error) {
	b.reads.Add(1)
	return 0, io.EOF
}

func (*trackedBody) Close() error { return nil }

type healthyDB struct{}

func (healthyDB) Ping(context.Context) error { return nil }

type healthyMinio struct{}

func (healthyMinio) BucketExists(context.Context, string) (bool, error) { return true, nil }

type healthyRabbitMQ struct{}

func (healthyRabbitMQ) IsClosed() bool { return false }

func TestUploadRateLimitAllowsConfiguredBurstThenRejectsWithoutReadingBody(t *testing.T) {
	handler := &observedUploadHandler{}
	router := NewRouter(nil, handler, "*", UploadRateLimit{Enabled: true, RPM: 7, Burst: 2}, UploadAuth{})

	for i := 0; i < 3; i++ {
		body := &trackedBody{}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/files", nil)
		req.Body = body
		response := httptest.NewRecorder()
		router.ServeHTTP(response, req)

		if i < 2 {
			if response.Code != http.StatusOK {
				t.Fatalf("request %d status = %d, want 200", i+1, response.Code)
			}
			if body.reads.Load() == 0 {
				t.Errorf("allowed request %d body was not read by the handler", i+1)
			}
			continue
		}

		if response.Code != http.StatusTooManyRequests {
			t.Fatalf("rejected request status = %d, want 429", response.Code)
		}
		if body.reads.Load() != 0 {
			t.Errorf("rejected request body read %d times, want 0", body.reads.Load())
		}
		if handler.calls.Load() != 2 {
			t.Errorf("handler calls = %d, want 2", handler.calls.Load())
		}

		var apiResponse upload.ApiErrorResponse
		if err := json.Unmarshal(response.Body.Bytes(), &apiResponse); err != nil {
			t.Fatalf("decode rate limit response: %v", err)
		}
		if apiResponse.Error.Code != upload.CodeRateLimitExceeded {
			t.Errorf("error code = %q, want %q", apiResponse.Error.Code, upload.CodeRateLimitExceeded)
		}
		if apiResponse.Error.Message != "Upload rate limit exceeded. Please try again later." {
			t.Errorf("error message = %q", apiResponse.Error.Message)
		}
		if response.Header().Get("Content-Type") != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", response.Header().Get("Content-Type"))
		}
		retryAfter, err := strconv.Atoi(response.Header().Get("Retry-After"))
		if err != nil || retryAfter != 9 {
			t.Errorf("Retry-After = %q, want integer 9 (parse error: %v)", response.Header().Get("Retry-After"), err)
		}
	}
}

func TestUploadRateLimitDoesNotConsumeOrBlockHealthRoutes(t *testing.T) {
	handler := &observedUploadHandler{}
	checker := health.NewChecker(healthyDB{}, healthyMinio{}, healthyRabbitMQ{}, "uploads")
	router := NewRouter(checker, handler, "*", UploadRateLimit{Enabled: true, RPM: 1, Burst: 1}, UploadAuth{})

	for i := 0; i < 20; i++ {
		for _, path := range []string{"/health", "/healthz"} {
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
			if response.Code != http.StatusOK {
				t.Fatalf("GET %s before exhaustion status = %d, want 200", path, response.Code)
			}
		}
	}

	first := httptest.NewRecorder()
	router.ServeHTTP(first, httptest.NewRequest(http.MethodPost, "/api/v1/files", nil))
	if first.Code != http.StatusOK {
		t.Fatalf("first upload status = %d, want 200 after health requests", first.Code)
	}
	second := httptest.NewRecorder()
	router.ServeHTTP(second, httptest.NewRequest(http.MethodPost, "/api/v1/files", nil))
	if second.Code != http.StatusTooManyRequests {
		t.Fatalf("second upload status = %d, want 429", second.Code)
	}

	for i := 0; i < 20; i++ {
		for _, path := range []string{"/health", "/healthz"} {
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
			if response.Code != http.StatusOK {
				t.Fatalf("GET %s after exhaustion status = %d, want 200", path, response.Code)
			}
		}
	}
	if handler.calls.Load() != 1 {
		t.Errorf("upload handler calls = %d, want 1", handler.calls.Load())
	}
}

func TestUploadRateLimitOnlyAppliesToPOSTFilesRoute(t *testing.T) {
	handler := &observedUploadHandler{}
	router := NewRouter(nil, handler, "*", UploadRateLimit{Enabled: true, RPM: 1, Burst: 1}, UploadAuth{})

	for _, tc := range []struct {
		method string
		path   string
		want   int
	}{
		{method: http.MethodGet, path: "/api/v1/files", want: http.StatusMethodNotAllowed},
		{method: http.MethodPost, path: "/api/v1/other", want: http.StatusNotFound},
	} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(tc.method, tc.path, nil))
		if response.Code != tc.want {
			t.Errorf("%s %s status = %d, want %d", tc.method, tc.path, response.Code, tc.want)
		}
	}

	uploadResponse := httptest.NewRecorder()
	router.ServeHTTP(uploadResponse, httptest.NewRequest(http.MethodPost, "/api/v1/files", nil))
	if uploadResponse.Code != http.StatusOK {
		t.Errorf("POST /api/v1/files status = %d, want 200 (other routes must not consume tokens)", uploadResponse.Code)
	}
	if handler.calls.Load() != 1 {
		t.Errorf("handler calls = %d, want 1", handler.calls.Load())
	}
}

func TestDisabledUploadRateLimitBypassesLimiter(t *testing.T) {
	handler := &observedUploadHandler{}
	router := NewRouter(nil, handler, "*", UploadRateLimit{Enabled: false, RPM: 0, Burst: -1}, UploadAuth{})

	for i := 0; i < 10; i++ {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/files", nil))
		if response.Code == http.StatusTooManyRequests {
			t.Fatalf("request %d was rate limited while limiter disabled", i+1)
		}
		if response.Code != http.StatusOK {
			t.Fatalf("request %d status = %d, want 200", i+1, response.Code)
		}
	}
}

func TestUploadRateLimitSharesBurstAcrossConcurrentRequests(t *testing.T) {
	handler := &observedUploadHandler{}
	router := NewRouter(nil, handler, "*", UploadRateLimit{Enabled: true, RPM: 1, Burst: 5}, UploadAuth{})
	const requests = 64
	var allowed atomic.Int32
	var rejected atomic.Int32
	var wg sync.WaitGroup

	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/files", nil))
			switch response.Code {
			case http.StatusOK:
				allowed.Add(1)
			case http.StatusTooManyRequests:
				rejected.Add(1)
			default:
				t.Errorf("concurrent request status = %d, want 200 or 429", response.Code)
			}
		}()
	}
	wg.Wait()

	if got := allowed.Load(); got != 5 {
		t.Errorf("allowed concurrent requests = %d, want burst 5", got)
	}
	if got := rejected.Load(); got != requests-5 {
		t.Errorf("rejected concurrent requests = %d, want %d", got, requests-5)
	}
}

func TestNewUploadRateLimiterConfigurationAndDeterministicRefill(t *testing.T) {
	limiter, retryAfter := newUploadRateLimiter(UploadRateLimit{Enabled: true, RPM: 6, Burst: 2})
	if limiter.Limit() != rate.Limit(0.1) {
		t.Errorf("limiter rate = %v, want 0.1 tokens/second", limiter.Limit())
	}
	if limiter.Burst() != 2 {
		t.Errorf("limiter burst = %d, want 2", limiter.Burst())
	}
	if retryAfter != "10" {
		t.Errorf("Retry-After = %q, want 10", retryAfter)
	}

	now := time.Unix(1_700_000_000, 0)
	if !limiter.AllowN(now, 2) {
		t.Fatal("initial burst of two tokens was not available")
	}
	if limiter.AllowN(now, 1) {
		t.Fatal("token bucket allowed a request without a token")
	}
	if !limiter.AllowN(now.Add(10*time.Second), 1) {
		t.Fatal("one token was not replenished after ten seconds at six RPM")
	}
	if limiter.AllowN(now.Add(10*time.Second), 1) {
		t.Fatal("token bucket allowed more than the single replenished token")
	}
}

func TestRetryAfterUsesConservativeIntegerCeiling(t *testing.T) {
	for _, tc := range []struct {
		rpm  int
		want string
	}{
		{rpm: 7, want: "9"},
		{rpm: 60, want: "1"},
		{rpm: 61, want: "1"},
		{rpm: int(^uint(0) >> 1), want: "1"},
	} {
		got := retryAfter(tc.rpm)
		if got != tc.want {
			t.Errorf("retryAfter(%d) = %q, want %q", tc.rpm, got, tc.want)
		}
		if _, err := strconv.Atoi(got); err != nil {
			t.Errorf("retryAfter(%d) = %q is not an integer: %v", tc.rpm, got, err)
		}
	}
}
