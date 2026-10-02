package server

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/daluoter/malscan-ingest/internal/health"
)

const testUploadAPIKey = "synthetic-upload-api-key-for-tests-0001"

func TestUploadAuthRejectsMalformedCredentialsBeforeReadingBody(t *testing.T) {
	tests := []struct {
		name   string
		header []string
	}{
		{name: "missing"},
		{name: "wrong scheme", header: []string{"Basic " + testUploadAPIKey}},
		{name: "missing token", header: []string{"Bearer "}},
		{name: "extra fields", header: []string{"Bearer " + testUploadAPIKey + " extra"}},
		{name: "wrong token", header: []string{"Bearer synthetic-wrong-api-key-for-tests-0001"}},
		{name: "duplicate authorization", header: []string{"Bearer " + testUploadAPIKey, "Bearer " + testUploadAPIKey}},
		{name: "tab separator", header: []string{"Bearer\t" + testUploadAPIKey}},
	}

	handler := &observedUploadHandler{}
	router := NewRouter(nil, handler, "*", UploadRateLimit{}, UploadAuth{Enabled: true, APIKey: testUploadAPIKey})
	const wantBody = "{\"error\":{\"code\":\"UNAUTHORIZED\",\"message\":\"Invalid or missing upload credentials.\"}}\n"

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body := &trackedBody{}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/files", nil)
			req.Body = body
			for _, value := range tc.header {
				req.Header.Add("Authorization", value)
			}
			response := httptest.NewRecorder()
			router.ServeHTTP(response, req)

			if response.Code != http.StatusUnauthorized {
				t.Errorf("status = %d, want 401", response.Code)
			}
			if got := response.Body.String(); got != wantBody {
				t.Errorf("body = %q, want exact body %q", got, wantBody)
			}
			if got := response.Header().Get("Content-Type"); got != "application/json" {
				t.Errorf("Content-Type = %q, want application/json", got)
			}
			if got := response.Header().Get("WWW-Authenticate"); got != "Bearer" {
				t.Errorf("WWW-Authenticate = %q, want Bearer", got)
			}
			if got := body.reads.Load(); got != 0 {
				t.Errorf("request body read %d times, want 0", got)
			}
		})
	}

	if got := handler.calls.Load(); got != 0 {
		t.Errorf("upload handler calls = %d, want 0", got)
	}
}

func TestUploadAuthDisabledAllowsRequestWithoutAuthorization(t *testing.T) {
	handler := &observedUploadHandler{}
	router := NewRouter(nil, handler, "*", UploadRateLimit{}, UploadAuth{})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/files", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 with auth disabled", response.Code)
	}
	if got := handler.calls.Load(); got != 1 {
		t.Errorf("upload handler calls = %d, want 1", got)
	}
}

func TestUploadAuthAcceptsValidBearerCredentials(t *testing.T) {
	handler := &observedUploadHandler{}
	router := NewRouter(nil, handler, "*", UploadRateLimit{}, UploadAuth{Enabled: true, APIKey: testUploadAPIKey})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/files", nil)
	req.Header.Set("Authorization", "bEaReR   "+testUploadAPIKey)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, req)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 for valid Bearer credentials", response.Code)
	}
	if got := handler.calls.Load(); got != 1 {
		t.Errorf("upload handler calls = %d, want 1", got)
	}
}

func TestUploadAuthRunsBeforeRateLimiter(t *testing.T) {
	handler := &observedUploadHandler{}
	router := NewRouter(nil, handler, "*", UploadRateLimit{Enabled: true, RPM: 1, Burst: 1}, UploadAuth{
		Enabled: true,
		APIKey:  testUploadAPIKey,
	})

	invalidBody := &trackedBody{}
	invalid := httptest.NewRequest(http.MethodPost, "/api/v1/files", nil)
	invalid.Body = invalidBody
	invalidResponse := httptest.NewRecorder()
	router.ServeHTTP(invalidResponse, invalid)
	if invalidResponse.Code != http.StatusUnauthorized {
		t.Fatalf("invalid request status = %d, want 401", invalidResponse.Code)
	}
	if invalidBody.reads.Load() != 0 {
		t.Errorf("invalid request body was read %d times, want 0", invalidBody.reads.Load())
	}

	validRequest := func() *http.Request {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/files", nil)
		req.Header.Set("Authorization", "Bearer "+testUploadAPIKey)
		return req
	}
	firstValid := httptest.NewRecorder()
	router.ServeHTTP(firstValid, validRequest())
	if firstValid.Code != http.StatusOK {
		t.Fatalf("first valid request status = %d, want 200 after invalid request", firstValid.Code)
	}
	secondValidBody := &trackedBody{}
	secondValidRequest := validRequest()
	secondValidRequest.Body = secondValidBody
	secondValid := httptest.NewRecorder()
	router.ServeHTTP(secondValid, secondValidRequest)
	if secondValid.Code != http.StatusTooManyRequests {
		t.Errorf("second valid request status = %d, want 429", secondValid.Code)
	}
	if secondValidBody.reads.Load() != 0 {
		t.Errorf("rate-limited body was read %d times, want 0", secondValidBody.reads.Load())
	}
	if got := handler.calls.Load(); got != 1 {
		t.Errorf("upload handler calls = %d, want 1", got)
	}
}

func TestUploadAuthDoesNotProtectHealthRoutes(t *testing.T) {
	checker := health.NewChecker(healthyDB{}, healthyMinio{}, healthyRabbitMQ{}, "uploads")
	router := NewRouter(checker, &observedUploadHandler{}, "*", UploadRateLimit{}, UploadAuth{
		Enabled: true,
		APIKey:  testUploadAPIKey,
	})

	for _, path := range []string{"/health", "/healthz"} {
		response := httptest.NewRecorder()
		router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusOK {
			t.Errorf("GET %s status = %d, want 200 without Authorization", path, response.Code)
		}
	}
}

func TestUploadAuthIsSafeForConcurrentRequests(t *testing.T) {
	handler := &observedUploadHandler{}
	router := NewRouter(nil, handler, "*", UploadRateLimit{}, UploadAuth{Enabled: true, APIKey: testUploadAPIKey})
	const requests = 32
	var wg sync.WaitGroup
	var successes int
	var successesMu sync.Mutex

	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPost, "/api/v1/files", nil)
			req.Header.Set("Authorization", "Bearer "+testUploadAPIKey)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, req)
			if response.Code == http.StatusOK {
				successesMu.Lock()
				successes++
				successesMu.Unlock()
			}
		}()
	}
	wg.Wait()

	if successes != requests {
		t.Errorf("concurrent successful requests = %d, want %d", successes, requests)
	}
	if got := handler.calls.Load(); got != requests {
		t.Errorf("upload handler calls = %d, want %d", got, requests)
	}
}
