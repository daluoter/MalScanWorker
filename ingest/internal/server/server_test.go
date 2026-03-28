package server_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/daluoter/malscan-ingest/internal/server"
)

// TestCORSPreflightWildcard verifies OPTIONS preflight returns proper CORS headers
// when origins are set to wildcard "*".
func TestCORSPreflightWildcard(t *testing.T) {
	r := server.NewRouter(nil, nil, "*")

	req := httptest.NewRequest("OPTIONS", "/api/v1/files", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	// Preflight must return 200
	if rr.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", rr.Code)
	}

	// Wildcard origin
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("expected Access-Control-Allow-Origin=*, got %q", got)
	}

	// Max-Age must be 600 (matching Python CORSMiddleware)
	if got := rr.Header().Get("Access-Control-Max-Age"); got != "600" {
		t.Errorf("expected Access-Control-Max-Age=600, got %q", got)
	}
}

// TestCORSPreflightSpecificOrigins verifies that when specific origins are configured,
// only matching origins are reflected back.
func TestCORSPreflightSpecificOrigins(t *testing.T) {
	r := server.NewRouter(nil, nil, "http://localhost:3000,http://example.com")

	tests := []struct {
		name       string
		origin     string
		wantOrigin string
	}{
		{
			name:       "matching origin reflected",
			origin:     "http://localhost:3000",
			wantOrigin: "http://localhost:3000",
		},
		{
			name:       "second matching origin reflected",
			origin:     "http://example.com",
			wantOrigin: "http://example.com",
		},
		{
			name:       "non-matching origin rejected",
			origin:     "http://evil.com",
			wantOrigin: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("OPTIONS", "/api/v1/files", nil)
			req.Header.Set("Origin", tt.origin)
			req.Header.Set("Access-Control-Request-Method", "POST")

			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)

			if got := rr.Header().Get("Access-Control-Allow-Origin"); got != tt.wantOrigin {
				t.Errorf("expected Access-Control-Allow-Origin=%q, got %q", tt.wantOrigin, got)
			}
		})
	}
}

// TestCORSAllowedMethods verifies each configured method is accepted by preflight.
// go-chi/cors echoes back the requested method (not all), so we test each individually.
func TestCORSAllowedMethods(t *testing.T) {
	r := server.NewRouter(nil, nil, "*")

	for _, method := range []string{"GET", "POST", "PUT", "DELETE", "PATCH"} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest("OPTIONS", "/api/v1/files", nil)
			req.Header.Set("Origin", "http://localhost:3000")
			req.Header.Set("Access-Control-Request-Method", method)

			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)

			methods := rr.Header().Get("Access-Control-Allow-Methods")
			if !strings.Contains(methods, method) {
				t.Errorf("expected Access-Control-Allow-Methods to include %s, got %q", method, methods)
			}
		})
	}
}

// TestCORSActualRequest verifies CORS headers on actual POST requests.
func TestCORSActualRequest(t *testing.T) {
	r := server.NewRouter(nil, nil, "*")

	// POST to /api/v1/files with Origin header — will fail at handler (nil),
	// but CORS headers should still be present before handler runs.
	req := httptest.NewRequest("POST", "/api/v1/files", nil)
	req.Header.Set("Origin", "http://localhost:3000")

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	// CORS middleware sets headers regardless of handler response
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("expected Access-Control-Allow-Origin=* on actual request, got %q", got)
	}
}

// TestCORSNoCredentials verifies Access-Control-Allow-Credentials is NOT set
// when using wildcard origins (matching Python allow_credentials=False).
func TestCORSNoCredentials(t *testing.T) {
	r := server.NewRouter(nil, nil, "*")

	req := httptest.NewRequest("OPTIONS", "/api/v1/files", nil)
	req.Header.Set("Origin", "http://localhost:3000")
	req.Header.Set("Access-Control-Request-Method", "POST")

	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	// When AllowCredentials is false, the header should not be present
	if got := rr.Header().Get("Access-Control-Allow-Credentials"); got == "true" {
		t.Errorf("expected no Allow-Credentials header (or not 'true'), got %q", got)
	}
}
