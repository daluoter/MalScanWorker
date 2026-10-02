package server

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	gocors "github.com/go-chi/cors"
	"golang.org/x/time/rate"

	"github.com/daluoter/malscan-ingest/internal/health"
	"github.com/daluoter/malscan-ingest/internal/upload"
)

// maxRequestBody is the absolute HTTP-level limit (150MB).
// Aborts before multipart parsing for clearly oversized requests (UPLOAD-04).
const maxRequestBody int64 = 150 * 1024 * 1024

// UploadRateLimit configures the process-local upload token bucket.
type UploadRateLimit struct {
	Enabled bool
	RPM     int
	Burst   int
}

// UploadAuth configures optional Bearer authentication for POST /api/v1/files.
type UploadAuth struct {
	Enabled bool
	APIKey  string
}

// NewRouter creates a chi router with CORS, health check, and upload routes.
// corsOrigins configures allowed origins: "*" for wildcard, or comma-separated
// list of origins (e.g. "http://localhost:3000,http://example.com").
// Matches Python FastAPI CORSMiddleware configuration exactly (main.py lines 34-52).
func NewRouter(checker *health.Checker, uploadHandler http.Handler, corsOrigins string, uploadRateLimit UploadRateLimit, uploadAuth UploadAuth) *chi.Mux {
	r := chi.NewRouter()

	// Parse CORS origins matching Python: main.py lines 35-38
	var origins []string
	if corsOrigins == "*" {
		origins = []string{"*"}
	} else {
		for _, o := range strings.Split(corsOrigins, ",") {
			if trimmed := strings.TrimSpace(o); trimmed != "" {
				origins = append(origins, trimmed)
			}
		}
	}

	// CORS middleware matching Python FastAPI CORSMiddleware exactly (D-06).
	// Added BEFORE Recoverer so CORS headers are set even on panics.
	r.Use(gocors.Handler(gocors.Options{
		AllowedOrigins:   origins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"},
		AllowedHeaders:   []string{"*"},
		ExposedHeaders:   []string{"*"},
		AllowCredentials: false,
		MaxAge:           600,
	}))

	r.Use(middleware.Recoverer)

	// Health endpoints (Phase 1)
	if checker != nil {
		r.Get("/health", checker.Handle)
		r.Get("/healthz", checker.Handle)
	}

	// Upload endpoint with MaxBytesReader (Phase 2). The limiter wraps the
	// route so rejected requests do not reach MaxBytesReader or the handler.
	var uploadRoute http.Handler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if uploadHandler == nil {
			http.Error(w, "upload handler not configured", http.StatusInternalServerError)
			return
		}
		req.Body = http.MaxBytesReader(w, req.Body, maxRequestBody)
		uploadHandler.ServeHTTP(w, req)
	})
	if uploadRateLimit.Enabled {
		limiter, retryAfter := newUploadRateLimiter(uploadRateLimit)
		uploadRoute = uploadRateLimitMiddleware(uploadRoute, limiter, retryAfter)
	}
	if uploadAuth.Enabled {
		// Authentication is outside the limiter so invalid credentials do not
		// consume upload capacity or reach body limiting/handling.
		uploadRoute = uploadAuthMiddleware(uploadRoute, uploadAuth.APIKey)
	}
	r.Post("/api/v1/files", uploadRoute.ServeHTTP)

	return r
}

func newUploadRateLimiter(cfg UploadRateLimit) (*rate.Limiter, string) {
	limiter := rate.NewLimiter(rate.Limit(float64(cfg.RPM)/60), cfg.Burst)
	return limiter, retryAfter(cfg.RPM)
}

func retryAfter(rpm int) string {
	if rpm <= 0 {
		return "1"
	}
	seconds := 60 / rpm
	if 60%rpm != 0 {
		seconds++
	}
	if seconds < 1 {
		seconds = 1
	}
	return strconv.Itoa(seconds)
}

func uploadAuthMiddleware(next http.Handler, apiKey string) http.Handler {
	expectedDigest := sha256.Sum256([]byte(apiKey))
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		token, ok := bearerToken(req.Header.Values("Authorization"))
		if !ok {
			writeUnauthorized(w)
			return
		}

		providedDigest := sha256.Sum256([]byte(token))
		if subtle.ConstantTimeCompare(expectedDigest[:], providedDigest[:]) != 1 {
			writeUnauthorized(w)
			return
		}
		next.ServeHTTP(w, req)
	})
}

func bearerToken(values []string) (string, bool) {
	if len(values) != 1 {
		return "", false
	}

	header := values[0]
	schemeEnd := strings.IndexByte(header, ' ')
	if schemeEnd <= 0 || !strings.EqualFold(header[:schemeEnd], "Bearer") {
		return "", false
	}

	// One or more SP characters separate the scheme from its credentials.
	token := strings.TrimLeft(header[schemeEnd+1:], " ")
	if token == "" || strings.ContainsAny(token, " \t\r\n") {
		return "", false
	}
	return token, true
}

func writeUnauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", "Bearer")
	upload.WriteError(w, http.StatusUnauthorized, upload.CodeUnauthorized,
		"Invalid or missing upload credentials.", nil)
}

func uploadRateLimitMiddleware(next http.Handler, limiter *rate.Limiter, retryAfter string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if limiter.Allow() {
			next.ServeHTTP(w, req)
			return
		}
		w.Header().Set("Retry-After", retryAfter)
		upload.WriteError(w, http.StatusTooManyRequests, upload.CodeRateLimitExceeded,
			"Upload rate limit exceeded. Please try again later.", nil)
	})
}
