package server

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	gocors "github.com/go-chi/cors"

	"github.com/daluoter/malscan-ingest/internal/health"
	"github.com/daluoter/malscan-ingest/internal/upload"
)

// maxRequestBody is the absolute HTTP-level limit (150MB).
// Aborts before multipart parsing for clearly oversized requests (UPLOAD-04).
const maxRequestBody int64 = 150 * 1024 * 1024

// NewRouter creates a chi router with CORS, health check, and upload routes.
// corsOrigins configures allowed origins: "*" for wildcard, or comma-separated
// list of origins (e.g. "http://localhost:3000,http://example.com").
// Matches Python FastAPI CORSMiddleware configuration exactly (main.py lines 34-52).
func NewRouter(checker *health.Checker, uploadHandler *upload.Handler, corsOrigins string) *chi.Mux {
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

	// Upload endpoint with MaxBytesReader (Phase 2)
	r.Post("/api/v1/files", func(w http.ResponseWriter, req *http.Request) {
		if uploadHandler == nil {
			http.Error(w, "upload handler not configured", http.StatusInternalServerError)
			return
		}
		req.Body = http.MaxBytesReader(w, req.Body, maxRequestBody)
		uploadHandler.ServeHTTP(w, req)
	})

	return r
}
