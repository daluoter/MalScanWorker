package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/daluoter/malscan-ingest/internal/health"
	"github.com/daluoter/malscan-ingest/internal/upload"
)

// maxRequestBody is the absolute HTTP-level limit (150MB).
// Aborts before multipart parsing for clearly oversized requests (UPLOAD-04).
const maxRequestBody int64 = 150 * 1024 * 1024

// NewRouter creates a chi router with health check and upload routes.
func NewRouter(checker *health.Checker, uploadHandler *upload.Handler) *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)

	// Health endpoints (Phase 1)
	r.Get("/health", checker.Handle)
	r.Get("/healthz", checker.Handle)

	// Upload endpoint with MaxBytesReader (Phase 2)
	r.Post("/api/v1/files", func(w http.ResponseWriter, req *http.Request) {
		req.Body = http.MaxBytesReader(w, req.Body, maxRequestBody)
		uploadHandler.ServeHTTP(w, req)
	})

	return r
}
