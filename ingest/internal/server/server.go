package server

import (
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/daluoter/malscan-ingest/internal/health"
)

// NewRouter creates a chi router with health check routes and recovery middleware.
func NewRouter(checker *health.Checker) *chi.Mux {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)

	// Primary health endpoint (per CONTEXT.md locked decision)
	r.Get("/health", checker.Handle)
	// Alias for K8s compatibility (OPS-01 says /healthz)
	r.Get("/healthz", checker.Handle)

	return r
}
