package config

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/caarlos0/env/v11"
	"github.com/joho/godotenv"
)

// Config holds all service configuration parsed from environment variables.
// Field names and defaults match backend/src/malscan/config.py exactly.
type Config struct {
	// Required — no defaults (security-sensitive)
	DatabaseURL    string `env:"DATABASE_URL,required"`
	MinioEndpoint  string `env:"MINIO_ENDPOINT,required"`
	MinioAccessKey string `env:"MINIO_ACCESS_KEY,required"`
	MinioSecretKey string `env:"MINIO_SECRET_KEY,required"`
	RabbitmqURL    string `env:"RABBITMQ_URL,required"`

	// Optional with defaults matching Python config.py
	MinioSecure   bool   `env:"MINIO_SECURE"          envDefault:"false"`
	MinioBucket   string `env:"MINIO_BUCKET_UPLOADS"   envDefault:"uploads"`
	RabbitmqQueue string `env:"RABBITMQ_QUEUE"         envDefault:"malscan.jobs"`
	MaxFileSize   int64  `env:"MAX_FILE_SIZE"           envDefault:"104857600"` // 100MB
	MaxDepth      int    `env:"MAX_DEPTH"               envDefault:"3"`         // max recursion depth for child jobs
	CORSOrigins   string `env:"CORS_ORIGINS"            envDefault:"*"`
	LogLevel      string `env:"LOG_LEVEL"               envDefault:"INFO"`
	Port          int    `env:"PORT"                    envDefault:"8080"`
	StagesTotal   int    `env:"STAGES_TOTAL"            envDefault:"9"`

	UploadRateLimitEnabled bool `env:"UPLOAD_RATE_LIMIT_ENABLED" envDefault:"true"`
	UploadRateLimitRPM     int  `env:"UPLOAD_RATE_LIMIT_RPM"     envDefault:"6"`
	UploadRateLimitBurst   int  `env:"UPLOAD_RATE_LIMIT_BURST"   envDefault:"2"`

	UploadAuthEnabled bool   `env:"UPLOAD_AUTH_ENABLED" envDefault:"false"`
	UploadAPIKey      string `env:"UPLOAD_API_KEY"      envDefault:""`

	ShutdownTimeout time.Duration `env:"SHUTDOWN_TIMEOUT" envDefault:"30s"`
}

// Load parses environment variables into Config and transforms DATABASE_URL.
// The shared .env file uses postgresql+asyncpg:// (SQLAlchemy dialect).
// pgx requires plain postgresql:// — we strip +asyncpg here (per DB-07).
func Load() (*Config, error) {
	// Load .env file for local development. Errors are silently ignored
	// so production deployments (no .env file) continue working via OS env vars.
	// godotenv does NOT override existing OS env vars — OS always wins.
	_ = godotenv.Load()

	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.UploadRateLimitEnabled && (cfg.UploadRateLimitRPM <= 0 || cfg.UploadRateLimitBurst <= 0) {
		return nil, fmt.Errorf("validate config: UPLOAD_RATE_LIMIT_RPM and UPLOAD_RATE_LIMIT_BURST must be positive when upload rate limiting is enabled")
	}
	if cfg.UploadAuthEnabled && (strings.TrimSpace(cfg.UploadAPIKey) == "" || utf8.RuneCountInString(cfg.UploadAPIKey) < 32) {
		return nil, fmt.Errorf("validate config: UPLOAD_API_KEY must contain at least 32 characters and not be whitespace when upload authentication is enabled")
	}

	// Strip SQLAlchemy asyncpg dialect: "postgresql+asyncpg://" → "postgresql://"
	cfg.DatabaseURL = strings.Replace(cfg.DatabaseURL, "+asyncpg", "", 1)

	return cfg, nil
}
