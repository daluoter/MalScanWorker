package config

import (
	"fmt"
	"strings"

	"github.com/caarlos0/env/v11"
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
	StagesTotal   int    `env:"STAGES_TOTAL"            envDefault:"5"`
}

// Load parses environment variables into Config and transforms DATABASE_URL.
// The shared .env file uses postgresql+asyncpg:// (SQLAlchemy dialect).
// pgx requires plain postgresql:// — we strip +asyncpg here (per DB-07).
func Load() (*Config, error) {
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// Strip SQLAlchemy asyncpg dialect: "postgresql+asyncpg://" → "postgresql://"
	cfg.DatabaseURL = strings.Replace(cfg.DatabaseURL, "+asyncpg", "", 1)

	return cfg, nil
}
