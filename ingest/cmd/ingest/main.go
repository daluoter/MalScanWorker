package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
	"github.com/minio/minio-go/v7/pkg/lifecycle"
	amqp091 "github.com/rabbitmq/amqp091-go"

	"github.com/daluoter/malscan-ingest/internal/config"
	"github.com/daluoter/malscan-ingest/internal/health"
	"github.com/daluoter/malscan-ingest/internal/server"
)

func main() {
	if err := run(); err != nil {
		slog.Error("fatal error", "error", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}

	setupLogger(cfg.LogLevel)

	slog.Info("starting ingest service", "port", cfg.Port)

	ctx := context.Background()

	// Backend connections — fail-fast, sequential (per CONTEXT.md)
	pool, err := connectPostgres(ctx, cfg)
	if err != nil {
		return err
	}
	defer pool.Close()

	minioClient, err := connectMinio(ctx, cfg)
	if err != nil {
		return err
	}

	amqpConn, err := connectRabbitMQ(cfg)
	if err != nil {
		return err
	}
	defer amqpConn.Close()

	// Setup router with health endpoint
	checker := health.NewChecker(pool, minioClient, amqpConn, cfg.MinioBucket)
	r := server.NewRouter(checker)

	srv := &http.Server{
		Addr:              fmt.Sprintf(":%d", cfg.Port),
		Handler:           r,
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		slog.Info("server listening", "addr", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			slog.Error("server error", "error", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	slog.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// connectPostgres creates a pgxpool with explicit pool sizing (DB-06).
// Go gets 15 of ~60 total connections.
// Budget: Python backend=30, worker=15, Go ingest=15.
func connectPostgres(ctx context.Context, cfg *config.Config) (*pgxpool.Pool, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.DatabaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database url: %w", err)
	}

	poolCfg.MaxConns = 15
	poolCfg.MinConns = 2
	poolCfg.MaxConnLifetime = 30 * time.Minute
	poolCfg.MaxConnIdleTime = 5 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("create pg pool: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}

	slog.Info("connected to PostgreSQL")
	return pool, nil
}

// connectMinio creates the MinIO client and ensures the uploads bucket exists (STORE-02).
func connectMinio(ctx context.Context, cfg *config.Config) (*minio.Client, error) {
	client, err := minio.New(cfg.MinioEndpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.MinioAccessKey, cfg.MinioSecretKey, ""),
		Secure: cfg.MinioSecure,
	})
	if err != nil {
		return nil, fmt.Errorf("create minio client: %w", err)
	}

	// Auto-create uploads bucket if missing (STORE-02)
	if err := ensureBucket(ctx, client, cfg.MinioBucket); err != nil {
		return nil, err
	}

	slog.Info("connected to MinIO", "bucket", cfg.MinioBucket)
	return client, nil
}

// ensureBucket creates the bucket if missing and sets 1-day lifecycle expiration.
// Matches Python backend/src/malscan/storage.py init_buckets() exactly:
//
//	Rule(status="Enabled", rule_id="1-day-expiry",
//	     expiration=Expiration(days=1), rule_filter=Filter(prefix=""))
func ensureBucket(ctx context.Context, client *minio.Client, bucket string) error {
	exists, err := client.BucketExists(ctx, bucket)
	if err != nil {
		return fmt.Errorf("check bucket %q: %w", bucket, err)
	}
	if !exists {
		if err := client.MakeBucket(ctx, bucket, minio.MakeBucketOptions{}); err != nil {
			return fmt.Errorf("create bucket %q: %w", bucket, err)
		}
		slog.Info("bucket created", "bucket", bucket)
	}

	// Always set lifecycle (idempotent — replaces existing config)
	lcConfig := lifecycle.NewConfiguration()
	lcConfig.Rules = []lifecycle.Rule{
		{
			ID:     "1-day-expiry",
			Status: "Enabled",
			Expiration: lifecycle.Expiration{
				Days: lifecycle.ExpirationDays(1),
			},
		},
	}
	if err := client.SetBucketLifecycle(ctx, bucket, lcConfig); err != nil {
		return fmt.Errorf("set bucket lifecycle for %q: %w", bucket, err)
	}
	slog.Info("bucket lifecycle configured", "bucket", bucket, "expiry_days", 1)
	return nil
}

// connectRabbitMQ dials the broker and opens+closes a channel to verify connectivity (Pitfall 6).
func connectRabbitMQ(cfg *config.Config) (*amqp091.Connection, error) {
	conn, err := amqp091.Dial(cfg.RabbitmqURL)
	if err != nil {
		return nil, fmt.Errorf("connect rabbitmq: %w", err)
	}
	// Open and close a channel to fully verify connectivity (Pitfall 6)
	ch, err := conn.Channel()
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("rabbitmq channel test: %w", err)
	}
	ch.Close()

	slog.Info("connected to RabbitMQ")
	return conn, nil
}

// setupLogger configures slog with a JSON handler at the specified level.
func setupLogger(levelStr string) {
	var level slog.Level

	switch strings.ToUpper(levelStr) {
	case "DEBUG":
		level = slog.LevelDebug
	case "INFO":
		level = slog.LevelInfo
	case "WARN", "WARNING":
		level = slog.LevelWarn
	case "ERROR":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	handler := slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	logger := slog.New(handler).With("service", "ingest")
	slog.SetDefault(logger)
}
