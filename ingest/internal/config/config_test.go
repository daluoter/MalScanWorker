package config

import (
	"os"
	"testing"
	"time"
)

// setRequiredEnv sets the minimum required env vars for config.Load() to succeed.
func setRequiredEnv(t *testing.T) {
	t.Helper()
	t.Setenv("DATABASE_URL", "postgresql://postgres:pass@localhost:5432/malscan")
	t.Setenv("MINIO_ENDPOINT", "localhost:9000")
	t.Setenv("MINIO_ACCESS_KEY", "minioaccess")
	t.Setenv("MINIO_SECRET_KEY", "miniosecret")
	t.Setenv("RABBITMQ_URL", "amqp://guest:guest@localhost:5672/")
}

func TestConfigDefaults(t *testing.T) {
	setRequiredEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	// Check defaults for optional fields
	if cfg.MinioBucket != "uploads" {
		t.Errorf("MinioBucket = %q, want %q", cfg.MinioBucket, "uploads")
	}
	if cfg.MinioSecure != false {
		t.Errorf("MinioSecure = %v, want false", cfg.MinioSecure)
	}
	if cfg.RabbitmqQueue != "malscan.jobs" {
		t.Errorf("RabbitmqQueue = %q, want %q", cfg.RabbitmqQueue, "malscan.jobs")
	}
	if cfg.MaxFileSize != 104857600 {
		t.Errorf("MaxFileSize = %d, want %d", cfg.MaxFileSize, 104857600)
	}
	if cfg.CORSOrigins != "*" {
		t.Errorf("CORSOrigins = %q, want %q", cfg.CORSOrigins, "*")
	}
	if cfg.LogLevel != "INFO" {
		t.Errorf("LogLevel = %q, want %q", cfg.LogLevel, "INFO")
	}
	if cfg.Port != 8080 {
		t.Errorf("Port = %d, want %d", cfg.Port, 8080)
	}
	if cfg.StagesTotal != 5 {
		t.Errorf("StagesTotal = %d, want %d", cfg.StagesTotal, 5)
	}
}

func TestDatabaseURLTransform(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("DATABASE_URL", "postgresql+asyncpg://postgres:pass@host:5432/db")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	want := "postgresql://postgres:pass@host:5432/db"
	if cfg.DatabaseURL != want {
		t.Errorf("DatabaseURL = %q, want %q", cfg.DatabaseURL, want)
	}
}

func TestDatabaseURLNoTransform(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("DATABASE_URL", "postgresql://postgres:pass@host:5432/db")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	want := "postgresql://postgres:pass@host:5432/db"
	if cfg.DatabaseURL != want {
		t.Errorf("DatabaseURL = %q, want %q", cfg.DatabaseURL, want)
	}
}

func TestConfigRequiredMissing(t *testing.T) {
	// Ensure required env vars are not set by registering them for cleanup
	// and then unsetting them. t.Setenv registers restore-on-cleanup;
	// os.Unsetenv actually removes the var for this test.
	for _, key := range []string{
		"DATABASE_URL", "MINIO_ENDPOINT", "MINIO_ACCESS_KEY",
		"MINIO_SECRET_KEY", "RABBITMQ_URL",
	} {
		t.Setenv(key, "") // register for cleanup
		os.Unsetenv(key)  // actually unset
	}

	_, err := Load()
	if err == nil {
		t.Fatal("Load() returned nil error, want error about missing DATABASE_URL")
	}

	// The error should mention DATABASE_URL
	if !containsStr(err.Error(), "DATABASE_URL") {
		t.Errorf("error = %q, want it to contain %q", err.Error(), "DATABASE_URL")
	}
}

func TestConfigCustomValues(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("PORT", "9090")
	t.Setenv("MAX_FILE_SIZE", "52428800")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	if cfg.Port != 9090 {
		t.Errorf("Port = %d, want %d", cfg.Port, 9090)
	}
	if cfg.MaxFileSize != 52428800 {
		t.Errorf("MaxFileSize = %d, want %d", cfg.MaxFileSize, 52428800)
	}
}

func TestShutdownTimeoutDefault(t *testing.T) {
	setRequiredEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	want := 30 * time.Second
	if cfg.ShutdownTimeout != want {
		t.Errorf("ShutdownTimeout = %v, want %v", cfg.ShutdownTimeout, want)
	}
}

func TestShutdownTimeoutCustom(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("SHUTDOWN_TIMEOUT", "45s")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	want := 45 * time.Second
	if cfg.ShutdownTimeout != want {
		t.Errorf("ShutdownTimeout = %v, want %v", cfg.ShutdownTimeout, want)
	}
}

func TestShutdownTimeoutCustomShort(t *testing.T) {
	setRequiredEnv(t)
	t.Setenv("SHUTDOWN_TIMEOUT", "10s")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	want := 10 * time.Second
	if cfg.ShutdownTimeout != want {
		t.Errorf("ShutdownTimeout = %v, want %v", cfg.ShutdownTimeout, want)
	}
}

// containsStr checks if s contains substr.
func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && searchStr(s, substr)
}

func searchStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
