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

// TestLoadFromDotEnvFile verifies that Load() reads variables from a .env file
// when OS env vars are not set. This tests the godotenv integration.
func TestLoadFromDotEnvFile(t *testing.T) {
	// Clear all required env vars so Load() must read them from .env
	for _, key := range []string{
		"DATABASE_URL", "MINIO_ENDPOINT", "MINIO_ACCESS_KEY",
		"MINIO_SECRET_KEY", "RABBITMQ_URL",
	} {
		t.Setenv(key, "") // register for cleanup
		os.Unsetenv(key)  // actually unset
	}

	// Create a temp directory with a .env file containing all required vars
	tmpDir := t.TempDir()
	envContent := `DATABASE_URL=postgresql://test:test@localhost:5432/testdb
MINIO_ENDPOINT=localhost:9000
MINIO_ACCESS_KEY=testaccess
MINIO_SECRET_KEY=testsecret
RABBITMQ_URL=amqp://test:test@localhost:5672/
`
	if err := os.WriteFile(tmpDir+"/.env", []byte(envContent), 0644); err != nil {
		t.Fatalf("failed to write .env: %v", err)
	}

	// Change to temp directory so godotenv.Load() finds the .env file
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	t.Cleanup(func() { os.Chdir(origDir) })

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to chdir to %s: %v", tmpDir, err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	if cfg.RabbitmqURL != "amqp://test:test@localhost:5672/" {
		t.Errorf("RabbitmqURL = %q, want %q", cfg.RabbitmqURL, "amqp://test:test@localhost:5672/")
	}
	if cfg.DatabaseURL != "postgresql://test:test@localhost:5432/testdb" {
		t.Errorf("DatabaseURL = %q, want %q", cfg.DatabaseURL, "postgresql://test:test@localhost:5432/testdb")
	}
}

// TestOsEnvOverridesDotEnv verifies that OS env vars take precedence over
// .env file values (godotenv's documented behavior: it does NOT override existing vars).
func TestOsEnvOverridesDotEnv(t *testing.T) {
	// Set required env vars via OS — these should win over .env values
	setRequiredEnv(t)
	osRabbitmqURL := "amqp://os-override:os-override@localhost:5672/"
	t.Setenv("RABBITMQ_URL", osRabbitmqURL)

	// Create a temp directory with a .env file containing different values
	tmpDir := t.TempDir()
	envContent := `DATABASE_URL=postgresql://dotenv:dotenv@localhost:5432/dotenvdb
MINIO_ENDPOINT=dotenv:9000
MINIO_ACCESS_KEY=dotenvaccess
MINIO_SECRET_KEY=dotenvsecret
RABBITMQ_URL=amqp://dotenv:dotenv@localhost:5672/
`
	if err := os.WriteFile(tmpDir+"/.env", []byte(envContent), 0644); err != nil {
		t.Fatalf("failed to write .env: %v", err)
	}

	// Change to temp directory
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatalf("failed to get working directory: %v", err)
	}
	t.Cleanup(func() { os.Chdir(origDir) })

	if err := os.Chdir(tmpDir); err != nil {
		t.Fatalf("failed to chdir to %s: %v", tmpDir, err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() returned error: %v", err)
	}

	// OS env var should win over .env value
	if cfg.RabbitmqURL != osRabbitmqURL {
		t.Errorf("RabbitmqURL = %q, want OS value %q (OS should override .env)", cfg.RabbitmqURL, osRabbitmqURL)
	}
}
