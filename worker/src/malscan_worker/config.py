"""Worker configuration."""

from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Worker settings loaded from environment variables."""

    # Database
    database_url: str = "postgresql+asyncpg://postgres:postgres@localhost:5432/malscan"

    # MinIO
    minio_endpoint: str = "localhost:9000"
    minio_access_key: str = "minioadmin"
    minio_secret_key: str = "minioadmin"
    minio_bucket_uploads: str = "uploads"
    minio_bucket_artifacts: str = "artifacts"
    minio_secure: bool = False

    # RabbitMQ
    rabbitmq_url: str = "amqp://guest:guest@localhost:5672/"
    rabbitmq_queue: str = "malscan.jobs"

    # Stage configuration
    stage_timeout_seconds: int = 300
    stages_total: int = 5

    # YARA
    yara_rules_path: str = "/etc/yara/rules"

    # ClamAV
    clamscan_path: str = "/usr/bin/clamscan"

    # Sandbox
    sandbox_enabled: bool = True
    sandbox_mock: bool = True

    # Metrics
    metrics_port: int = 9090

    # Logging
    log_level: str = "INFO"
    log_format: str = "json"

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
