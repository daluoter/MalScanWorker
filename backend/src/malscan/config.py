"""Application configuration using pydantic-settings."""

from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

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

    # CORS (use * for development, restrict in production via env var)
    cors_origins: str = "*"

    # Logging
    log_level: str = "INFO"
    log_format: str = "json"

    # File upload
    max_file_size: int = 20 * 1024 * 1024  # 20MB

    # Stages
    stages_total: int = 5

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
