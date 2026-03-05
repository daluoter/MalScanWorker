"""Application configuration using pydantic-settings."""

from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # Database (required - no default to enforce security)
    database_url: str

    # MinIO (required - no default to enforce security)
    minio_endpoint: str
    minio_access_key: str
    minio_secret_key: str
    minio_bucket_uploads: str = "uploads"
    minio_bucket_artifacts: str = "artifacts"
    minio_secure: bool = False

    # RabbitMQ (required - no default to enforce security)
    rabbitmq_url: str
    rabbitmq_queue: str = "malscan.jobs"

    # CORS (use * for development, restrict in production via env var)
    cors_origins: str = "*"

    # Logging
    log_level: str = "INFO"
    log_format: str = "json"

    # File upload
    max_file_size: int = 100 * 1024 * 1024  # 100MB

    # Stages
    stages_total: int = 5

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()
