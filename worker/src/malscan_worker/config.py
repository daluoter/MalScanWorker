"""Worker configuration."""

from functools import lru_cache

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Worker settings loaded from environment variables."""

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

    # Stage configuration
    stage_timeout_seconds: int = 300
    stages_total: int = 8

    # Deobfuscation
    deobfuscation_enabled: bool = True
    deobfuscation_max_file_size: int = 10_000_000
    deobfuscation_min_base64_length: int = 8
    deobfuscation_xor_min_decoded_length: int = 8
    deobfuscation_max_candidates: int = 100
    deobfuscation_per_decoder_limit: int = 25
    deobfuscation_confidence_threshold: float = 0.5
    deobfuscation_max_wall_time_seconds: float = 2.0
    deobfuscation_max_candidate_bytes: int = 4096

    # Extraction limits (depth controlled by existing max_job_depth)
    extraction_max_files: int = 100
    extraction_max_bytes: int = 500_000_000  # 500MB total
    extraction_max_single_bytes: int = 100_000_000  # 100MB per file
    extraction_max_ratio: float = 100.0
    extraction_timeout: int = 120  # seconds

    # YARA
    yara_rules_path: str = "/etc/yara/rules"

    # ClamAV
    clamav_host: str = "clamav"
    clamav_port: int = 3310

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
