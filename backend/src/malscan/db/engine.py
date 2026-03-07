"""Database engine configuration."""

from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from malscan.config import get_settings

_engine: AsyncEngine | None = None


def get_engine() -> AsyncEngine:
    """Get or create the async database engine."""
    global _engine
    if _engine is None:
        settings = get_settings()
        _engine = create_async_engine(
            settings.database_url,
            echo=False,
            pool_pre_ping=True,
            # Tuning connection pool for higher concurrency
            pool_size=10,
            max_overflow=20,
        )
    return _engine
