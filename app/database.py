from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

from app.config import settings

# Async engine — uses asyncpg (PostgreSQL) or aiosqlite (SQLite)
is_sqlite = settings.DATABASE_URL.startswith("sqlite")
engine = create_async_engine(
    settings.DATABASE_URL,
    echo=False,          # Set True to log SQL (useful for debugging)
    connect_args={"check_same_thread": False} if is_sqlite else {},
    **({} if is_sqlite else {"pool_size": 10, "max_overflow": 20}),
)

# Session factory
AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)


class Base(DeclarativeBase):
    """All SQLAlchemy models inherit from this base."""
    pass


async def get_db() -> AsyncSession:
    """
    FastAPI dependency — yields an async DB session per request.
    Automatically closes the session when the request is done.
    """
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
