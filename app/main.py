"""
FastAPI application entry point.
"""
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.database import engine, Base
from app.routers import auth, users

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(name)s  %(message)s",
)
logger = logging.getLogger(__name__)


# ── Lifespan (startup / shutdown) ─────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    Startup: create all DB tables if they don't exist.
    Shutdown: dispose the connection pool.
    """
    logger.info("🚀 Starting %s ...", settings.APP_NAME)
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("✅ Database tables ready.")
    yield
    await engine.dispose()
    logger.info("🔴 Shutting down.")


# ── App ───────────────────────────────────────────────────────────────────────

app = FastAPI(
    title=settings.APP_NAME,
    description="""
## JWT Authentication System

A production-ready authentication API built with **FastAPI + PostgreSQL**.

### Features
- 🔐 **Register** with email + password (bcrypt hashed)
- 🎫 **JWT tokens** — access (30 min) + refresh (7 days)
- 📧 **Email verification** via Gmail SMTP
- 🔑 **Password reset** via email link
- 🛡️ **Protected routes** with Bearer token
- 👑 **Role-based access** (user / admin)
""",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# ── CORS ──────────────────────────────────────────────────────────────────────
# Adjust origins for your frontend in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Routers ───────────────────────────────────────────────────────────────────
app.include_router(auth.router)
app.include_router(users.router)


# ── Health check ──────────────────────────────────────────────────────────────
@app.get("/health", tags=["Health"])
async def health_check():
    """Returns 200 OK — used by load balancers / Docker health checks."""
    return {"status": "ok", "app": settings.APP_NAME}
