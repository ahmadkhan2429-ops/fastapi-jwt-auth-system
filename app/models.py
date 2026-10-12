import uuid
import enum
from datetime import datetime, timezone

from sqlalchemy import (
    String, Boolean, DateTime, Enum as SAEnum,
    ForeignKey, Text, Uuid
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


# ── Enums ────────────────────────────────────────────────────────────────────

class UserRole(str, enum.Enum):
    """User roles for role-based access control."""
    ADMIN = "admin"
    USER  = "user"


class TokenType(str, enum.Enum):
    """Types of one-time tokens stored in DB."""
    EMAIL_VERIFICATION = "email_verification"
    PASSWORD_RESET     = "password_reset"


# ── Models ───────────────────────────────────────────────────────────────────

class User(Base):
    """
    Core user entity.

    Relationships:
        tokens  →  UserToken (one user → many tokens)
    """
    __tablename__ = "users"

    # Primary Key
    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4, index=True
    )

    # Identity
    full_name: Mapped[str]  = mapped_column(String(100), nullable=False)
    email:     Mapped[str]  = mapped_column(String(255), unique=True, index=True, nullable=False)

    # Authentication
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)

    # Email verification
    is_email_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Account status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Role-based access
    role: Mapped[UserRole] = mapped_column(
        SAEnum(UserRole), default=UserRole.USER, nullable=False
    )

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=False
    )
    last_login_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    tokens: Mapped[list["UserToken"]] = relationship(
        "UserToken", back_populates="user", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<User id={self.id} email={self.email} role={self.role}>"


class UserToken(Base):
    """
    Stores one-time tokens for email verification and password reset.

    Each token is:
      - UUID-based (secure, random)
      - Tied to a single User via FK
      - Typed (email_verification | password_reset)
      - Has an expiry datetime
      - Marked used once consumed
    """
    __tablename__ = "user_tokens"

    # Primary Key
    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), primary_key=True, default=uuid.uuid4
    )

    # The random token string sent in email links
    token: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)

    # FK → users
    user_id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )

    token_type: Mapped[TokenType] = mapped_column(SAEnum(TokenType), nullable=False)

    # Lifecycle
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    is_used:    Mapped[bool]     = mapped_column(Boolean, default=False, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False
    )

    # Relationships
    user: Mapped["User"] = relationship("User", back_populates="tokens")

    def __repr__(self) -> str:
        return f"<UserToken type={self.token_type} user_id={self.user_id} used={self.is_used}>"
