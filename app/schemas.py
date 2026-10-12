import uuid
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, EmailStr, Field, field_validator

from app.models import UserRole


# ══════════════════════════════════════════════════════════════════════════════
#  Auth Schemas
# ══════════════════════════════════════════════════════════════════════════════

class RegisterRequest(BaseModel):
    """Payload to create a new user account."""
    full_name: str     = Field(..., min_length=2, max_length=100, examples=["Ahmad Khan"])
    email:     EmailStr = Field(..., examples=["ahmad@example.com"])
    password:  str     = Field(..., min_length=8, max_length=128, examples=["Password123"])

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter.")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit.")
        return v


class LoginRequest(BaseModel):
    """Credentials for logging in."""
    email:    EmailStr = Field(..., examples=["ahmad@example.com"])
    password: str      = Field(..., examples=["Password123"])


class TokenResponse(BaseModel):
    """JWT tokens returned after login."""
    access_token:  str
    refresh_token: str
    token_type:    str = "bearer"


class RefreshTokenRequest(BaseModel):
    """Payload to refresh an access token."""
    refresh_token: str


# ══════════════════════════════════════════════════════════════════════════════
#  OTP Verification Schemas
# ══════════════════════════════════════════════════════════════════════════════

class VerifyOtpRequest(BaseModel):
    """Email + 6-digit OTP code to verify account."""
    email: EmailStr = Field(..., examples=["ahmad@example.com"])
    otp:   str      = Field(..., min_length=6, max_length=6, examples=["123456"])


class ResendOtpRequest(BaseModel):
    """Request a fresh OTP."""
    email: EmailStr = Field(..., examples=["ahmad@example.com"])


class ForgotPasswordRequest(BaseModel):
    """Email address to send password-reset OTP to."""
    email: EmailStr = Field(..., examples=["ahmad@example.com"])


class ResetPasswordOtpRequest(BaseModel):
    """Reset password using 6-digit OTP."""
    email:        EmailStr = Field(..., examples=["ahmad@example.com"])
    otp:          str      = Field(..., min_length=6, max_length=6, examples=["123456"])
    new_password: str      = Field(..., min_length=8, max_length=128, examples=["NewPassword123"])

    @field_validator("new_password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter.")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit.")
        return v


# ══════════════════════════════════════════════════════════════════════════════
#  User Schemas
# ══════════════════════════════════════════════════════════════════════════════

class UserProfile(BaseModel):
    """Public user profile (never expose hashed_password)."""
    id:                uuid.UUID
    full_name:         str
    email:             EmailStr
    role:              UserRole
    is_email_verified: bool
    is_active:         bool
    created_at:        datetime
    last_login_at:     Optional[datetime]

    model_config = {"from_attributes": True}


class UpdateProfileRequest(BaseModel):
    """Fields the user can update on their profile."""
    full_name: Optional[str] = Field(None, min_length=2, max_length=100)


class ChangePasswordRequest(BaseModel):
    """Change password when already logged in."""
    current_password: str
    new_password:     str = Field(..., min_length=8, max_length=128)

    @field_validator("new_password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter.")
        if not any(c.islower() for c in v):
            raise ValueError("Password must contain at least one lowercase letter.")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit.")
        return v


# ── Generic message response ──────────────────────────────────────────────────

class MessageResponse(BaseModel):
    message: str
