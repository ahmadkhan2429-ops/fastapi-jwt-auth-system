"""
Authentication router — all /auth/* endpoints with 6-Digit OTP.
Supports both JSON body and OAuth2 Form data for login!
"""
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, HTTPException, status, BackgroundTasks, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.dependencies import get_current_user
from app.models import User, UserToken, TokenType
from app.schemas import (
    RegisterRequest, LoginRequest, TokenResponse, RefreshTokenRequest,
    VerifyOtpRequest, ResendOtpRequest, ForgotPasswordRequest, ResetPasswordOtpRequest,
    MessageResponse,
)
from app.security import (
    hash_password, verify_password,
    create_access_token, create_refresh_token, decode_refresh_token,
)
from app.email_service import send_verification_otp, send_password_reset_otp

router = APIRouter(prefix="/auth", tags=["Authentication"])

OTP_EXPIRE_MINUTES = 10


def _generate_6digit_otp() -> str:
    """Generate a cryptographically secure 6-digit numeric OTP."""
    return str(secrets.randbelow(900000) + 100000)


# ── Register ──────────────────────────────────────────────────────────────────

@router.post("/register", response_model=MessageResponse, status_code=status.HTTP_201_CREATED)
async def register(
    payload: RegisterRequest,
    background_tasks: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Register a new user and generate a 6-digit OTP."""
    existing = await db.execute(select(User).where(User.email == payload.email))
    if existing.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered.")

    user = User(
        full_name=payload.full_name,
        email=payload.email,
        hashed_password=hash_password(payload.password),
    )
    db.add(user)
    await db.flush()

    otp_code = _generate_6digit_otp()
    db_token = UserToken(
        token=otp_code,
        user_id=user.id,
        token_type=TokenType.EMAIL_VERIFICATION,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRE_MINUTES),
    )
    db.add(db_token)
    await db.commit()

    background_tasks.add_task(
        send_verification_otp, user.email, user.full_name, otp_code
    )

    return MessageResponse(
        message="Account created! A 6-digit OTP has been sent (check terminal / email)."
    )


# ── Verify OTP ────────────────────────────────────────────────────────────────

@router.post("/verify-otp", response_model=MessageResponse)
async def verify_otp(
    payload: VerifyOtpRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Verify account using the 6-digit OTP code."""
    res_user = await db.execute(select(User).where(User.email == payload.email))
    user = res_user.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    if user.is_email_verified:
        return MessageResponse(message="Email is already verified. You can login.")

    res_token = await db.execute(
        select(UserToken).where(
            UserToken.user_id == user.id,
            UserToken.token == payload.otp,
            UserToken.token_type == TokenType.EMAIL_VERIFICATION,
            UserToken.is_used == False,
        )
    )
    db_token = res_token.scalar_one_or_none()

    if not db_token:
        raise HTTPException(status_code=400, detail="Invalid OTP code.")

    expires_at = db_token.expires_at
    if expires_at.tzinfo is not None:
        expires_at = expires_at.replace(tzinfo=None)
    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)

    if expires_at < now_utc:
        raise HTTPException(status_code=400, detail="OTP code has expired. Please request a new one.")

    user.is_email_verified = True
    db_token.is_used = True
    await db.commit()

    return MessageResponse(message="Email successfully verified! You can now login.")


# ── Resend OTP ────────────────────────────────────────────────────────────────

@router.post("/resend-otp", response_model=MessageResponse)
async def resend_otp(
    payload: ResendOtpRequest,
    background_tasks: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Resend a fresh 6-digit verification OTP."""
    res_user = await db.execute(select(User).where(User.email == payload.email))
    user = res_user.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    if user.is_email_verified:
        raise HTTPException(status_code=400, detail="Email is already verified.")

    otp_code = _generate_6digit_otp()
    db_token = UserToken(
        token=otp_code,
        user_id=user.id,
        token_type=TokenType.EMAIL_VERIFICATION,
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRE_MINUTES),
    )
    db.add(db_token)
    await db.commit()

    background_tasks.add_task(
        send_verification_otp, user.email, user.full_name, otp_code
    )

    return MessageResponse(message="A new 6-digit OTP has been sent.")


# ── Login (Supports BOTH JSON Body and Form Data for Swagger) ──────────────────

@router.post("/login", response_model=TokenResponse)
async def login(
    request: Request,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """
    Login with email + password.
    Accepts JSON body ({"email": "...", "password": "..."})
    OR Form data (username=...&password=...) for Swagger Authorize button.
    """
    content_type = request.headers.get("content-type", "")
    email = ""
    password = ""

    if "application/json" in content_type:
        body = await request.json()
        email = body.get("email") or body.get("username", "")
        password = body.get("password", "")
    else:
        form = await request.form()
        email = form.get("username") or form.get("email", "")
        password = form.get("password", "")

    if not email or not password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email and password are required.",
        )

    result = await db.execute(select(User).where(User.email == email))
    user = result.scalar_one_or_none()

    dummy_hash = "$2b$12$invalidhashtopreventtimingattack"
    valid = verify_password(
        password,
        user.hashed_password if user else dummy_hash
    )
    if not user or not valid:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is deactivated.")

    user.last_login_at = datetime.now(timezone.utc)
    await db.commit()

    access_token  = create_access_token(str(user.id), user.role.value)
    refresh_token = create_refresh_token(str(user.id))

    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


# ── Refresh Token ─────────────────────────────────────────────────────────────

@router.post("/refresh", response_model=TokenResponse)
async def refresh_tokens(
    payload: RefreshTokenRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Exchange refresh token for new access & refresh tokens."""
    token_data = decode_refresh_token(payload.refresh_token)
    if not token_data:
        raise HTTPException(status_code=401, detail="Invalid or expired refresh token.")

    user_id_str = token_data.get("sub")
    result = await db.execute(select(User))
    all_users = result.scalars().all()
    user = next((u for u in all_users if str(u.id) == str(user_id_str)), None)

    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or inactive.")

    access_token  = create_access_token(str(user.id), user.role.value)
    refresh_token = create_refresh_token(str(user.id))

    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


# ── Forgot Password ───────────────────────────────────────────────────────────

@router.post("/forgot-password", response_model=MessageResponse)
async def forgot_password(
    payload: ForgotPasswordRequest,
    background_tasks: BackgroundTasks,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Request a 6-digit password reset OTP."""
    result = await db.execute(select(User).where(User.email == payload.email))
    user = result.scalar_one_or_none()

    if user:
        otp_code = _generate_6digit_otp()
        db_token = UserToken(
            token=otp_code,
            user_id=user.id,
            token_type=TokenType.PASSWORD_RESET,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=OTP_EXPIRE_MINUTES),
        )
        db.add(db_token)
        await db.commit()

        background_tasks.add_task(
            send_password_reset_otp, user.email, user.full_name, otp_code
        )

    return MessageResponse(
        message="If this email is registered, you will receive a 6-digit reset OTP shortly."
    )


# ── Reset Password ────────────────────────────────────────────────────────────

@router.post("/reset-password-otp", response_model=MessageResponse)
async def reset_password_otp(
    payload: ResetPasswordOtpRequest,
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """Reset password using 6-digit OTP."""
    res_user = await db.execute(select(User).where(User.email == payload.email))
    user = res_user.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found.")

    res_token = await db.execute(
        select(UserToken).where(
            UserToken.user_id == user.id,
            UserToken.token == payload.otp,
            UserToken.token_type == TokenType.PASSWORD_RESET,
            UserToken.is_used == False,
        )
    )
    db_token = res_token.scalar_one_or_none()

    if not db_token:
        raise HTTPException(status_code=400, detail="Invalid OTP code.")

    expires_at = db_token.expires_at
    if expires_at.tzinfo is not None:
        expires_at = expires_at.replace(tzinfo=None)
    now_utc = datetime.now(timezone.utc).replace(tzinfo=None)

    if expires_at < now_utc:
        raise HTTPException(status_code=400, detail="OTP code has expired.")

    user.hashed_password = hash_password(payload.new_password)
    db_token.is_used = True
    await db.commit()

    return MessageResponse(message="Password reset successfully! You can now login with your new password.")


# ── Logout ────────────────────────────────────────────────────────────────────

@router.post("/logout", response_model=MessageResponse)
async def logout(
    _: Annotated[User, Depends(get_current_user)],
):
    """Stateless logout."""
    return MessageResponse(message="Logged out successfully.")
