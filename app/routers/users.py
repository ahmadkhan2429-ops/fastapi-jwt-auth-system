"""
User profile router — /users/* endpoints.

All routes require a valid JWT access token (protected routes).

Endpoints:
  GET    /users/me            → Get current user profile
  PATCH  /users/me            → Update profile (full_name)
  POST   /users/me/change-password → Change password (authenticated)
  GET    /users/              → [ADMIN] List all users
  DELETE /users/{user_id}     → [ADMIN] Delete a user
"""
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.dependencies import get_current_user, get_verified_user, require_admin
from app.models import User
from app.schemas import (
    UserProfile, UpdateProfileRequest,
    ChangePasswordRequest, MessageResponse,
)
from app.security import verify_password, hash_password

router = APIRouter(prefix="/users", tags=["Users"])


# ── My Profile ────────────────────────────────────────────────────────────────

@router.get("/me", response_model=UserProfile)
async def get_my_profile(
    current_user: Annotated[User, Depends(get_current_user)],
):
    """
    🔒 Protected route — requires valid Bearer token.
    Returns the logged-in user's profile.
    """
    return current_user


@router.patch("/me", response_model=UserProfile)
async def update_my_profile(
    payload: UpdateProfileRequest,
    current_user: Annotated[User, Depends(get_current_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """
    🔒 Protected route — update full_name.
    Extend this to allow avatar upload, phone number, etc.
    """
    if payload.full_name is not None:
        current_user.full_name = payload.full_name

    await db.commit()
    await db.refresh(current_user)
    return current_user


@router.post("/me/change-password", response_model=MessageResponse)
async def change_password(
    payload: ChangePasswordRequest,
    current_user: Annotated[User, Depends(get_verified_user)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """
    🔒 Protected + email-verified route — change password while logged in.
    Requires the current password for confirmation.
    """
    if not verify_password(payload.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect.")

    current_user.hashed_password = hash_password(payload.new_password)
    await db.commit()

    return MessageResponse(message="Password changed successfully.")


# ── Admin routes ──────────────────────────────────────────────────────────────

@router.get("/", response_model=list[UserProfile])
async def list_all_users(
    _: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
    skip: int = 0,
    limit: int = 50,
):
    """
    🔒 Admin-only route — list all users with pagination.
    """
    result = await db.execute(select(User).offset(skip).limit(limit))
    return result.scalars().all()


@router.delete("/{user_id}", response_model=MessageResponse)
async def delete_user(
    user_id: uuid.UUID,
    current_admin: Annotated[User, Depends(require_admin)],
    db: Annotated[AsyncSession, Depends(get_db)],
):
    """
    🔒 Admin-only route — delete a user by ID.
    Admin cannot delete themselves.
    """
    if user_id == current_admin.id:
        raise HTTPException(status_code=400, detail="You cannot delete your own account.")

    result = await db.execute(select(User).where(User.id == user_id))
    user   = result.scalar_one_or_none()

    if user is None:
        raise HTTPException(status_code=404, detail="User not found.")

    await db.delete(user)
    await db.commit()

    return MessageResponse(message=f"User {user.email} deleted successfully.")
