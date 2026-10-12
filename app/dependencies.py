"""
FastAPI dependencies:
  - get_current_user   → any authenticated user (valid access token)
  - get_verified_user  → authenticated + email verified
  - require_admin      → authenticated + admin role
"""
import uuid
import logging
from typing import Annotated

from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.database import get_db
from app.models import User, UserRole
from app.security import decode_access_token

logger = logging.getLogger(__name__)

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


async def get_current_user(
    token: Annotated[str, Depends(oauth2_scheme)],
    db: Annotated[AsyncSession, Depends(get_db)],
) -> User:
    """
    Protected route dependency with detailed logging for debugging.
    """
    logger.info("Received token: %s...", token[:15] if token else "EMPTY")

    payload = decode_access_token(token)
    if payload is None:
        logger.error("Token decoding failed! (Secret key mismatch or expired)")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token decode failed: invalid or expired token.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id_str: str | None = payload.get("sub")
    logger.info("Decoded user_id from token: %s", user_id_str)
    if not user_id_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has no subject (user_id).",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # Fetch all users to debug ID match
    result = await db.execute(select(User))
    all_users = result.scalars().all()
    user = None
    for u in all_users:
        if str(u.id) == str(user_id_str):
            user = u
            break

    if user is None:
        logger.error("User ID %s not found in DB! Existing IDs: %s", user_id_str, [str(u.id) for u in all_users])
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"User with ID {user_id_str} not found in database.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Your account has been deactivated.",
        )

    return user


async def get_verified_user(
    current_user: Annotated[User, Depends(get_current_user)],
) -> User:
    """Requires authenticated user with email verified."""
    if not current_user.is_email_verified:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Please verify your email address first.",
        )
    return current_user


async def require_admin(
    current_user: Annotated[User, Depends(get_verified_user)],
) -> User:
    """Requires ADMIN role."""
    if current_user.role != UserRole.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required.",
        )
    return current_user
