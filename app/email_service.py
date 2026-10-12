"""
Email service — sends transactional emails via Gmail SMTP,
or logs formatted OTP to terminal in development mode.
"""
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

import aiosmtplib

from app.config import settings

logger = logging.getLogger(__name__)


def _build_email(to: str, subject: str, html_body: str) -> MIMEMultipart:
    """Build a MIME email message."""
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = f"{settings.EMAILS_FROM_NAME} <{settings.EMAILS_FROM_EMAIL}>"
    msg["To"]      = to
    msg.attach(MIMEText(html_body, "html"))
    return msg


async def _send(to: str, subject: str, otp_code: str, action_name: str) -> None:
    """Send message via Gmail SMTP, or pretty print to console in dev mode."""
    if not settings.SMTP_USERNAME or not settings.SMTP_PASSWORD:
        # Dev mode — print visible box in terminal!
        print("\n" + "="*50)
        print(f"📬 [EMAIL SIMULATOR - DEV MODE]")
        print(f"To:      {to}")
        print(f"Action:  {action_name}")
        print(f"🔑 YOUR 6-DIGIT OTP IS:  >> {otp_code} <<")
        print(f"Expires in 10 minutes")
        print("="*50 + "\n")
        return

    # Real Gmail SMTP sending
    html_body = f"""
    <div style="font-family: Arial, sans-serif; max-width: 500px; margin: 0 auto; border: 1px solid #e5e7eb; padding: 24px; border-radius: 8px;">
      <h2 style="color: #2563eb; margin-top: 0;">{settings.APP_NAME}</h2>
      <p>Hello,</p>
      <p>Your one-time verification code for <strong>{action_name}</strong> is:</p>
      <div style="background: #f3f4f6; padding: 16px; border-radius: 6px; text-align: center; margin: 20px 0;">
        <span style="font-size: 32px; font-weight: bold; letter-spacing: 6px; color: #1f2937;">{otp_code}</span>
      </div>
      <p style="color: #6b7280; font-size: 13px;">
        This code is valid for 10 minutes. Do not share this code with anyone.
      </p>
    </div>
    """
    msg = _build_email(to, subject, html_body)

    try:
        await aiosmtplib.send(
            msg,
            hostname=settings.SMTP_HOST,
            port=settings.SMTP_PORT,
            username=settings.SMTP_USERNAME,
            password=settings.SMTP_PASSWORD,
            start_tls=True,
        )
        logger.info("Email with OTP sent to %s", to)
    except Exception as exc:
        logger.error("Failed to send email to %s: %s", to, exc)
        raise


async def send_verification_otp(to_email: str, full_name: str, otp: str) -> None:
    """Send 6-digit email verification OTP."""
    await _send(
        to=to_email,
        subject=f"Your Verification Code – {settings.APP_NAME}",
        otp_code=otp,
        action_name="Email Verification"
    )


async def send_password_reset_otp(to_email: str, full_name: str, otp: str) -> None:
    """Send 6-digit password reset OTP."""
    await _send(
        to=to_email,
        subject=f"Your Password Reset Code – {settings.APP_NAME}",
        otp_code=otp,
        action_name="Password Reset"
    )
