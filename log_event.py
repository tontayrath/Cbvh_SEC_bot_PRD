"""
Helper module — imported by Mian.py to log blocked events to the dashboard.
"""
import os
import logging
import httpx

DASHBOARD_URLS   = [url.strip() for url in os.environ.get("DASHBOARD_URL", "http://localhost:5000").split(",") if url.strip()]
BOT_API_SECRET   = os.environ.get("BOT_API_SECRET", "bot-secret-key")
BOT_NAME         = os.environ.get("BOT_NAME", "EXE Guard Bot")

logger = logging.getLogger(__name__)

async def log_event(
    chat_id:     int,
    chat_title:  str,
    file_name:   str,
    block_type:  str,
    reason:      str,
    sender_name: str,
) -> None:
    """Send a blocked event to the dashboard API. Fire-and-forget."""
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            for url in DASHBOARD_URLS:
                try:
                    resp = await client.post(
                        f"{url}/api/log_event",
                        headers={"X-Bot-Secret": BOT_API_SECRET},
                        json={
                            "bot_name":    BOT_NAME,
                            "chat_id":     chat_id,
                            "chat_title":  chat_title,
                            "file_name":   file_name,
                            "block_type":  block_type,
                            "reason":      reason,
                            "sender_name": sender_name,
                        }
                    )
                    resp.raise_for_status()
                except Exception as e:
                    logger.error("Dashboard log failed for %s: %s", url, e)
    except Exception as e:
        logger.error("Dashboard log client error: %s", e)


async def log_group(chat_id: int, chat_title: str) -> None:
    """Register a group with the dashboard."""
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            for url in DASHBOARD_URLS:
                try:
                    resp = await client.post(
                        f"{url}/api/log_group",
                        headers={"X-Bot-Secret": BOT_API_SECRET},
                        json={
                            "bot_name":   BOT_NAME,
                            "chat_id":    chat_id,
                            "chat_title": chat_title,
                        }
                    )
                    resp.raise_for_status()
                except Exception as e:
                    logger.error("Dashboard group log failed for %s: %s", url, e)
    except Exception as e:
        logger.error("Dashboard log client error: %s", e)
