from dotenv import load_dotenv
load_dotenv()

from log_event import log_event, log_group, log_group_leave

import os
import re
import io
import time
import asyncio
import logging
import zipfile
import urllib.parse

import httpx
from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    MessageHandler,
    ChatMemberHandler,
    TypeHandler,
    filters,
    ContextTypes,
)

# ── Tokens ────────────────────────────────────────────────────────────────────

API_TOKEN = os.environ.get("API_TOKEN", "")
if not API_TOKEN:
    raise ValueError("API_TOKEN is not set. Add it to your .env file.")

VT_API_KEY = os.environ.get("VT_API_KEY", "")

# ── Settings ──────────────────────────────────────────────────────────────────

WARNING_AUTO_DELETE_SECS = 3

BLOCKED_EXTENSIONS = {
    # ── Executables & scripts ──
    ".exe", ".msi", ".bat", ".cmd", ".com", ".scr", ".pif",
    ".vbs", ".vbe", ".js",  ".jse", ".wsf", ".wsh", ".ps1", ".psm1",
    ".appx", ".appxbundle", ".msix",
    ".hta", ".cpl", ".dll", ".reg", ".inf", ".lnk",
    # ── Archives & compressed (delivery vectors) ──
    ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz",
    ".tgz", ".tar.gz", ".tar.bz2", ".tar.xz",
    ".cab", ".arj", ".lzh", ".lzma", ".z", ".ace",
    # ── Split / multipart archives ──
    ".001", ".002", ".003", ".r00", ".r01", ".z01", ".z02",
    ".part1", ".part2",
    # ── Disk images ──
    ".iso", ".img", ".vhd", ".vhdx", ".vmdk", ".wim",
    # ── Other delivery formats ──
    ".apk", ".ipa", ".deb", ".rpm", ".dmg", ".pkg", ".app",
    ".jar", ".war", ".ear",
    ".swf", ".gadget", ".sys", ".drv",
}

BLOCKED_DOMAINS: set[str] = {
    "malware-traffic-analysis.net",
    "phishtank.com",
    "openphish.com",
    "bit.ly",
    "tinyurl.com",
    "t.co",
}

SUSPICIOUS_PARENT_DOMAINS: set[str] = {
    "trycloudflare.com",
    "ngrok.io",
    "ngrok-free.app",
    "localhost.run",
    "lhr.life",
    "serveo.net",
    "pagekite.me",
    "glitch.me",
    "repl.co",
    "vercel.app",
    "netlify.app",
    "web.app",
    "firebaseapp.com",
    "onrender.com",
    "railway.app",
    "herokuapp.com",
    "pythonanywhere.com",
}

# ── Logging ───────────────────────────────────────────────────────────────────

logging.basicConfig(
    format="%(asctime)s | %(levelname)s | %(name)s — %(message)s",
    level=logging.INFO,
)
logger = logging.getLogger(__name__)

# ── Warning messages ──────────────────────────────────────────────────────────

WARN_BLOCKED_EXT = (
    "⚠️ <b>សូមប្រុងប្រយ័ត្ន! File <code>{ext}</code> ត្រូវបានលុប!</b>\n\n"
    "🚫 File ប្រភេទ <code>{ext}</code> មិនអនុញ្ញាតនៅក្នុង Group នេះ។\n"
    "Sent by: {user}"
)

WARN_MAGIC_BYTES = (
    "⚠️ <b>សូមប្រុងប្រយ័ត្ន! File គ្រោះថ្នាក់ត្រូវបានលុប!</b>\n\n"
    "🔍 File <code>{name}</code> ត្រូវបានរកឃើញជា <b>{threat}</b> "
    "ទោះបីជាមានផ្នែកបន្ថែម <code>{ext}</code> ក៏ដោយ។\n"
    "Sent by: {user}"
)

WARN_BAD_LINK = (
    "⚠️ <b>សូមប្រុងប្រយ័ត្ន! Link គ្រោះថ្នាក់ត្រូវបានលុប!</b>\n\n"
    "🔗 Domain <code>{domain}</code> ត្រូវបានដាក់ទង់ថាជា Suspicious Link។\n"
    "⚠️ Reason: <i>{reason}</i>\n"
    "Sent by: {user}"
)

# ══════════════════════════════════════════════════════════════════════════════
#  ACTIVATION CHECK (dashboard-controlled lock / unlock)
# ══════════════════════════════════════════════════════════════════════════════

_activation_cache: dict[int, tuple[bool, float]] = {}   # chat_id → (active, timestamp)
ACTIVATION_CACHE_TTL = 300  # seconds (Optimized from 60 to 300 for faster processing)


async def check_activation(chat_id: int) -> bool:
    """Ask the dashboard whether this group is activated.

    Results are cached for ACTIVATION_CACHE_TTL seconds so we don't
    hit the dashboard API on every single message.
    """
    now = time.monotonic()
    cached = _activation_cache.get(chat_id)
    if cached and (now - cached[1]) < ACTIVATION_CACHE_TTL:
        return cached[0]

    dashboard_urls = [
        url.strip()
        for url in os.environ.get("DASHBOARD_URL", "http://localhost:3000").split(",")
        if url.strip()
    ]
    bot_secret = os.environ.get("BOT_API_SECRET", "bot-secret-key")

    for url in dashboard_urls:
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                resp = await client.post(
                    f"{url}/api/check_activation",
                    headers={"X-Bot-Secret": bot_secret},
                    json={"chat_id": chat_id, "token": API_TOKEN},
                )
                if resp.status_code == 200:
                    active = resp.json().get("active", False)
                    _activation_cache[chat_id] = (active, now)
                    logger.info(
                        "Activation check for chat %s: %s",
                        chat_id,
                        "ACTIVE" if active else "INACTIVE",
                    )
                    return active
        except Exception as e:
            logger.warning("Activation check failed for %s: %s", url, e)

    # If all dashboard URLs fail, default to active so we don't break
    # protection when the dashboard is temporarily unreachable.
    logger.warning("All dashboards unreachable — defaulting to ACTIVE for chat %s", chat_id)
    return True


WARN_NOT_ACTIVATED = (
    "🔒 <b>Bot មិនទាន់ត្រូវបានធ្វើឱ្យសកម្មក្នុង Group នេះទេ។</b>\n\n"
    "សូមប្រើពាក្យបញ្ជា /activate <code>KEY</code> ដើម្បីដាក់ Bot ឱ្យដំណើរការ។\n"
    "សូមទាក់ទង Admin ដើម្បីទទួលបាន Activation Key។"
)

ACTIVATE_SUCCESS = (
    "✅ <b>Bot ត្រូវបានធ្វើឱ្យសកម្មដោយជោគជ័យ!</b>\n\n"
    "🛡️ Bot នឹងការពារ Group នេះពីឥឡូវទៅ។"
)

ACTIVATE_FAIL = (
    "❌ <b>ការធ្វើឱ្យសកម្មបរាជ័យ!</b>\n\n"
    "⚠️ Reason: <i>{reason}</i>\n"
    "សូមពិនិត្យ Key ម្ដងទៀត ឬទាក់ទង Admin។"
)

# ══════════════════════════════════════════════════════════════════════════════
#  AUTO-DELETE HELPER
# ══════════════════════════════════════════════════════════════════════════════

async def _auto_delete(bot, chat_id: int, message_id: int, delay: int) -> None:
    """Wait `delay` seconds then silently delete a message."""
    await asyncio.sleep(delay)
    try:
        await bot.delete_message(chat_id=chat_id, message_id=message_id)
        logger.info("Warning auto-deleted (chat=%s msg=%s)", chat_id, message_id)
    except Exception as e:
        logger.warning("Warning auto-delete failed: %s", e)

# ══════════════════════════════════════════════════════════════════════════════
#  MAGIC BYTES DETECTION
# ══════════════════════════════════════════════════════════════════════════════

MAGIC_SCAN_BYTES = 8192


def detect_magic(header: bytes) -> str | None:
    if len(header) < 4:
        return None
    if header[:2] == b"MZ":
        return "PE executable (EXE/DLL/SCR)"
    if header[:2] == b"PK":
        try:
            with zipfile.ZipFile(io.BytesIO(header)) as zf:
                risky = {".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".hta", ".msi"}
                for name in zf.namelist():
                    ext = os.path.splitext(name.lower())[1]
                    if ext in risky:
                        return f"ZIP archive containing {ext.upper()} file"
        except Exception:
            pass
        return None
    if header[:4] == b"%PDF":
        snippet = header.decode("latin-1", errors="replace")
        if "/JS" in snippet or "/JavaScript" in snippet:
            return "PDF with embedded JavaScript"
        return None
    if header[:4] == b"\xd0\xcf\x11\xe0":
        snippet = header.decode("latin-1", errors="replace")
        if any(m in snippet for m in ["Macros", "VBA", "_VBA_PROJECT", "ThisDocument"]):
            return "Office document with VBA macros"
        return None
    return None


async def scan_file_magic(bot, file_id: str) -> str | None:
    try:
        tg_file = await bot.get_file(file_id)
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                tg_file.file_path,
                headers={"Range": f"bytes=0-{MAGIC_SCAN_BYTES - 1}"}
            )
            return detect_magic(resp.content)
    except Exception as e:
        logger.warning("Magic scan failed: %s", e)
        return None

# ══════════════════════════════════════════════════════════════════════════════
#  DOMAIN / LINK SCANNING
# ══════════════════════════════════════════════════════════════════════════════

VT_URL = "https://www.virustotal.com/api/v3/urls"

URL_RE = re.compile(
    r"https?://[^\s<>\"']+"
    r"|(?<!\w)(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/[^\s]*)?",
    re.IGNORECASE,
)


def extract_domains(text: str) -> list[str]:
    domains, seen = [], set()
    for match in URL_RE.findall(text):
        try:
            host = urllib.parse.urlparse(match).hostname if match.startswith("http") else match.split("/")[0]
            host = (host or "").lower().strip()
            if host and host not in seen:
                seen.add(host)
                domains.append(host)
        except Exception:
            pass
    return domains


def check_domain_local(domain: str) -> tuple[bool, str]:
    parts = domain.split(".")
    for i in range(len(parts) - 1):
        candidate = ".".join(parts[i:])
        if candidate in BLOCKED_DOMAINS:
            return True, f"Domain is on the blocked list ({candidate})"
    for i in range(len(parts) - 1):
        candidate = ".".join(parts[i:])
        if candidate in SUSPICIOUS_PARENT_DOMAINS:
            return True, f"Subdomain of a platform commonly abused for phishing ({candidate})"
    return False, ""


async def check_domain_virustotal(domain: str) -> tuple[bool, str]:
    if not VT_API_KEY:
        return False, ""
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(
                VT_URL,
                headers={"x-apikey": VT_API_KEY},
                data={"url": f"https://{domain}"},
            )
            if resp.status_code not in (200, 201):
                return False, ""
            analysis_id = resp.json().get("data", {}).get("id", "")
            if not analysis_id:
                return False, ""

            result_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            for _ in range(3):
                await asyncio.sleep(3)
                r = await client.get(result_url, headers={"x-apikey": VT_API_KEY})
                if r.status_code != 200:
                    continue
                stats = r.json().get("data", {}).get("attributes", {}).get("stats", {})
                malicious = stats.get("malicious", 0)
                if malicious >= 2:
                    return True, f"Flagged by {malicious} VirusTotal engines"
                if stats.get("harmless", 0) > 0:
                    return False, ""
    except Exception as e:
        logger.warning("VirusTotal check failed for %s: %s", domain, e)
    return False, ""


async def scan_links(text: str) -> tuple[bool, str, str]:
    for domain in extract_domains(text):
        blocked, reason = check_domain_local(domain)
        if blocked:
            logger.info("Local check blocked: %s — %s", domain, reason)
            return True, domain, reason
        if VT_API_KEY:
            flagged, vt_reason = await check_domain_virustotal(domain)
            if flagged:
                logger.info("VirusTotal blocked: %s — %s", domain, vt_reason)
                return True, domain, vt_reason
    return False, "", ""

# ══════════════════════════════════════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def is_blocked_extension(file_name: str) -> bool:
    if not file_name:
        return False
    _, ext = os.path.splitext(file_name.lower())
    return ext in BLOCKED_EXTENSIONS


def get_extension(file_name: str) -> str:
    if not file_name:
        return ""
    _, ext = os.path.splitext(file_name.lower())
    return ext.upper() if ext else "(no extension)"


def mention(user) -> str:
    if user.username:
        return f'<a href="tg://user?id={user.id}">@{user.username}</a>'
    return f'<a href="tg://user?id={user.id}">{user.full_name}</a>'


async def delete_and_warn(message, context, warning_text: str) -> None:
    """Delete the offending message, post a warning, then auto-delete the warning."""
    chat = message.chat
    bot  = context.bot

    async def _do_delete():
        try:
            await message.delete()
            logger.info("Message deleted.")
        except Exception as e:
            logger.debug("Could not delete message (might already be deleted): %s", e)
            
    # Trigger deletion in the background instantly
    context.application.create_task(_do_delete())

    try:
        warning = await bot.send_message(
            chat_id=chat.id,
            text=warning_text,
            parse_mode="HTML",
        )
    except Exception as e:
        logger.warning("Could not send warning: %s", e)
        return

    context.application.create_task(
        _auto_delete(bot, chat.id, warning.message_id, WARNING_AUTO_DELETE_SECS)
    )

# ══════════════════════════════════════════════════════════════════════════════
#  HANDLERS
# ══════════════════════════════════════════════════════════════════════════════

async def handle_activate(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle /activate KEY — register a group with an activation key."""
    message = update.message
    if not message:
        return

    chat = message.chat
    args = context.args  # ['KEY'] or []

    # Auto-delete the command message so the key doesn't stay in chat history
    try:
        await message.delete()
    except Exception:
        pass

    if not args:
        reply = await context.bot.send_message(
            chat_id=chat.id,
            text="⚠️ <b>សូមបញ្ចូល Activation Key!</b>\n\nExample: <code>/activate EG-A1B2-C3D4-E5F6</code>",
            parse_mode="HTML",
        )
        context.application.create_task(
            _auto_delete(context.bot, chat.id, reply.message_id, 5)
        )
        return

    key = args[0].strip().upper()
    dashboard_urls = [
        url.strip()
        for url in os.environ.get("DASHBOARD_URL", "http://localhost:3000").split(",")
        if url.strip()
    ]
    bot_secret = os.environ.get("BOT_API_SECRET", "bot-secret-key")

    activated = False
    error_reason = "Could not reach the dashboard"

    for url in dashboard_urls:
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.post(
                    f"{url}/api/activate",
                    headers={"X-Bot-Secret": bot_secret},
                    json={"key": key, "chat_id": chat.id},
                )
                data = resp.json()
                if resp.status_code == 200 and data.get("ok"):
                    activated = True
                    break
                else:
                    error_reason = data.get("error", "Unknown error")
                    break
        except Exception as e:
            logger.warning("Activate call failed for %s: %s", url, e)
            error_reason = str(e)

    if activated:
        # Clear the activation cache so the bot picks up the new state immediately
        _activation_cache.pop(chat.id, None)
        reply = await context.bot.send_message(
            chat_id=chat.id,
            text=ACTIVATE_SUCCESS,
            parse_mode="HTML",
        )
        logger.info("Group %s (%s) activated with key %s", chat.id, chat.title or "?", key)
    else:
        reply = await context.bot.send_message(
            chat_id=chat.id,
            text=ACTIVATE_FAIL.format(reason=error_reason),
            parse_mode="HTML",
        )
        logger.info("Activation failed for group %s: %s", chat.id, error_reason)

    # Auto-delete the reply after 5 seconds
    context.application.create_task(
        _auto_delete(context.bot, chat.id, reply.message_id, 5)
    )


async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.message or update.channel_post
    if not message or not message.document:
        return

    # ── Activation gate ──────────────────────────────────────────────────────
    if not await check_activation(message.chat.id):
        return

    doc          = message.document
    file_name    = doc.file_name or ""
    user         = message.from_user
    chat         = message.chat
    ext          = get_extension(file_name)
    user_mention = mention(user) if user else "Unknown user"

    # DEBUG: log every document received
    logger.info("📥 Document received: file_name='%s', ext='%s', mime='%s', chat='%s'",
                file_name, ext, doc.mime_type, chat.title or chat.id)

    # Log group to dashboard
    context.application.create_task(log_group(chat.id, chat.title or str(chat.id)))

    if is_blocked_extension(file_name):
        # ── INSTANT DELETE OPTIMIZATION ──
        # Fire the delete request immediately in the background so it happens < 1s
        async def _instant_delete():
            try:
                await message.delete()
            except Exception:
                pass
        context.application.create_task(_instant_delete())

        logger.info("Blocked by extension: '%s' from %s in '%s'",
                    file_name, user.full_name if user else "?", chat.title or chat.id)
        context.application.create_task(log_event(
            chat_id=chat.id, chat_title=chat.title or "",
            file_name=file_name, block_type="extension",
            reason=f"Dangerous file extension: {ext}",
            sender_name=user.full_name if user else "",
        ))
        await delete_and_warn(message, context,
                              WARN_BLOCKED_EXT.format(ext=ext, user=user_mention))
        return

    threat = await scan_file_magic(context.bot, doc.file_id)
    if threat:
        context.application.create_task(log_event(
            chat_id=chat.id, chat_title=chat.title or "",
            file_name=file_name, block_type="magic_bytes",
            reason=threat,
            sender_name=user.full_name if user else "",
        ))
        logger.info("Blocked by magic bytes: '%s' → %s from %s in '%s'",
                    file_name, threat, user.full_name if user else "?", chat.title or chat.id)
        await delete_and_warn(message, context,
                              WARN_MAGIC_BYTES.format(
                                  name=file_name or "(unnamed)",
                                  threat=threat,
                                  ext=ext or "(none)",
                                  user=user_mention,
                              ))
        return

    logger.info("File allowed: '%s' from %s", file_name, user.full_name if user else "?")


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.message or update.channel_post
    if not message or not message.text or "." not in message.text:
        return

    # ── Activation gate ──────────────────────────────────────────────────────
    if not await check_activation(message.chat.id):
        return

    is_bad, domain, reason = await scan_links(message.text)
    if not is_bad:
        return

    user         = message.from_user
    user_mention = mention(user) if user else "Unknown user"
    # Log group and event to dashboard
    context.application.create_task(log_group(message.chat.id, message.chat.title or str(message.chat.id)))
    context.application.create_task(log_event(
        chat_id=message.chat.id, chat_title=message.chat.title or "",
        file_name=domain, block_type="link",
        reason=reason,
        sender_name=user.full_name if user else "",
    ))
    logger.info("Blocked link: domain=%s reason=%s from %s in '%s'",
                domain, reason, user.full_name if user else "?",
                message.chat.title or message.chat.id)
    await delete_and_warn(message, context,
                          WARN_BAD_LINK.format(domain=domain, reason=reason, user=user_mention))


async def handle_caption(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.message or update.channel_post
    if not message or not message.caption or "." not in message.caption:
        return

    # ── Activation gate ──────────────────────────────────────────────────────
    if not await check_activation(message.chat.id):
        return

    is_bad, domain, reason = await scan_links(message.caption)
    if not is_bad:
        return

    user         = message.from_user
    user_mention = mention(user) if user else "Unknown user"
    context.application.create_task(log_event(
        chat_id=message.chat.id, chat_title=message.chat.title or "",
        file_name=domain, block_type="link",
        reason=reason,
        sender_name=user.full_name if user else "",
    ))
    logger.info("Blocked link in caption: domain=%s reason=%s", domain, reason)
    await delete_and_warn(message, context,
                          WARN_BAD_LINK.format(domain=domain, reason=reason, user=user_mention))

_admin_warning_msgs: dict[int, int] = {}  # chat_id -> message_id

async def handle_service_message(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Delete service messages (user joined/left, pinned message, etc.) to keep chat clean."""
    message = update.message or update.effective_message
    if not message:
        return

    logger.info("SERVICE MESSAGE: %s", update.to_dict())

    # Fallback: if the bot itself is the one who was left/kicked, log it!
    if message.left_chat_member and message.left_chat_member.id == context.bot.id:
        logger.info("Bot was removed (detected via service message): %s (%s)", message.chat.title, message.chat.id)
        _activation_cache.pop(message.chat.id, None)
        await log_group_leave(message.chat.id)

    # Fallback: if the bot itself was ADDED to the group, log it!
    if message.new_chat_members:
        for member in message.new_chat_members:
            if member.id == context.bot.id:
                logger.info("Bot was ADDED to group: %s (%s)", message.chat.title, message.chat.id)
                _activation_cache.pop(message.chat.id, None)
                await log_group(message.chat.id, message.chat.title or str(message.chat.id))
                
                # Check if we are admin, if not send a warning
                try:
                    bot_member = await context.bot.get_chat_member(message.chat.id, context.bot.id)
                    if bot_member.status != "administrator":
                        msg = await context.bot.send_message(
                            chat_id=message.chat.id,
                            text="⚠️ <b>ចំណាំ:</b> ខ្ញុំមិនទាន់មានសិទ្ធិជា Admin ទេ។\n\nសូម Promote ខ្ញុំជា Admin (ផ្តល់សិទ្ធិលុបសារ) ដើម្បីឲ្យខ្ញុំអាចការពារ Group នេះបាន!",
                            parse_mode="HTML"
                        )
                        _admin_warning_msgs[message.chat.id] = msg.message_id
                        context.application.create_task(_auto_delete(context.bot, message.chat.id, msg.message_id, 60))
                except Exception as e:
                    logger.warning("Could not send admin warning: %s", e)
                break

    try:
        await message.delete()
        logger.info(
            "Service message deleted (chat=%s type=%s)",
            message.chat.id,
            "join" if message.new_chat_members else
            "leave" if message.left_chat_member else "other",
        )
    except Exception as e:
        logger.warning("Could not delete service message: %s", e)
        error_msg = str(e).lower()
        if "kicked" in error_msg or "not a member" in error_msg or "forbidden" in error_msg:
            logger.info("Ultimate fallback: Bot was kicked! Updating dashboard for chat %s", message.chat.id)
            await log_group_leave(message.chat.id)

# ══════════════════════════════════════════════════════════════════════════════
#  GROUP LEAVE / KICK
# ══════════════════════════════════════════════════════════════════════════════

async def handle_my_chat_member(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Handle when the bot's own membership status in a group changes."""
    my_chat_member = update.my_chat_member
    if not my_chat_member:
        return

    chat = my_chat_member.chat
    new_status = my_chat_member.new_chat_member.status
    old_status = my_chat_member.old_chat_member.status

    logger.info(
        "MY_CHAT_MEMBER UPDATE: chat=%s (%s), old_status=%s, new_status=%s",
        chat.title, chat.id, old_status, new_status
    )

    if new_status in ["left", "kicked"]:
        logger.info("Triggering log_group_leave for chat: %s", chat.id)
        # Notify the dashboard
        await log_group_leave(chat.id)
    elif new_status == "administrator" and old_status != "administrator":
        # Bot was promoted to admin!
        logger.info("Bot promoted to admin in chat: %s", chat.id)
        
        # Delete the warning message if we sent one
        warning_msg_id = _admin_warning_msgs.pop(chat.id, None)
        if warning_msg_id:
            try:
                await context.bot.delete_message(chat_id=chat.id, message_id=warning_msg_id)
            except Exception:
                pass
                
        # Send a thank you message and auto-delete it after 15 seconds
        try:
            msg = await context.bot.send_message(
                chat_id=chat.id,
                text="✅ <b>អរគុណ!</b> ខ្ញុំទទួលបានសិទ្ធិជា Admin ហើយ។\n\nខ្ញុំនឹងចាប់ផ្តើមការពារ Group នេះឥឡូវនេះ!",
                parse_mode="HTML"
            )
            context.application.create_task(_auto_delete(context.bot, chat.id, msg.message_id, 15))
        except Exception as e:
            logger.warning("Could not send admin thank you msg: %s", e)

# ══════════════════════════════════════════════════════════════════════════════
#  HEARTBEAT
# ══════════════════════════════════════════════════════════════════════════════

async def heartbeat(context: ContextTypes.DEFAULT_TYPE) -> None:
    """Send a heartbeat ping to the dashboard every 30s to show the bot is alive."""
    dashboard_urls = [url.strip() for url in os.environ.get("DASHBOARD_URL", "http://localhost:3000").split(",") if url.strip()]
    bot_secret = os.environ.get("BOT_API_SECRET", "bot-secret-key")
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            for url in dashboard_urls:
                try:
                    await client.post(
                        f"{url}/api/heartbeat",
                        headers={"X-Bot-Secret": bot_secret},
                        json={"token": API_TOKEN}
                    )
                except Exception as e:
                    logger.debug("Dashboard heartbeat failed for %s: %s", url, e)
    except Exception as e:
        logger.debug("Dashboard heartbeat client error: %s", e)

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

async def debug_all_updates(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Log every single update received to see if my_chat_member is even in the JSON."""
    logger.info("DEBUG UPDATE: %s", update.to_dict())

def main() -> None:
    app = Application.builder().token(API_TOKEN).build()

    # Log absolutely every update before any other handler
    app.add_handler(TypeHandler(Update, debug_all_updates), group=-1)

    group_filter = (
        filters.ChatType.GROUPS |
        filters.ChatType.SUPERGROUP |
        filters.ChatType.PRIVATE
    )

    app.add_handler(CommandHandler("activate", handle_activate))
    app.add_handler(MessageHandler(filters.Document.ALL & group_filter, handle_document))
    app.add_handler(MessageHandler(filters.TEXT & group_filter, handle_text))
    app.add_handler(MessageHandler((filters.PHOTO | filters.VIDEO) & group_filter, handle_caption))

    # Track when the bot is kicked or leaves
    app.add_handler(ChatMemberHandler(handle_my_chat_member, ChatMemberHandler.MY_CHAT_MEMBER))

    # Auto-delete service messages (user joined, left, bot added/removed, etc.)
    service_filter = (
        filters.StatusUpdate.NEW_CHAT_MEMBERS |
        filters.StatusUpdate.LEFT_CHAT_MEMBER |
        filters.StatusUpdate.NEW_CHAT_TITLE |
        filters.StatusUpdate.NEW_CHAT_PHOTO |
        filters.StatusUpdate.DELETE_CHAT_PHOTO |
        filters.StatusUpdate.PINNED_MESSAGE
    )
    app.add_handler(MessageHandler(service_filter, handle_service_message))

    # Ping dashboard every 30s
    app.job_queue.run_repeating(heartbeat, interval=30, first=1)

    logger.info("EXE Guard Bot v3 is running. Press Ctrl+C to stop.")
    app.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
