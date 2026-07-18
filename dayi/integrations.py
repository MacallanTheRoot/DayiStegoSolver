"""
dayi/integrations.py
~~~~~~~~~~~~~~~~~~~~~
Real-time flag notification and auto-submission integration for Dayı v3.0.

Library resolution chain (first available wins, application never crashes):
  Priority 1 — ctfshit  : FlagSubmitter (CTFd) + send_flag_notification (Discord embed)
  Priority 2 — aiohttp  : direct async HTTP fallback for CTFd + Discord webhook
  Priority 3 — urllib   : stdlib sync fallback via run_in_executor (always available)

ctfshit import paths (as specified by the project):
  from ctfshit.src.api_client       import CTFdAPIClient
  from ctfshit.src.flag_submitter   import FlagSubmitter
  from ctfshit.src.discord_notifier import send_flag_notification

Public API:
  IntegrationManager(webhook, ctfd_url, ctfd_token, challenge_id, challenge_name)
  integration.notify(flag, tool_name)  ← fire-and-forget, never blocks caller
  await integration.drain()            ← flush pending tasks at end of scan

Design principles:
  - notify() is synchronous and returns immediately: it schedules an
    asyncio.Task internally so it never blocks the analysis pipeline.
  - Duplicate flags are tracked in a set(); each unique flag is dispatched
    at most once across all notification channels.
  - All network errors are caught and logged — an unreachable Discord webhook
    or an invalid CTFd token must never crash or stall the steganography scan.
"""
import asyncio
import importlib
import json
import logging
import urllib.error
import urllib.request
from typing import Optional

from dayi import __version__

logger = logging.getLogger("dayi")

def _resolve_optional_backends() -> tuple[tuple[object, object, object] | None, object | None]:
    """Lazy-load optional notification libraries only when integration is enabled."""
    ctfshit_backend = None
    aiohttp_backend = None
    try:
        api_module = importlib.import_module("ctfshit.src.api_client")
        submitter_module = importlib.import_module("ctfshit.src.flag_submitter")
        discord_module = importlib.import_module("ctfshit.src.discord_notifier")
        ctfshit_backend = (
            api_module.CTFdAPIClient,
            submitter_module.FlagSubmitter,
            discord_module.send_flag_notification,
        )
    except (ImportError, AttributeError):
        logger.debug("[integrations] ctfshit yok yeğenim, HTTP yedeğine bakıyorum.")
    try:
        aiohttp_backend = importlib.import_module("aiohttp")
    except ImportError:
        logger.debug("[integrations] aiohttp da yok; stdlib urllib nöbette yeğenim.")
    return ctfshit_backend, aiohttp_backend


# ---------------------------------------------------------------------------
# Stdlib urllib fallback (Tier 3 — always available)
# ---------------------------------------------------------------------------

def _urllib_post_json(url: str, payload: dict, extra_headers: dict | None = None) -> int:
    """
    Blocking HTTP POST with a JSON body via stdlib urllib.

    Intended to run inside asyncio.run_in_executor() so the event loop is
    never blocked. Returns the HTTP status code, or -1 on connection failure.

    Args:
        url:           Target URL.
        payload:       Dictionary to serialize as the JSON body.
        extra_headers: Optional additional HTTP headers.

    Returns:
        HTTP response status code, or -1 on failure.
    """
    body = json.dumps(payload).encode("utf-8")
    req  = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    if extra_headers:
        for key, val in extra_headers.items():
            req.add_header(key, val)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
    except Exception as exc:
        logger.debug(f"[integrations] urllib POST tökezledi yeğenim: {exc}")
        return -1


# ---------------------------------------------------------------------------
# IntegrationManager
# ---------------------------------------------------------------------------

class IntegrationManager:
    """
    Coordinates real-time flag notification and CTFd auto-submission.

    Instantiated once per scan from CLI arguments via build_integration().
    Each found flag is dispatched through notify(), which schedules an
    asyncio.Task and returns immediately. Call drain() at the end of the
    scan to flush any in-flight tasks before writing the final report.

    Duplicate flag suppression: each unique flag string is dispatched to
    external services at most once, regardless of how many tools find it.

    Attributes:
        webhook_url:    Discord incoming webhook URL (empty = disabled).
        ctfd_url:       CTFd base URL (empty = disabled).
        ctfd_token:     CTFd API token.
        challenge_id:   CTFd challenge ID to submit flags against (0 = disabled).
        challenge_name: Human-readable challenge name shown in Discord embed.
    """

    def __init__(
        self,
        webhook_url: str = "",
        ctfd_url: str = "",
        ctfd_token: str = "",
        challenge_id: int = 0,
        challenge_name: str = "Dayı Auto-Solve",
    ) -> None:
        self.webhook_url    = webhook_url
        self.ctfd_url       = ctfd_url.rstrip("/")
        self.ctfd_token     = ctfd_token
        self.challenge_id   = challenge_id
        self.challenge_name = challenge_name
        self._ctfshit_backend, self._aiohttp = _resolve_optional_backends()

        # In-flight asyncio.Task objects — needed for drain()
        self._tasks: set[asyncio.Task] = set()

        # Duplicate submission guard — flags already dispatched this scan
        self._sent_flags: set[str] = set()

        self._log_active_backend()

    def _log_active_backend(self) -> None:
        """Log which notification backend is active at startup."""
        if self._ctfshit_backend is not None:
            backend = "ctfshit (FlagSubmitter + Discord embed)"
        elif self._aiohttp is not None:
            backend = "aiohttp (doğrudan HTTP)"
        else:
            backend = "urllib (stdlib yedek — sıfır bağımlılık)"

        if self.ctfd_url or self.webhook_url:
            logger.info(
                f"[integrations] Entegrasyon aktif, backend: {backend}. "
                f"Flag bulunca müjdeyi hemen vereceğim yeğenim!"
            )
        else:
            logger.debug("[integrations] CTFd URL veya webhook yapılandırılmamış — pasif mod.")

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def notify(self, flag: str, tool_name: str) -> None:
        """
        Schedule an immediate fire-and-forget notification for a found flag.

        Returns synchronously after creating an asyncio.Task. The actual
        network calls happen in the background without blocking the scan.

        Duplicate flags (same string found by multiple tools) are silently
        discarded — each unique flag is dispatched at most once.

        Args:
            flag:      The flag string that was found.
            tool_name: Name of the discovering tool (for log context).
        """
        if flag in self._sent_flags:
            logger.debug(f"[integrations] Çift gönderim engellendi: {flag!r} (zaten yollandı).")
            return

        self._sent_flags.add(flag)

        logger.log(
            25,
            f"[integrations] 🚨 Müjde! '{flag}' ({tool_name} buldu). "
            "Yapılandırılmış servislere yolluyorum, dayın hallediyor..."
        )

        task = asyncio.create_task(self._dispatch(flag, tool_name))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def drain(self, timeout: float = 15.0) -> None:
        """
        Wait for all in-flight notification tasks to finish.

        Called once at the end of the scan (in a finally block inside runner)
        to ensure Discord/CTFd calls complete before the process exits.
        Respects a timeout so a slow server cannot indefinitely block exit.

        Args:
            timeout: Maximum seconds to wait for pending tasks.
        """
        if not self._tasks:
            return

        pending_count = len(self._tasks)
        logger.debug(
            f"[integrations] {pending_count} bekleyen bildirim tamamlanıyor..."
        )
        try:
            await asyncio.wait_for(
                asyncio.gather(*self._tasks, return_exceptions=True),
                timeout=timeout,
            )
            logger.debug("[integrations] Tüm bildirimler tamamlandı.")
        except asyncio.TimeoutError:
            logger.warning(
                f"[integrations] {timeout}s içinde bildirimler bitmedi, devam ediyoruz. "
                "Ağ yavaş olabilir, sorun değil yeğenim."
            )
            tasks = tuple(self._tasks)
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)

    # -------------------------------------------------------------------------
    # Internal dispatch — backend routing
    # -------------------------------------------------------------------------

    async def _dispatch(self, flag: str, tool_name: str) -> None:
        """
        Route flag notification through the highest-priority available backend.

        All exceptions are caught and logged so that a network failure never
        propagates to the event loop or interrupts the scan pipeline.

        Args:
            flag:      Found flag string.
            tool_name: Discovering tool name (for log context).
        """
        del tool_name
        if self._ctfshit_backend is not None:
            try:
                await self._send_via_ctfshit(flag)
                return
            except Exception as exc:
                logger.warning(
                    f"[integrations] ctfshit tökezledi yeğenim ({exc}); "
                    "HTTP yedeğine geçiyorum."
                )
        if self._aiohttp is not None:
            try:
                await self._send_via_aiohttp(flag)
                return
            except Exception as exc:
                logger.warning(
                    f"[integrations] aiohttp tökezledi yeğenim ({exc}); "
                    "stdlib yedeğine geçiyorum."
                )
        try:
            await self._send_via_urllib(flag)
        except Exception as exc:
            logger.warning(
                f"[integrations] Bildirim gönderilemedi ({flag!r}): {exc}. "
                "Taramaya devam ediyoruz, merak etme yeğenim."
            )

    # ── Tier 1: ctfshit ──────────────────────────────────────────────────────

    async def _send_via_ctfshit(self, flag: str) -> None:
        """
        Submit flag via ctfshit FlagSubmitter and send Discord embed via
        ctfshit send_flag_notification.

        Uses CTFdAPIClient as an async context manager to ensure the aiohttp
        session is properly opened and closed for each background submission.

        Args:
            flag: Flag string to submit and announce.
        """
        # ── CTFd submission ───────────────────────────────────────────────────
        if self._ctfshit_backend is None:
            raise RuntimeError("ctfshit backend is unavailable")
        api_client, flag_submitter, send_discord = self._ctfshit_backend
        failures: list[str] = []
        if self.ctfd_url and self.ctfd_token and self.challenge_id:
            try:
                async with api_client(self.ctfd_url, self.ctfd_token) as api:
                    submitter = flag_submitter(api)
                    result    = await submitter.submit_single_flag(self.challenge_id, flag)

                if result.correct:
                    logger.log(
                        25,
                        f"[integrations] ✅ CTFd kabul etti! "
                        f"'{self.challenge_name}' çözüldü, tebrikler yeğenim!"
                    )
                else:
                    logger.warning(
                        f"[integrations] CTFd flag'i reddetti: {result.message}. "
                        "Yanlış flag mı bulduk yoksa? Bir bak yeğenim..."
                    )
            except Exception as exc:
                logger.warning(f"[integrations] ctfshit CTFd hatası: {exc}")
                failures.append(f"CTFd: {exc}")

        # ── Discord notification ──────────────────────────────────────────────
        if self.webhook_url:
            try:
                await send_discord(
                    webhook_url=self.webhook_url,
                    challenge_name=self.challenge_name,
                    challenge_id=self.challenge_id or 0,
                    category="Stego",
                    points=0,       # Point value unknown at discovery time
                    flag=flag,
                    source="watch",
                )
                logger.info("[integrations] Discord bildirimi ctfshit üzerinden gönderildi.")
            except Exception as exc:
                logger.warning(f"[integrations] ctfshit Discord hatası: {exc}")
                failures.append(f"Discord: {exc}")
        if failures:
            raise RuntimeError("; ".join(failures))

    # ── Tier 2: aiohttp ───────────────────────────────────────────────────────

    async def _send_via_aiohttp(self, flag: str) -> None:
        """
        Submit to CTFd and post a Discord embed directly via aiohttp.

        Used when ctfshit is unavailable but aiohttp is installed.
        Targets the official CTFd v1 submission endpoint:
          POST /api/v1/challenges/attempt
          Body: {"challenge_id": <id>, "submission": "<flag>"}

        Args:
            flag: Flag string to submit and announce.
        """
        if self._aiohttp is None:
            raise RuntimeError("aiohttp backend is unavailable")
        failures: list[str] = []
        timeout = self._aiohttp.ClientTimeout(total=10)

        async with self._aiohttp.ClientSession(timeout=timeout) as session:
            # ── CTFd submission ───────────────────────────────────────────────
            if self.ctfd_url and self.ctfd_token and self.challenge_id:
                try:
                    payload = {
                        "challenge_id": self.challenge_id,
                        "submission":   flag,
                    }
                    headers = {
                        "Authorization": f"Token {self.ctfd_token}",
                        "Content-Type":  "application/json",
                    }
                    url = f"{self.ctfd_url}/api/v1/challenges/attempt"

                    async with session.post(url, json=payload, headers=headers) as resp:
                        data   = await resp.json(content_type=None)
                        status = data.get("data", {}).get("status", "unknown")

                        if status == "correct":
                            logger.log(
                                25,
                                "[integrations] ✅ aiohttp ile CTFd'ye flag gönderildi — "
                                "correct! Aferin yeğenim!"
                            )
                        else:
                            logger.warning(
                                f"[integrations] aiohttp CTFd yanıtı: status={status!r}. "
                                "Bakalım ne dedi..."
                            )
                except Exception as exc:
                    logger.warning(f"[integrations] aiohttp CTFd hatası: {exc}")
                    failures.append(f"CTFd: {exc}")

            # ── Discord webhook ───────────────────────────────────────────────
            if self.webhook_url:
                try:
                    embed = {
                        "title":  "🚩 Dayı Flag Buldu!",
                        "color":  0xFEE75C,
                        "fields": [
                            {
                                "name":   "Challenge",
                                "value":  f"`{self.challenge_name}`",
                                "inline": True,
                            },
                            {
                                "name":   "Flag",
                                "value":  f"||`{flag}`||",
                                "inline": False,
                            },
                        ],
                        "footer": {
                            "text": (
                                f"Dayı Stego Solver v{__version__} — "
                                "Hallederiz yeğenim!"
                            )
                        },
                    }
                    async with session.post(
                        self.webhook_url, json={"embeds": [embed]}
                    ) as resp:
                        if resp.status == 204:
                            logger.info("[integrations] aiohttp Discord bildirimi gönderildi.")
                        else:
                            body = await resp.text()
                            logger.warning(
                                f"[integrations] Discord webhook HTTP {resp.status}: {body[:200]}"
                            )
                            failures.append(f"Discord HTTP {resp.status}")
                except Exception as exc:
                    logger.warning(f"[integrations] aiohttp Discord hatası: {exc}")
                    failures.append(f"Discord: {exc}")
        if failures:
            raise RuntimeError("; ".join(failures))

    # ── Tier 3: urllib (stdlib — always available) ────────────────────────────

    async def _send_via_urllib(self, flag: str) -> None:
        """
        Submit to CTFd and post a Discord embed via stdlib urllib.

        Runs blocking urlopen() calls in a thread-pool executor so the event
        loop is never blocked. This is the last-resort fallback when neither
        ctfshit nor aiohttp is available.

        Args:
            flag: Flag string to submit and announce.
        """
        loop = asyncio.get_running_loop()

        # ── CTFd submission ───────────────────────────────────────────────────
        if self.ctfd_url and self.ctfd_token and self.challenge_id:
            try:
                payload = {
                    "challenge_id": self.challenge_id,
                    "submission":   flag,
                }
                auth_header = {"Authorization": f"Token {self.ctfd_token}"}
                url         = f"{self.ctfd_url}/api/v1/challenges/attempt"

                status_code = await loop.run_in_executor(
                    None, _urllib_post_json, url, payload, auth_header
                )
                if status_code in (200, 201):
                    logger.log(
                        25,
                        "[integrations] ✅ urllib ile CTFd'ye flag gönderildi! "
                        "Stdlib ile de hallederiz yeğenim!"
                    )
                else:
                    logger.warning(
                        f"[integrations] urllib CTFd yanıtı: HTTP {status_code}"
                    )
            except Exception as exc:
                logger.warning(f"[integrations] urllib CTFd hatası: {exc}")

        # ── Discord webhook ───────────────────────────────────────────────────
        if self.webhook_url:
            try:
                embed = {
                    "title":  "🚩 Dayı Flag Buldu!",
                    "color":  0xFEE75C,
                    "fields": [
                        {
                            "name":   "Challenge",
                            "value":  f"`{self.challenge_name}`",
                            "inline": True,
                        },
                        {
                            "name":   "Flag",
                            "value":  f"||`{flag}`||",
                            "inline": False,
                        },
                    ],
                    "footer": {
                        "text": (
                            f"Dayı Stego Solver v{__version__} — urllib yedeği"
                        )
                    },
                }
                status_code = await loop.run_in_executor(
                    None, _urllib_post_json, self.webhook_url, {"embeds": [embed]}, None
                )
                if status_code == 204:
                    logger.info("[integrations] urllib Discord bildirimi gönderildi.")
                else:
                    logger.warning(
                        f"[integrations] urllib Discord webhook HTTP {status_code}"
                    )
            except Exception as exc:
                logger.warning(f"[integrations] urllib Discord hatası: {exc}")


# ---------------------------------------------------------------------------
# Factory — used by cli.py to construct the integration from parsed args.
# ---------------------------------------------------------------------------

def build_integration(
    webhook_url: str = "",
    ctfd_url: str = "",
    ctfd_token: str = "",
    challenge_id: int = 0,
    challenge_name: str = "Dayı Auto-Solve",
) -> Optional["IntegrationManager"]:
    """
    Construct an IntegrationManager only when at least one notification
    endpoint is configured. Returns None if neither webhook nor CTFd URL
    is provided, keeping the default behaviour identical to v1.x.

    Args:
        webhook_url:    Discord incoming webhook URL.
        ctfd_url:       CTFd platform base URL.
        ctfd_token:     CTFd API token.
        challenge_id:   CTFd challenge ID (0 = no submission).
        challenge_name: Human-readable challenge name (Discord embed label).

    Returns:
        Configured IntegrationManager instance, or None.
    """
    if not (webhook_url or ctfd_url):
        return None

    return IntegrationManager(
        webhook_url=webhook_url,
        ctfd_url=ctfd_url,
        ctfd_token=ctfd_token,
        challenge_id=challenge_id,
        challenge_name=challenge_name,
    )
