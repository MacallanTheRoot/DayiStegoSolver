"""
dayi/integrations.py
~~~~~~~~~~~~~~~~~~~~~
Real-time flag notification and auto-submission integration for Dayı v3.0.

One native transport is selected when the manager is created:
  Priority 1 — aiohttp : direct asynchronous HTTP
  Priority 2 — urllib  : stdlib HTTP in a killable isolated worker

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
import os
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Callable, Literal, Optional

from dayi import __version__
from dayi.tools._base import async_run_isolated

logger = logging.getLogger("dayi")


NOTIFICATION_TOTAL_TIMEOUT = 10.0
NOTIFICATION_CONNECT_TIMEOUT = 5.0
NOTIFICATION_READ_TIMEOUT = 5.0
URLLIB_REQUEST_TIMEOUT = 10.0
CTFD_RESPONSE_LIMIT = 64 * 1024
URLLIB_WORKER_RESPONSE_LIMIT = 128 * 1024
_CTFD_ATTEMPT_PATH = "/api/v1/challenges/attempt"
_DEFAULT_CHALLENGE_NAME = "Dayı Auto-Solve"


Channel = Literal["ctfd", "discord"]
ErrorCategory = Literal[
    "configuration",
    "timeout",
    "network",
    "rejected",
    "invalid-response",
    "internal",
]
ConfigurationState = Literal["configured", "incomplete", "invalid", "not-configured"]


@dataclass(frozen=True)
class DeliveryResult:
    """Secret-free outcome of one notification channel attempt."""

    channel: Channel
    attempted: bool
    success: bool
    status_code: int | None
    error_category: ErrorCategory | None


@dataclass(frozen=True)
class NotificationConfiguration:
    """Selected CLI/environment notification values before URL validation."""

    webhook_url: str
    ctfd_url: str
    ctfd_token: str
    challenge_id: int
    challenge_name: str


@dataclass(frozen=True)
class NativeNotificationDiagnostic:
    """Secret-free, network-free notification capability status."""

    transport: Literal["aiohttp", "urllib"]
    ctfd_status: ConfigurationState
    discord_status: ConfigurationState


@dataclass(frozen=True)
class _HttpResponse:
    """Bounded native HTTP response data used by the urllib transport."""

    status_code: int
    body: bytes | None
    body_oversized: bool


def _environment_text(name: str) -> str | None:
    value = os.environ.get(name)
    if value is None or not value.strip():
        return None
    return value.strip()


def _select_text(cli_value: str | None, environment_name: str, default: str = "") -> str:
    if cli_value is not None:
        return cli_value.strip()
    return _environment_text(environment_name) or default


def select_notification_configuration(
    *,
    webhook_url: str | None = None,
    ctfd_url: str | None = None,
    ctfd_token: str | None = None,
    challenge_id: int | None = None,
    challenge_name: str | None = None,
) -> NotificationConfiguration:
    """Apply per-field CLI, environment, and default precedence once."""
    selected_challenge_id = challenge_id
    if selected_challenge_id is None:
        raw_challenge_id = _environment_text("DAYI_CTFD_CHALLENGE_ID")
        if raw_challenge_id is None:
            selected_challenge_id = 0
        else:
            try:
                selected_challenge_id = int(raw_challenge_id)
            except ValueError:
                selected_challenge_id = 0
                logger.warning(
                    "[integrations] DAYI_CTFD_CHALLENGE_ID geçersiz; "
                    "CTFd kanalı devre dışı bırakılabilir."
                )

    return NotificationConfiguration(
        webhook_url=_select_text(webhook_url, "DAYI_DISCORD_WEBHOOK_URL"),
        ctfd_url=_select_text(ctfd_url, "DAYI_CTFD_URL"),
        ctfd_token=_select_text(ctfd_token, "DAYI_CTFD_TOKEN"),
        challenge_id=selected_challenge_id,
        challenge_name=_select_text(
            challenge_name,
            "DAYI_CHALLENGE_NAME",
            _DEFAULT_CHALLENGE_NAME,
        ),
    )


def _normalize_notification_url(value: str, channel: Channel) -> tuple[str, str | None]:
    """Validate and normalize one endpoint without network access."""
    candidate = value.strip()
    if not candidate:
        return "", None
    if any(character.isspace() or ord(character) < 32 for character in candidate):
        return "", "whitespace or control characters are not allowed"

    try:
        parsed = urllib.parse.urlsplit(candidate)
        hostname = parsed.hostname
        _ = parsed.port
    except ValueError:
        return "", "the URL is malformed"

    allowed_schemes = {"http", "https"} if channel == "ctfd" else {"https"}
    if parsed.scheme.lower() not in allowed_schemes:
        return "", "the URL scheme is not allowed"
    if not hostname:
        return "", "a hostname is required"
    if parsed.username is not None or parsed.password is not None:
        return "", "userinfo is not allowed"
    if parsed.query or "?" in candidate:
        return "", "query strings are not allowed"
    if parsed.fragment or "#" in candidate:
        return "", "fragments are not allowed"

    path = parsed.path
    if channel == "ctfd":
        path = path.rstrip("/")
        if path.endswith(_CTFD_ATTEMPT_PATH):
            return "", "the CTFd base URL must not include the submission endpoint"

    normalized = urllib.parse.urlunsplit(
        (parsed.scheme.lower(), parsed.netloc, path, "", "")
    )
    return normalized, None


def _resolve_aiohttp() -> object | None:
    """Return a usable optional aiohttp module, or select stdlib fallback."""
    try:
        module = importlib.import_module("aiohttp")
        if not callable(getattr(module, "ClientSession", None)):
            raise AttributeError("ClientSession is unavailable")
        if not callable(getattr(module, "ClientTimeout", None)):
            raise AttributeError("ClientTimeout is unavailable")
        return module
    except Exception:
        logger.debug("[integrations] aiohttp kullanılamıyor; urllib seçildi.")
        return None


def detect_notification_transport() -> Literal["aiohttp", "urllib"]:
    """Return the runtime-preferred usable native transport label."""
    return "aiohttp" if _resolve_aiohttp() is not None else "urllib"


def inspect_native_notification_configuration(
    environment: Mapping[str, str] | None = None,
) -> NativeNotificationDiagnostic:
    """Inspect notification environment configuration without exposing values."""
    active_environment = os.environ if environment is None else environment

    def selected(name: str) -> str | None:
        value = active_environment.get(name)
        if value is None or not value.strip():
            return None
        return value.strip()

    ctfd_url = selected("DAYI_CTFD_URL")
    ctfd_token = selected("DAYI_CTFD_TOKEN")
    raw_challenge_id = selected("DAYI_CTFD_CHALLENGE_ID")
    ctfd_values_present = any((ctfd_url, ctfd_token, raw_challenge_id))
    if not ctfd_values_present:
        ctfd_status: ConfigurationState = "not-configured"
    else:
        normalized_ctfd_url, ctfd_url_error = _normalize_notification_url(
            ctfd_url or "", "ctfd"
        )
        try:
            parsed_challenge_id = (
                int(raw_challenge_id) if raw_challenge_id is not None else None
            )
        except ValueError:
            parsed_challenge_id = -1
        if ctfd_url_error is not None or (
            parsed_challenge_id is not None and parsed_challenge_id <= 0
        ):
            ctfd_status = "invalid"
        elif not (
            normalized_ctfd_url
            and ctfd_token
            and parsed_challenge_id is not None
        ):
            ctfd_status = "incomplete"
        else:
            ctfd_status = "configured"

    webhook_url = selected("DAYI_DISCORD_WEBHOOK_URL")
    if webhook_url is None:
        discord_status: ConfigurationState = "not-configured"
    else:
        normalized_webhook, webhook_error = _normalize_notification_url(
            webhook_url, "discord"
        )
        discord_status = (
            "configured"
            if normalized_webhook and webhook_error is None
            else "invalid"
        )

    return NativeNotificationDiagnostic(
        transport=detect_notification_transport(),
        ctfd_status=ctfd_status,
        discord_status=discord_status,
    )


# ---------------------------------------------------------------------------
# Native HTTP helpers
# ---------------------------------------------------------------------------


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Reject redirects without changing urllib's process-global opener."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        del req, fp, code, msg, headers, newurl
        return None


def _urllib_post_json(
    url: str,
    payload: dict,
    extra_headers: dict | None = None,
    read_response_body: bool = False,
) -> _HttpResponse:
    """
    Blocking HTTP POST with a JSON body via stdlib urllib.

    Intended to run in a killable isolated process. Network errors propagate
    to the async boundary for safe categorization.

    Args:
        url:           Target URL.
        payload:       Dictionary to serialize as the JSON body.
        extra_headers: Optional additional HTTP headers.

    Returns bounded response metadata. The body is read only for CTFd.
    """
    body = json.dumps(payload).encode("utf-8")
    req  = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", "application/json")
    if extra_headers:
        for key, val in extra_headers.items():
            req.add_header(key, val)
    opener = urllib.request.build_opener(_NoRedirectHandler())
    try:
        with opener.open(req, timeout=URLLIB_REQUEST_TIMEOUT) as resp:  # noqa: S310
            response_body = None
            oversized = False
            if read_response_body:
                response_body = resp.read(CTFD_RESPONSE_LIMIT + 1)
                oversized = len(response_body) > CTFD_RESPONSE_LIMIT
            return _HttpResponse(resp.status, response_body, oversized)
    except urllib.error.HTTPError as exc:
        return _HttpResponse(exc.code, None, False)


async def _run_urllib_post_isolated(
    url: str,
    payload: dict,
    extra_headers: dict | None,
    read_response_body: bool,
    *,
    timeout: float = NOTIFICATION_TOTAL_TIMEOUT,
    worker: Callable[..., _HttpResponse] | None = None,
) -> _HttpResponse:
    """Run one urllib request under a genuine killable total deadline."""
    selected_worker = _urllib_post_json if worker is None else worker
    return await async_run_isolated(
        selected_worker,
        url,
        payload,
        extra_headers,
        read_response_body,
        timeout=max(0.01, timeout),
        max_response_bytes=URLLIB_WORKER_RESPONSE_LIMIT,
    )


async def _read_aiohttp_body_bounded(response) -> tuple[bytes | None, bool]:
    """Read no more than the configured CTFd response limit plus one byte."""
    chunks: list[bytes] = []
    remaining = CTFD_RESPONSE_LIMIT + 1
    while remaining > 0:
        chunk = await response.content.read(min(8192, remaining))
        if not chunk:
            break
        if not isinstance(chunk, bytes):
            return None, False
        chunks.append(chunk)
        remaining -= len(chunk)
    body = b"".join(chunks)
    return body, len(body) > CTFD_RESPONSE_LIMIT


def _ctfd_delivery_result(
    status_code: int,
    body: bytes | None,
    body_oversized: bool,
) -> DeliveryResult:
    """Apply identical bounded CTFd response semantics to both transports."""
    if not 200 <= status_code < 300:
        return DeliveryResult("ctfd", True, False, status_code, "rejected")
    if body is None or body_oversized:
        return DeliveryResult("ctfd", True, False, status_code, "invalid-response")
    try:
        payload = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return DeliveryResult("ctfd", True, False, status_code, "invalid-response")
    if not isinstance(payload, dict):
        return DeliveryResult("ctfd", True, False, status_code, "invalid-response")
    data = payload.get("data")
    if not isinstance(data, dict) or not isinstance(data.get("status"), str):
        return DeliveryResult("ctfd", True, False, status_code, "invalid-response")
    if data["status"] != "correct":
        return DeliveryResult("ctfd", True, False, status_code, "rejected")
    return DeliveryResult("ctfd", True, True, status_code, None)


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
        normalized_ctfd_url, ctfd_url_error = _normalize_notification_url(
            ctfd_url, "ctfd"
        )
        normalized_webhook_url, webhook_url_error = _normalize_notification_url(
            webhook_url, "discord"
        )
        self.webhook_url = normalized_webhook_url
        self.ctfd_url = normalized_ctfd_url
        self.ctfd_token = ctfd_token.strip()
        self.challenge_id = challenge_id
        self.challenge_name = challenge_name or _DEFAULT_CHALLENGE_NAME
        self._aiohttp = _resolve_aiohttp()
        self._transport = "aiohttp" if self._aiohttp is not None else "urllib"

        # In-flight asyncio.Task objects — needed for drain()
        self._tasks: set[asyncio.Task] = set()

        # Duplicate submission guard — flags already dispatched this scan
        self._sent_flags: set[str] = set()
        self._delivery_results: list[DeliveryResult] = []

        ctfd_requested = bool(ctfd_url or ctfd_token or challenge_id)
        if ctfd_url_error is not None:
            logger.warning(
                f"[integrations] CTFd URL geçersiz ({ctfd_url_error}); "
                "CTFd kanalı devre dışı."
            )
        if ctfd_requested and not self._ctfd_configured():
            logger.warning(
                "[integrations] CTFd yapılandırması eksik veya geçersiz; "
                "CTFd kanalı devre dışı."
            )
        if webhook_url_error is not None:
            logger.warning(
                f"[integrations] Discord webhook URL geçersiz ({webhook_url_error}); "
                "Discord kanalı devre dışı."
            )

        self._log_active_backend()

    def _log_active_backend(self) -> None:
        """Log which notification backend is active at startup."""
        if self._configured_channels():
            logger.info(
                f"[integrations] Entegrasyon aktif, transport: {self.transport}. "
                f"Flag bulunca müjdeyi hemen vereceğim yeğenim!"
            )
        else:
            logger.debug("[integrations] CTFd URL veya webhook yapılandırılmamış — pasif mod.")

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    @property
    def delivery_results(self) -> tuple[DeliveryResult, ...]:
        """Return immutable, secret-free delivery outcomes collected so far."""
        return tuple(self._delivery_results)

    @property
    def transport(self) -> str:
        """Return the safe, fixed native transport label."""
        return self._transport

    @property
    def configured_channels(self) -> tuple[Channel, ...]:
        """Return configured channel labels without endpoint details."""
        return self._configured_channels()

    def _ctfd_configured(self) -> bool:
        return bool(self.ctfd_url and self.ctfd_token and self.challenge_id > 0)

    def _configured_channels(self) -> tuple[Channel, ...]:
        channels: list[Channel] = []
        if self._ctfd_configured():
            channels.append("ctfd")
        if self.webhook_url:
            channels.append("discord")
        return tuple(channels)

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
        channels = self._configured_channels()
        if not channels:
            return
        if flag in self._sent_flags:
            logger.debug("[integrations] Çift bildirim gönderimi engellendi.")
            return

        self._sent_flags.add(flag)

        logger.log(
            25,
            f"[integrations] 🚨 Müjde! {tool_name} bir flag buldu. "
            "Yapılandırılmış servislere yolluyorum, dayın hallediyor..."
        )

        dispatch = self._dispatch(flag, tool_name)
        try:
            task = asyncio.create_task(dispatch)
        except Exception:
            dispatch.close()
            self._delivery_results.extend(
                DeliveryResult(channel, False, False, None, "internal")
                for channel in channels
            )
            logger.warning(
                "[integrations] Bildirim görevi başlatılamadı: internal"
            )
            return
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
    # Independent channel dispatch
    # -------------------------------------------------------------------------

    async def _dispatch(self, flag: str, tool_name: str) -> tuple[DeliveryResult, ...]:
        """Deliver configured channels independently with the fixed transport."""
        del tool_name
        deliveries = []
        if self._ctfd_configured():
            deliveries.append(self._deliver("ctfd", flag))
        if self.webhook_url:
            deliveries.append(self._deliver("discord", flag))
        if not deliveries:
            return ()

        results = tuple(await asyncio.gather(*deliveries))
        self._delivery_results.extend(results)
        for result in results:
            self._log_delivery_result(result)
        return results

    async def _deliver(self, channel: Channel, flag: str) -> DeliveryResult:
        """Attempt one channel and convert ordinary failures to safe results."""
        try:
            if self._transport == "aiohttp":
                if channel == "ctfd":
                    return await self._send_ctfd_aiohttp(flag)
                return await self._send_discord_aiohttp(flag)
            if channel == "ctfd":
                return await self._send_ctfd_urllib(flag)
            return await self._send_discord_urllib(flag)
        except (asyncio.TimeoutError, TimeoutError):
            return DeliveryResult(channel, True, False, None, "timeout")
        except urllib.error.URLError as exc:
            category: ErrorCategory = (
                "timeout" if isinstance(exc.reason, TimeoutError) else "network"
            )
            return DeliveryResult(channel, True, False, None, category)
        except OSError:
            return DeliveryResult(channel, True, False, None, "network")
        except Exception as exc:
            client_error = (
                getattr(self._aiohttp, "ClientError", None)
                if self._aiohttp is not None
                else None
            )
            if isinstance(client_error, type) and isinstance(exc, client_error):
                return DeliveryResult(channel, True, False, None, "network")
            return DeliveryResult(channel, True, False, None, "internal")

    @staticmethod
    def _log_delivery_result(result: DeliveryResult) -> None:
        label = "CTFd" if result.channel == "ctfd" else "Discord"
        if result.success:
            logger.info(f"[integrations] {label} bildirimi gönderildi.")
        elif result.error_category == "rejected" and result.status_code is not None:
            logger.warning(
                f"[integrations] {label} bildirimi HTTP {result.status_code} ile reddedildi."
            )
        else:
            logger.warning(
                f"[integrations] {label} bildirimi başarısız: "
                f"{result.error_category or 'internal'}"
            )

    def _ctfd_payload(self, flag: str) -> dict[str, object]:
        return {"challenge_id": self.challenge_id, "submission": flag}

    def _discord_payload(self, flag: str) -> dict[str, object]:
        embed = {
            "title": "🚩 Dayı Flag Buldu!",
            "color": 0xFEE75C,
            "fields": [
                {
                    "name": "Challenge",
                    "value": f"`{self.challenge_name}`",
                    "inline": True,
                },
                {
                    "name": "Flag",
                    "value": f"||`{flag}`||",
                    "inline": False,
                },
            ],
            "footer": {
                "text": f"Dayı Stego Solver v{__version__} — Hallederiz yeğenim!"
            },
        }
        return {"embeds": [embed]}

    async def _send_ctfd_aiohttp(self, flag: str) -> DeliveryResult:
        if self._aiohttp is None:
            raise RuntimeError("aiohttp transport unavailable")
        timeout = self._aiohttp.ClientTimeout(
            total=NOTIFICATION_TOTAL_TIMEOUT,
            connect=NOTIFICATION_CONNECT_TIMEOUT,
            sock_read=NOTIFICATION_READ_TIMEOUT,
        )
        headers = {
            "Authorization": f"Token {self.ctfd_token}",
            "Content-Type": "application/json",
        }
        url = f"{self.ctfd_url}/api/v1/challenges/attempt"
        async with self._aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(
                url,
                json=self._ctfd_payload(flag),
                headers=headers,
                allow_redirects=False,
            ) as response:
                status_code = response.status
                if not 200 <= status_code < 300:
                    return DeliveryResult("ctfd", True, False, status_code, "rejected")
                body, oversized = await _read_aiohttp_body_bounded(response)
                return _ctfd_delivery_result(status_code, body, oversized)

    async def _send_discord_aiohttp(self, flag: str) -> DeliveryResult:
        if self._aiohttp is None:
            raise RuntimeError("aiohttp transport unavailable")
        timeout = self._aiohttp.ClientTimeout(
            total=NOTIFICATION_TOTAL_TIMEOUT,
            connect=NOTIFICATION_CONNECT_TIMEOUT,
            sock_read=NOTIFICATION_READ_TIMEOUT,
        )
        async with self._aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(
                self.webhook_url,
                json=self._discord_payload(flag),
                allow_redirects=False,
            ) as response:
                if response.status == 204:
                    return DeliveryResult("discord", True, True, 204, None)
                return DeliveryResult(
                    "discord", True, False, response.status, "rejected"
                )

    async def _send_ctfd_urllib(self, flag: str) -> DeliveryResult:
        headers = {"Authorization": f"Token {self.ctfd_token}"}
        url = f"{self.ctfd_url}/api/v1/challenges/attempt"
        response = await _run_urllib_post_isolated(
            url,
            self._ctfd_payload(flag),
            headers,
            True,
            timeout=NOTIFICATION_TOTAL_TIMEOUT,
        )
        return _ctfd_delivery_result(
            response.status_code,
            response.body,
            response.body_oversized,
        )

    async def _send_discord_urllib(self, flag: str) -> DeliveryResult:
        response = await _run_urllib_post_isolated(
            self.webhook_url,
            self._discord_payload(flag),
            None,
            False,
            timeout=NOTIFICATION_TOTAL_TIMEOUT,
        )
        if response.status_code == 204:
            return DeliveryResult("discord", True, True, 204, None)
        return DeliveryResult(
            "discord", True, False, response.status_code, "rejected"
        )


# ---------------------------------------------------------------------------
# Factory — used by cli.py to construct the integration from parsed args.
# ---------------------------------------------------------------------------

def build_integration(
    webhook_url: str | None = None,
    ctfd_url: str | None = None,
    ctfd_token: str | None = None,
    challenge_id: int | None = None,
    challenge_name: str | None = None,
) -> Optional["IntegrationManager"]:
    """
    Select CLI/environment values and construct a manager for valid channels.

    Returns None when neither CTFd nor Discord is completely and validly
    configured, keeping the default behavior identical to v1.x.

    Args:
        webhook_url:    Discord incoming webhook URL.
        ctfd_url:       CTFd platform base URL.
        ctfd_token:     CTFd API token.
        challenge_id:   CTFd challenge ID (0 = no submission).
        challenge_name: Human-readable challenge name (Discord embed label).

    Returns:
        Configured IntegrationManager instance, or None.
    """
    configuration = select_notification_configuration(
        webhook_url=webhook_url,
        ctfd_url=ctfd_url,
        ctfd_token=ctfd_token,
        challenge_id=challenge_id,
        challenge_name=challenge_name,
    )
    if not (
        configuration.webhook_url
        or configuration.ctfd_url
        or configuration.ctfd_token
        or configuration.challenge_id
    ):
        return None

    manager = IntegrationManager(
        webhook_url=configuration.webhook_url,
        ctfd_url=configuration.ctfd_url,
        ctfd_token=configuration.ctfd_token,
        challenge_id=configuration.challenge_id,
        challenge_name=configuration.challenge_name,
    )
    if not manager.configured_channels:
        return None
    return manager
