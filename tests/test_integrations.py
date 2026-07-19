import asyncio
import json
import os
import re
import tempfile
import unittest
import urllib.error
from dataclasses import asdict, fields
from pathlib import Path
from unittest.mock import AsyncMock, Mock, patch

from dayi import cli
from dayi.integrations import (
    CTFD_RESPONSE_LIMIT,
    NOTIFICATION_CONNECT_TIMEOUT,
    NOTIFICATION_READ_TIMEOUT,
    NOTIFICATION_TOTAL_TIMEOUT,
    URLLIB_REQUEST_TIMEOUT,
    DeliveryResult,
    IntegrationManager,
    _HttpResponse,
    _NoRedirectHandler,
    _normalize_notification_url,
    _urllib_post_json,
    build_integration,
    select_notification_configuration,
)
from dayi.reporter import ScanReport, ToolResult, write_json_report
from dayi.runner import DayiRunner


class _ResponseContext:
    def __init__(self, response):
        self.response = response

    async def __aenter__(self):
        return self.response

    async def __aexit__(self, exc_type, exc, traceback):
        return False


class _FakeContent:
    def __init__(self, body: bytes, read_error: Exception | None = None):
        self.body = body
        self.read_error = read_error
        self.offset = 0
        self.read_sizes: list[int] = []

    async def read(self, size: int) -> bytes:
        self.read_sizes.append(size)
        if self.read_error is not None:
            raise self.read_error
        chunk = self.body[self.offset:self.offset + size]
        self.offset += len(chunk)
        return chunk


class _FakeResponse:
    def __init__(
        self,
        status: int,
        payload=None,
        *,
        raw_body: bytes | None = None,
        read_error: Exception | None = None,
    ):
        self.status = status
        self.payload = payload
        if raw_body is None:
            raw_body = b"" if payload is None else json.dumps(payload).encode("utf-8")
        self.content = _FakeContent(raw_body, read_error)

    async def json(self, *, content_type=None):
        del content_type
        raise AssertionError("CTFd JSON must be parsed from a bounded body")

    async def text(self):
        raise AssertionError("raw response bodies must not be read")


class _FakeSession:
    def __init__(self, backend):
        self.backend = backend

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, traceback):
        return False

    def post(self, url, **kwargs):
        self.backend.calls.append((url, kwargs))
        response = self.backend.response_for(url)
        if isinstance(response, BaseException):
            raise response
        return _ResponseContext(response)


class _FakeAiohttp:
    def __init__(self, ctfd_response=None, discord_response=None):
        self.ctfd_response = ctfd_response or _FakeResponse(
            200, {"data": {"status": "correct"}}
        )
        self.discord_response = discord_response or _FakeResponse(204)
        self.calls: list[tuple[str, dict]] = []
        self.timeouts: list[dict[str, float]] = []

    def ClientTimeout(self, *, total, connect, sock_read):
        values = {"total": total, "connect": connect, "sock_read": sock_read}
        self.timeouts.append(values)
        return values

    def ClientSession(self, *, timeout):
        self.session_timeout = timeout
        return _FakeSession(self)

    def response_for(self, url: str):
        if url.endswith("/api/v1/challenges/attempt"):
            return self.ctfd_response
        return self.discord_response


def _manager(*, aiohttp=None, **kwargs) -> IntegrationManager:
    with patch("dayi.integrations._resolve_aiohttp", return_value=aiohttp):
        return IntegrationManager(**kwargs)


class TransportSelectionTests(unittest.TestCase):
    def test_aiohttp_is_selected_when_usable(self) -> None:
        backend = _FakeAiohttp()
        manager = _manager(aiohttp=backend, webhook_url="https://discord.invalid/hook")

        self.assertEqual(manager.transport, "aiohttp")
        self.assertIs(manager._aiohttp, backend)

    def test_urllib_is_selected_when_aiohttp_is_unavailable(self) -> None:
        for error in (ImportError("missing"), RuntimeError("broken import")):
            with self.subTest(error=type(error).__name__), patch(
                "dayi.integrations.importlib.import_module",
                side_effect=error,
            ) as importer:
                manager = IntegrationManager(
                    webhook_url="https://discord.invalid/hook"
                )

            self.assertEqual(manager.transport, "urllib")
            importer.assert_called_once_with("aiohttp")

    def test_ctfshit_notification_modules_are_never_imported(self) -> None:
        backend = _FakeAiohttp()
        imported: list[str] = []

        def load(name: str):
            imported.append(name)
            if name != "aiohttp":
                raise AssertionError(f"unexpected import: {name}")
            return backend

        with patch("dayi.integrations.importlib.import_module", side_effect=load):
            manager = IntegrationManager(webhook_url="https://discord.invalid/hook")

        self.assertEqual(manager.transport, "aiohttp")
        self.assertEqual(imported, ["aiohttp"])


class ChannelDispatchTests(unittest.IsolatedAsyncioTestCase):
    async def test_ctfd_only_dispatches_ctfd(self) -> None:
        manager = _manager(
            aiohttp=_FakeAiohttp(),
            ctfd_url="https://ctfd.invalid",
            ctfd_token="token",
            challenge_id=7,
        )
        manager._deliver = AsyncMock(
            return_value=DeliveryResult("ctfd", True, True, 200, None)
        )

        results = await manager._dispatch("FLAG{one}", "tool")

        manager._deliver.assert_awaited_once_with("ctfd", "FLAG{one}")
        self.assertEqual(results[0].channel, "ctfd")

    async def test_discord_only_dispatches_discord(self) -> None:
        manager = _manager(
            aiohttp=_FakeAiohttp(), webhook_url="https://discord.invalid/hook"
        )
        manager._deliver = AsyncMock(
            return_value=DeliveryResult("discord", True, True, 204, None)
        )

        results = await manager._dispatch("FLAG{one}", "tool")

        manager._deliver.assert_awaited_once_with("discord", "FLAG{one}")
        self.assertEqual(results[0].channel, "discord")

    async def test_both_channels_are_independent_and_not_retried(self) -> None:
        manager = _manager(
            aiohttp=_FakeAiohttp(),
            ctfd_url="https://ctfd.invalid",
            ctfd_token="token",
            challenge_id=7,
            webhook_url="https://discord.invalid/hook",
        )
        manager._send_ctfd_aiohttp = AsyncMock(
            return_value=DeliveryResult("ctfd", True, True, 200, None)
        )
        manager._send_discord_aiohttp = AsyncMock(
            side_effect=RuntimeError("discord failed")
        )
        with patch("dayi.integrations._urllib_post_json") as urllib_post:
            results = await manager._dispatch("FLAG{one}", "tool")

        self.assertEqual(
            results,
            (
                DeliveryResult("ctfd", True, True, 200, None),
                DeliveryResult("discord", True, False, None, "internal"),
            ),
        )
        manager._send_ctfd_aiohttp.assert_awaited_once()
        manager._send_discord_aiohttp.assert_awaited_once()
        urllib_post.assert_not_called()
        self.assertEqual(manager.transport, "aiohttp")
        with self.assertRaises(AttributeError):
            manager.transport = "urllib"

    async def test_discord_success_survives_ctfd_failure(self) -> None:
        manager = _manager(
            aiohttp=_FakeAiohttp(),
            ctfd_url="https://ctfd.invalid",
            ctfd_token="token",
            challenge_id=7,
            webhook_url="https://discord.invalid/hook",
        )
        manager._send_ctfd_aiohttp = AsyncMock(side_effect=OSError("network"))
        manager._send_discord_aiohttp = AsyncMock(
            return_value=DeliveryResult("discord", True, True, 204, None)
        )

        results = await manager._dispatch("FLAG{one}", "tool")

        self.assertEqual(results[0].error_category, "network")
        self.assertTrue(results[1].success)
        manager._send_discord_aiohttp.assert_awaited_once()

    async def test_both_fail_without_cross_transport_retry(self) -> None:
        manager = _manager(
            aiohttp=_FakeAiohttp(),
            ctfd_url="https://ctfd.invalid",
            ctfd_token="token",
            challenge_id=7,
            webhook_url="https://discord.invalid/hook",
        )
        manager._send_ctfd_aiohttp = AsyncMock(side_effect=TimeoutError())
        manager._send_discord_aiohttp = AsyncMock(
            side_effect=RuntimeError("failed")
        )
        with patch("dayi.integrations._urllib_post_json") as urllib_post:
            results = await manager._dispatch("FLAG{one}", "tool")

        self.assertEqual(results[0].error_category, "timeout")
        self.assertEqual(results[1].error_category, "internal")
        urllib_post.assert_not_called()

    async def test_incomplete_ctfd_and_no_configuration_schedule_nothing(self) -> None:
        for kwargs in (
            {},
            {"ctfd_url": "https://ctfd.invalid"},
            {"ctfd_url": "https://ctfd.invalid", "ctfd_token": "token"},
        ):
            with self.subTest(kwargs=kwargs):
                manager = _manager(aiohttp=_FakeAiohttp(), **kwargs)
                with patch("dayi.integrations.asyncio.create_task") as create_task:
                    manager.notify("FLAG{one}", "tool")
                create_task.assert_not_called()
                self.assertEqual(manager.delivery_results, ())

    async def test_duplicate_flag_schedules_once(self) -> None:
        manager = _manager(
            aiohttp=_FakeAiohttp(), webhook_url="https://discord.invalid/hook"
        )
        manager._dispatch = AsyncMock(return_value=())

        manager.notify("FLAG{duplicate}", "first")
        manager.notify("FLAG{duplicate}", "second")
        await manager.drain()

        manager._dispatch.assert_awaited_once_with("FLAG{duplicate}", "first")


class NativeDeliveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_aiohttp_payloads_and_success_results(self) -> None:
        backend = _FakeAiohttp()
        manager = _manager(
            aiohttp=backend,
            ctfd_url="https://ctfd.invalid",
            ctfd_token="secret-token",
            challenge_id=42,
            webhook_url="https://discord.invalid/hook",
            challenge_name="Challenge",
        )

        results = await manager._dispatch("FLAG{payload}", "tool")

        self.assertEqual(
            results,
            (
                DeliveryResult("ctfd", True, True, 200, None),
                DeliveryResult("discord", True, True, 204, None),
            ),
        )
        ctfd_call, discord_call = backend.calls
        self.assertEqual(ctfd_call[1]["json"]["submission"], "FLAG{payload}")
        self.assertEqual(ctfd_call[1]["json"]["challenge_id"], 42)
        self.assertEqual(
            ctfd_call[1]["headers"]["Authorization"], "Token secret-token"
        )
        self.assertIn("FLAG{payload}", json.dumps(discord_call[1]["json"]))
        self.assertEqual(
            backend.timeouts,
            [
                {
                    "total": NOTIFICATION_TOTAL_TIMEOUT,
                    "connect": NOTIFICATION_CONNECT_TIMEOUT,
                    "sock_read": NOTIFICATION_READ_TIMEOUT,
                },
                {
                    "total": NOTIFICATION_TOTAL_TIMEOUT,
                    "connect": NOTIFICATION_CONNECT_TIMEOUT,
                    "sock_read": NOTIFICATION_READ_TIMEOUT,
                },
            ],
        )
        self.assertFalse(ctfd_call[1]["allow_redirects"])
        self.assertFalse(discord_call[1]["allow_redirects"])

    async def test_rejected_and_malformed_responses_are_safe_results(self) -> None:
        cases = (
            (_FakeResponse(403), "rejected", 403),
            (_FakeResponse(200, raw_body=b"not-json"), "invalid-response", 200),
            (_FakeResponse(200, ["wrong shape"]), "invalid-response", 200),
            (_FakeResponse(200, {"data": {"status": "incorrect"}}), "rejected", 200),
        )
        for response, category, status_code in cases:
            with self.subTest(category=category, response=response.payload):
                manager = _manager(
                    aiohttp=_FakeAiohttp(ctfd_response=response),
                    ctfd_url="https://ctfd.invalid",
                    ctfd_token="token",
                    challenge_id=1,
                )
                result = await manager._deliver("ctfd", "FLAG{one}")
                self.assertEqual(result.error_category, category)
                self.assertEqual(result.status_code, status_code)

    async def test_timeout_network_and_internal_exceptions_are_categorized(self) -> None:
        cases = (
            (TimeoutError("secret"), "timeout"),
            (urllib.error.URLError("secret URL"), "network"),
            (OSError("secret URL"), "network"),
            (RuntimeError("secret URL"), "internal"),
        )
        for error, category in cases:
            with self.subTest(category=category):
                manager = _manager(
                    aiohttp=_FakeAiohttp(), webhook_url="https://discord.invalid/hook"
                )
                manager._send_discord_aiohttp = AsyncMock(side_effect=error)
                result = await manager._deliver("discord", "FLAG{one}")
                self.assertEqual(result.error_category, category)

    async def test_urllib_fallback_is_fixed_and_channel_specific(self) -> None:
        manager = _manager(
            aiohttp=None,
            ctfd_url="https://ctfd.invalid",
            ctfd_token="token",
            challenge_id=1,
            webhook_url="https://discord.invalid/hook",
        )
        with patch(
            "dayi.integrations._urllib_post_json",
            side_effect=[
                _HttpResponse(
                    201,
                    json.dumps({"data": {"status": "correct"}}).encode("utf-8"),
                    False,
                ),
                _HttpResponse(400, None, False),
            ],
        ) as post:
            results = await manager._dispatch("FLAG{one}", "tool")

        self.assertEqual(manager.transport, "urllib")
        self.assertTrue(results[0].success)
        self.assertEqual(results[1].error_category, "rejected")
        self.assertEqual(post.call_count, 2)


class FailureAndSafetyTests(unittest.IsolatedAsyncioTestCase):
    async def test_scheduling_failure_is_contained_and_recorded(self) -> None:
        manager = _manager(
            aiohttp=_FakeAiohttp(),
            ctfd_url="https://ctfd.invalid/ctfd-secret-path",
            ctfd_token="ctfd-secret",
            challenge_id=1,
            webhook_url="https://discord.invalid/api/webhooks/webhook-secret",
        )
        with self.assertLogs("dayi", level="WARNING") as captured, patch(
            "dayi.integrations.asyncio.create_task",
            side_effect=RuntimeError("webhook-secret query-secret"),
        ):
            manager.notify("FLAG{secret-flag}", "tool")

        rendered = "\n".join(captured.output)
        self.assertEqual(len(manager.delivery_results), 2)
        self.assertTrue(all(not result.attempted for result in manager.delivery_results))
        for secret in (
            "ctfd-secret", "webhook-secret", "query-secret", "password",
            "FLAG{secret-flag}",
        ):
            self.assertNotIn(secret, rendered)

    async def test_delivery_logs_exclude_secrets_bodies_and_exception_text(self) -> None:
        manager = _manager(
            aiohttp=_FakeAiohttp(),
            ctfd_url="https://ctfd.invalid/ctfd-secret-path",
            ctfd_token="ctfd-secret",
            challenge_id=1,
            webhook_url="https://discord.invalid/api/webhooks/webhook-secret",
        )
        manager._send_ctfd_aiohttp = AsyncMock(
            side_effect=RuntimeError("raw exception webhook-secret")
        )
        manager._send_discord_aiohttp = AsyncMock(
            return_value=DeliveryResult("discord", True, False, 400, "rejected")
        )
        with self.assertLogs("dayi", level="WARNING") as captured:
            await manager._dispatch("FLAG{secret-flag}", "tool")

        rendered = "\n".join(captured.output)
        for secret in (
            "ctfd-secret", "webhook-secret", "query-secret", "password",
            "raw exception", "FLAG{secret-flag}",
        ):
            self.assertNotIn(secret, rendered)
        self.assertNotIn("response body", rendered)

    async def test_runner_contains_ordinary_notify_failure(self) -> None:
        integration = Mock()
        integration.notify.side_effect = RuntimeError("secret URL")
        runner = DayiRunner(Path("target.bin"), re.compile("FLAG"), integration=integration)
        result = ToolResult(
            tool_name="test",
            command=[],
            return_code=0,
            stdout="",
            stderr="",
            flags_found=["FLAG{one}"],
            elapsed_seconds=0.0,
        )

        completed = await runner._wrap_notify(asyncio.sleep(0, result=result), "test")

        self.assertIs(completed, result)
        self.assertFalse(completed.error)

    async def test_keyboard_interrupt_and_system_exit_propagate(self) -> None:
        for error in (KeyboardInterrupt(), SystemExit(2)):
            with self.subTest(error=type(error).__name__):
                manager = _manager(
                    aiohttp=_FakeAiohttp(), webhook_url="https://discord.invalid/hook"
                )
                manager._send_discord_aiohttp = AsyncMock(side_effect=error)
                with self.assertRaises(type(error)):
                    await manager._deliver("discord", "FLAG{one}")

                integration = Mock()
                integration.notify.side_effect = error
                runner = DayiRunner(
                    Path("target.bin"), re.compile("FLAG"), integration=integration
                )
                with self.assertRaises(type(error)):
                    runner._notify_safely("FLAG{one}", "tool")

    def test_delivery_result_contract_contains_only_safe_fields(self) -> None:
        result = DeliveryResult("ctfd", True, False, 400, "rejected")

        self.assertEqual(
            [field.name for field in fields(result)],
            ["channel", "attempted", "success", "status_code", "error_category"],
        )
        self.assertEqual(
            asdict(result),
            {
                "channel": "ctfd",
                "attempted": True,
                "success": False,
                "status_code": 400,
                "error_category": "rejected",
            },
        )

    def test_report_json_schema_does_not_include_delivery_results(self) -> None:
        report = ScanReport(
            target_file="target.bin",
            flag_pattern="FLAG",
            wordlist=None,
            started_at="start",
            finished_at="finish",
            all_flags=[],
            tool_results=[],
        )
        with tempfile.TemporaryDirectory() as tmpdir:
            output = Path(tmpdir) / "report.json"
            write_json_report(report, output)
            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertNotIn("delivery_results", payload)
        self.assertNotIn("notifications", payload)

    def test_factory_contract_remains_compatible(self) -> None:
        with patch.dict(os.environ, {}, clear=True):
            self.assertIsNone(build_integration())
            with patch("dayi.integrations._resolve_aiohttp", return_value=None):
                manager = build_integration(webhook_url="https://discord.invalid/hook")
        self.assertIsInstance(manager, IntegrationManager)
        self.assertEqual(manager.transport, "urllib")

    async def test_cli_scan_exit_and_builder_contract_survive_notify_failure(self) -> None:
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "target.bin"
            target.write_bytes(b"FLAG{one}")
            secret_url = "https://user:password@ctfd.invalid/path?token=query-secret"
            args = cli.parse_cli_args([
                "scan", str(target), "--ctfd-url", secret_url,
                "--ctfd-token", "ctfd-secret", "--challenge-id", "7",
            ])
            integration = Mock()
            integration.notify.side_effect = RuntimeError("secret URL")
            logger = Mock()

            class FakeRunner:
                def __init__(self, **kwargs):
                    self.kwargs = kwargs

                async def run_all(self):
                    result = ToolResult(
                        tool_name="test",
                        command=[],
                        return_code=0,
                        stdout="",
                        stderr="",
                        flags_found=["FLAG{one}"],
                        elapsed_seconds=0.0,
                    )
                    boundary = DayiRunner(
                        target,
                        re.compile("FLAG"),
                        integration=self.kwargs["integration"],
                    )
                    await boundary._wrap_notify(
                        asyncio.sleep(0, result=result),
                        "test",
                    )
                    return ScanReport(
                        target_file=str(target),
                        flag_pattern="FLAG",
                        wordlist=None,
                        started_at="start",
                        finished_at="finish",
                        all_flags=["FLAG{one}"],
                        tool_results=[result],
                    )

            with patch(
                "dayi.cli.build_integration", return_value=integration
            ) as builder, patch("dayi.cli.DayiRunner", FakeRunner):
                report, exit_code = await cli._run_analysis(args, logger)

        self.assertIsNotNone(report)
        self.assertEqual(exit_code, 0)
        builder.assert_called_once_with(
            webhook_url=None,
            ctfd_url=secret_url,
            ctfd_token="ctfd-secret",
            challenge_id=7,
            challenge_name=None,
        )
        rendered_logs = "\n".join(
            str(call.args[0]) for call in logger.info.call_args_list if call.args
        )
        for secret in ("password", "query-secret", "ctfd-secret"):
            self.assertNotIn(secret, rendered_logs)

    async def test_environment_only_secrets_do_not_enter_logs_or_report(self) -> None:
        environment = {
            "DAYI_CTFD_URL": "https://ctfd.invalid/ctfd-secret-path",
            "DAYI_CTFD_TOKEN": "environment-token-secret",
            "DAYI_CTFD_CHALLENGE_ID": "17",
            "DAYI_DISCORD_WEBHOOK_URL": (
                "https://hooks.invalid/api/webhooks/environment-webhook-secret"
            ),
            "DAYI_CHALLENGE_NAME": "environment-name-secret",
        }
        with tempfile.TemporaryDirectory() as tmpdir:
            target = Path(tmpdir) / "target.bin"
            target.write_bytes(b"no flags")
            args = cli.parse_cli_args(["scan", str(target)])
            captured: dict[str, object] = {}
            logger = Mock()

            class FakeRunner:
                def __init__(self, **kwargs):
                    captured.update(kwargs)

                async def run_all(self):
                    return ScanReport(
                        target_file=str(target),
                        flag_pattern="FLAG",
                        wordlist=None,
                        started_at="start",
                        finished_at="finish",
                        all_flags=[],
                        tool_results=[],
                    )

            with patch.dict(os.environ, environment, clear=True), patch(
                "dayi.integrations._resolve_aiohttp", return_value=None
            ), patch("dayi.cli.DayiRunner", FakeRunner):
                report, exit_code = await cli._run_analysis(args, logger)

            output = Path(tmpdir) / "report.json"
            write_json_report(report, output)
            rendered = "\n".join(
                str(call.args[0])
                for method in (logger.info, logger.warning, logger.error)
                for call in method.call_args_list
                if call.args
            ) + output.read_text(encoding="utf-8")

        self.assertEqual(exit_code, 0)
        self.assertEqual(
            captured["integration"].configured_channels,
            ("ctfd", "discord"),
        )
        for secret in (
            "ctfd-secret-path",
            "environment-token-secret",
            "environment-webhook-secret",
            "environment-name-secret",
        ):
            self.assertNotIn(secret, rendered)


class EnvironmentConfigurationTests(unittest.TestCase):
    def _environment(self) -> dict[str, str]:
        return {
            "DAYI_CTFD_URL": "https://environment-ctfd.invalid",
            "DAYI_CTFD_TOKEN": "environment-token",
            "DAYI_CTFD_CHALLENGE_ID": "41",
            "DAYI_DISCORD_WEBHOOK_URL": "https://environment-discord.invalid/hook",
            "DAYI_CHALLENGE_NAME": "Environment Challenge",
        }

    def test_cli_ctfd_url_overrides_environment(self) -> None:
        with patch.dict(os.environ, self._environment(), clear=True):
            selected = select_notification_configuration(
                ctfd_url="https://cli-ctfd.invalid"
            )
        self.assertEqual(selected.ctfd_url, "https://cli-ctfd.invalid")

    def test_cli_token_overrides_environment(self) -> None:
        with patch.dict(os.environ, self._environment(), clear=True):
            selected = select_notification_configuration(ctfd_token="cli-token")
        self.assertEqual(selected.ctfd_token, "cli-token")

    def test_cli_challenge_id_overrides_environment(self) -> None:
        with patch.dict(os.environ, self._environment(), clear=True):
            selected = select_notification_configuration(challenge_id=73)
        self.assertEqual(selected.challenge_id, 73)

    def test_cli_webhook_overrides_environment(self) -> None:
        with patch.dict(os.environ, self._environment(), clear=True):
            selected = select_notification_configuration(
                webhook_url="https://cli-discord.invalid/hook"
            )
        self.assertEqual(selected.webhook_url, "https://cli-discord.invalid/hook")

    def test_environment_values_are_selected_when_cli_values_are_absent(self) -> None:
        with patch.dict(os.environ, self._environment(), clear=True):
            selected = select_notification_configuration()
        self.assertEqual(
            selected,
            type(selected)(
                webhook_url="https://environment-discord.invalid/hook",
                ctfd_url="https://environment-ctfd.invalid",
                ctfd_token="environment-token",
                challenge_id=41,
                challenge_name="Environment Challenge",
            ),
        )

    def test_whitespace_environment_values_are_ignored(self) -> None:
        environment = {
            "DAYI_CTFD_URL": "  ",
            "DAYI_CTFD_TOKEN": "\t",
            "DAYI_CTFD_CHALLENGE_ID": "\n",
            "DAYI_DISCORD_WEBHOOK_URL": "   ",
            "DAYI_CHALLENGE_NAME": " ",
        }
        with patch.dict(os.environ, environment, clear=True):
            selected = select_notification_configuration()
            manager = build_integration()
        self.assertEqual(selected.webhook_url, "")
        self.assertEqual(selected.ctfd_url, "")
        self.assertEqual(selected.ctfd_token, "")
        self.assertEqual(selected.challenge_id, 0)
        self.assertEqual(selected.challenge_name, "Dayı Auto-Solve")
        self.assertIsNone(manager)

    def test_invalid_environment_challenge_id_disables_only_ctfd(self) -> None:
        environment = self._environment()
        environment["DAYI_CTFD_CHALLENGE_ID"] = "secret-not-an-integer"
        with patch.dict(os.environ, environment, clear=True), patch(
            "dayi.integrations._resolve_aiohttp", return_value=None
        ), self.assertLogs("dayi", level="WARNING") as captured:
            manager = build_integration()

        self.assertIsNotNone(manager)
        self.assertEqual(manager.configured_channels, ("discord",))
        rendered = "\n".join(captured.output)
        self.assertNotIn("secret-not-an-integer", rendered)

    def test_environment_only_configuration_constructs_manager(self) -> None:
        with patch.dict(os.environ, self._environment(), clear=True), patch(
            "dayi.integrations._resolve_aiohttp", return_value=None
        ):
            manager = build_integration()
        self.assertIsNotNone(manager)
        self.assertEqual(manager.configured_channels, ("ctfd", "discord"))

    def test_parser_defaults_preserve_cli_presence_information(self) -> None:
        defaults = cli.parse_cli_args(["scan", "target.bin"])
        explicit = cli.parse_cli_args([
            "scan", "target.bin",
            "--ctfd-url", "https://ctfd.invalid",
            "--ctfd-token", "token",
            "--challenge-id", "7",
            "--webhook", "https://discord.invalid/hook",
            "--challenge-name", "Explicit",
        ])
        for name in (
            "ctfd_url", "ctfd_token", "challenge_id", "webhook", "challenge_name"
        ):
            self.assertIsNone(getattr(defaults, name))
        self.assertEqual(explicit.challenge_id, 7)
        self.assertEqual(explicit.challenge_name, "Explicit")

    def test_missing_cli_notification_value_is_an_argparse_error(self) -> None:
        for option in ("--ctfd-url", "--ctfd-token", "--challenge-id", "--webhook"):
            with self.subTest(option=option), self.assertRaises(SystemExit) as raised:
                cli.parse_cli_args(["scan", "target.bin", option])
            self.assertEqual(raised.exception.code, 2)


class NotificationUrlValidationTests(unittest.TestCase):
    def test_valid_ctfd_http_and_https_urls_are_normalized(self) -> None:
        for value, expected in (
            ("https://ctfd.invalid/", "https://ctfd.invalid"),
            ("http://ctfd.invalid/base///", "http://ctfd.invalid/base"),
        ):
            with self.subTest(value=value):
                self.assertEqual(
                    _normalize_notification_url(value, "ctfd"),
                    (expected, None),
                )

    def test_invalid_ctfd_url_forms_are_rejected(self) -> None:
        cases = (
            "https:///missing-host",
            "ftp://ctfd.invalid",
            "https://user:password@ctfd.invalid",
            "https://ctfd.invalid/path?secret=query",
            "https://ctfd.invalid/path?",
            "https://ctfd.invalid/path#fragment-secret",
            "https://ctfd.invalid/path#",
            "https://ctfd.invalid/api/v1/challenges/attempt",
        )
        for value in cases:
            with self.subTest(value=value):
                normalized, reason = _normalize_notification_url(value, "ctfd")
                self.assertEqual(normalized, "")
                self.assertIsNotNone(reason)

    def test_discord_requires_https_and_rejects_unsafe_url_parts(self) -> None:
        accepted = "https://hooks.invalid/api/webhooks/opaque-secret-path"
        self.assertEqual(
            _normalize_notification_url(accepted, "discord"),
            (accepted, None),
        )
        for value in (
            "http://hooks.invalid/path",
            "https:///missing-host",
            "https://user:password@hooks.invalid/path",
            "https://hooks.invalid/path?secret=query",
            "https://hooks.invalid/path?",
            "https://hooks.invalid/path#fragment-secret",
            "https://hooks.invalid/path#",
        ):
            with self.subTest(value=value):
                normalized, reason = _normalize_notification_url(value, "discord")
                self.assertEqual(normalized, "")
                self.assertIsNotNone(reason)

    def test_invalid_url_diagnostic_never_contains_secret_path(self) -> None:
        secret_path = "opaque-webhook-secret"
        with patch("dayi.integrations._resolve_aiohttp", return_value=None), self.assertLogs(
            "dayi", level="WARNING"
        ) as captured:
            manager = IntegrationManager(
                webhook_url=f"https://hooks.invalid/{secret_path}?not-allowed=yes"
            )
        self.assertEqual(manager.configured_channels, ())
        self.assertNotIn(secret_path, "\n".join(captured.output))


class NetworkHardeningTests(unittest.IsolatedAsyncioTestCase):
    async def test_aiohttp_uses_bounded_timeouts_and_disables_redirects(self) -> None:
        backend = _FakeAiohttp()
        manager = _manager(
            aiohttp=backend,
            ctfd_url="https://ctfd.invalid",
            ctfd_token="token",
            challenge_id=1,
            webhook_url="https://hooks.invalid/path",
        )
        await manager._dispatch("FLAG{one}", "tool")

        expected_timeout = {
            "total": NOTIFICATION_TOTAL_TIMEOUT,
            "connect": NOTIFICATION_CONNECT_TIMEOUT,
            "sock_read": NOTIFICATION_READ_TIMEOUT,
        }
        self.assertEqual(backend.timeouts, [expected_timeout, expected_timeout])
        self.assertTrue(all(not call[1]["allow_redirects"] for call in backend.calls))

    async def test_oversized_ctfd_body_is_invalid_and_bounded(self) -> None:
        response = _FakeResponse(
            200,
            raw_body=b"x" * (CTFD_RESPONSE_LIMIT + 100),
        )
        manager = _manager(
            aiohttp=_FakeAiohttp(ctfd_response=response),
            ctfd_url="https://ctfd.invalid",
            ctfd_token="token",
            challenge_id=1,
        )
        result = await manager._deliver("ctfd", "FLAG{one}")
        self.assertEqual(result.error_category, "invalid-response")
        self.assertLessEqual(sum(response.content.read_sizes), CTFD_RESPONSE_LIMIT + 1)

    async def test_discord_responses_are_never_read(self) -> None:
        for status in (204, 400):
            with self.subTest(status=status):
                response = _FakeResponse(
                    status,
                    raw_body=b"raw-discord-body-secret",
                )
                manager = _manager(
                    aiohttp=_FakeAiohttp(discord_response=response),
                    webhook_url="https://hooks.invalid/opaque-path",
                )
                await manager._deliver("discord", "FLAG{one}")
                self.assertEqual(response.content.read_sizes, [])

    async def test_timeout_category_matches_across_transports(self) -> None:
        aiohttp_manager = _manager(
            aiohttp=_FakeAiohttp(), webhook_url="https://hooks.invalid/path"
        )
        aiohttp_manager._send_discord_aiohttp = AsyncMock(
            side_effect=asyncio.TimeoutError()
        )
        urllib_manager = _manager(
            aiohttp=None, webhook_url="https://hooks.invalid/path"
        )
        with patch(
            "dayi.integrations._urllib_post_json", side_effect=TimeoutError()
        ):
            aiohttp_result = await aiohttp_manager._deliver("discord", "FLAG{one}")
            urllib_result = await urllib_manager._deliver("discord", "FLAG{one}")
        self.assertEqual(aiohttp_result.error_category, "timeout")
        self.assertEqual(urllib_result.error_category, "timeout")

    async def test_aiohttp_redirect_is_rejected_without_transport_retry(self) -> None:
        response = _FakeResponse(302, raw_body=b"redirect-body-secret")
        response.headers = {"Location": "https://redirect.invalid/location-secret"}
        manager = _manager(
            aiohttp=_FakeAiohttp(ctfd_response=response),
            ctfd_url="https://ctfd.invalid",
            ctfd_token="token",
            challenge_id=1,
        )
        with patch("dayi.integrations._urllib_post_json") as urllib_post, self.assertLogs(
            "dayi", level="WARNING"
        ) as captured:
            results = await manager._dispatch("FLAG{one}", "tool")
        self.assertEqual(results[0].error_category, "rejected")
        self.assertEqual(results[0].status_code, 302)
        self.assertEqual(response.content.read_sizes, [])
        self.assertNotIn("location-secret", "\n".join(captured.output))
        urllib_post.assert_not_called()

    async def test_aiohttp_and_urllib_ctfd_semantics_are_equivalent(self) -> None:
        cases = (
            (200, {"data": {"status": "correct"}}, True, None),
            (200, {"data": {"status": "incorrect"}}, False, "rejected"),
            (200, {"unexpected": True}, False, "invalid-response"),
            (403, None, False, "rejected"),
        )
        for status, payload, success, category in cases:
            with self.subTest(status=status, category=category):
                raw_body = b"" if payload is None else json.dumps(payload).encode("utf-8")
                aiohttp_manager = _manager(
                    aiohttp=_FakeAiohttp(
                        ctfd_response=_FakeResponse(status, raw_body=raw_body)
                    ),
                    ctfd_url="https://ctfd.invalid",
                    ctfd_token="token",
                    challenge_id=1,
                )
                urllib_manager = _manager(
                    aiohttp=None,
                    ctfd_url="https://ctfd.invalid",
                    ctfd_token="token",
                    challenge_id=1,
                )
                with patch(
                    "dayi.integrations._urllib_post_json",
                    return_value=_HttpResponse(status, raw_body, False),
                ):
                    aiohttp_result = await aiohttp_manager._deliver(
                        "ctfd", "FLAG{one}"
                    )
                    urllib_result = await urllib_manager._deliver(
                        "ctfd", "FLAG{one}"
                    )
                self.assertEqual(aiohttp_result.success, success)
                self.assertEqual(aiohttp_result.error_category, category)
                self.assertEqual(urllib_result, aiohttp_result)

    async def test_partial_or_invalid_channel_does_not_block_valid_channel(self) -> None:
        discord_manager = _manager(
            aiohttp=_FakeAiohttp(),
            ctfd_url="https://ctfd.invalid",
            webhook_url="https://hooks.invalid/path",
        )
        discord_manager._deliver = AsyncMock(
            return_value=DeliveryResult("discord", True, True, 204, None)
        )
        discord_results = await discord_manager._dispatch("FLAG{one}", "tool")
        discord_manager._deliver.assert_awaited_once_with("discord", "FLAG{one}")
        self.assertTrue(discord_results[0].success)

        ctfd_manager = _manager(
            aiohttp=_FakeAiohttp(),
            ctfd_url="https://ctfd.invalid",
            ctfd_token="token",
            challenge_id=1,
            webhook_url="http://hooks.invalid/not-https",
        )
        ctfd_manager._deliver = AsyncMock(
            return_value=DeliveryResult("ctfd", True, True, 200, None)
        )
        ctfd_results = await ctfd_manager._dispatch("FLAG{two}", "tool")
        ctfd_manager._deliver.assert_awaited_once_with("ctfd", "FLAG{two}")
        self.assertTrue(ctfd_results[0].success)


class UrllibHardeningTests(unittest.TestCase):
    class _Response:
        status = 200

        def __init__(self, body: bytes):
            self.body = body
            self.read_sizes: list[int] = []

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, traceback):
            return False

        def read(self, size: int) -> bytes:
            self.read_sizes.append(size)
            return self.body[:size]

    def test_local_no_redirect_opener_and_bounded_timeout_are_used(self) -> None:
        response = self._Response(b'{"data":{"status":"correct"}}')
        opener = Mock()
        opener.open.return_value = response
        with patch(
            "dayi.integrations.urllib.request.build_opener", return_value=opener
        ) as build_opener, patch(
            "dayi.integrations.urllib.request.urlopen"
        ) as global_urlopen:
            result = _urllib_post_json(
                "https://ctfd.invalid/api/v1/challenges/attempt",
                {"challenge_id": 1, "submission": "FLAG{one}"},
                {"Authorization": "Token secret"},
                True,
            )

        self.assertEqual(result.status_code, 200)
        self.assertEqual(response.read_sizes, [CTFD_RESPONSE_LIMIT + 1])
        self.assertIsInstance(build_opener.call_args.args[0], _NoRedirectHandler)
        self.assertEqual(opener.open.call_args.kwargs["timeout"], URLLIB_REQUEST_TIMEOUT)
        global_urlopen.assert_not_called()

    def test_redirect_is_returned_without_following_or_logging_location(self) -> None:
        secret_location = "https://redirect.invalid/secret-location"
        redirect = urllib.error.HTTPError(
            "https://ctfd.invalid",
            302,
            "redirect",
            {"Location": secret_location},
            None,
        )
        opener = Mock()
        opener.open.side_effect = redirect
        with patch(
            "dayi.integrations.urllib.request.build_opener", return_value=opener
        ), self.assertNoLogs("dayi", level="WARNING"):
            result = _urllib_post_json(
                "https://ctfd.invalid/api/v1/challenges/attempt",
                {},
                None,
                True,
            )
        self.assertEqual(result, _HttpResponse(302, None, False))

    def test_discord_failure_body_is_not_read(self) -> None:
        response = self._Response(b"raw-response-secret")
        response.status = 400
        opener = Mock()
        opener.open.return_value = response
        with patch(
            "dayi.integrations.urllib.request.build_opener", return_value=opener
        ):
            result = _urllib_post_json(
                "https://hooks.invalid/opaque-path", {}, None, False
            )
        self.assertEqual(result.status_code, 400)
        self.assertEqual(response.read_sizes, [])

    def test_urllib_ctfd_response_read_is_size_bounded(self) -> None:
        response = self._Response(b"x" * (CTFD_RESPONSE_LIMIT + 100))
        opener = Mock()
        opener.open.return_value = response
        with patch(
            "dayi.integrations.urllib.request.build_opener", return_value=opener
        ):
            result = _urllib_post_json(
                "https://ctfd.invalid/api/v1/challenges/attempt",
                {},
                None,
                True,
            )
        self.assertTrue(result.body_oversized)
        self.assertEqual(len(result.body), CTFD_RESPONSE_LIMIT + 1)
        self.assertEqual(response.read_sizes, [CTFD_RESPONSE_LIMIT + 1])


if __name__ == "__main__":
    unittest.main()
