"""Bounded execution of user-supplied flag patterns (T3.3).

Every case that runs a catastrophic pattern on hostile input executes in a
separate, time-limited Python process, so an unbounded implementation fails
with ``TimeoutExpired`` instead of hanging the suite.
"""
import asyncio
import json
import re
import subprocess
import sys
import tempfile
import textwrap
import threading
import unittest
from multiprocessing.context import SpawnProcess
from pathlib import Path
from unittest.mock import patch

import dayi.scanner as scanner
from dayi.extraction import _flags as extraction_flags
from dayi.reporter import ToolResult
from dayi.runner import DayiRunner
from dayi.scanner import (
    BoundedFlagPattern,
    IncrementalFlagScanner,
    build_flag_pattern_config,
    scan_directory,
    scan_text,
)
from dayi.text_stego import _find_flags
from dayi.tools._base import async_run_command
from dayi.tools._plugin import PluginContext, PluginPhase, PluginRegistry, ToolPlugin

# Accepted by ``compile_pattern`` and polynomial (O(n^4)) on a digit run
# without ``x``: thousands of seconds in-process on 2 000 digits.
HOSTILE_PATTERN = r"\d+\d+\d+\d+x"
HOSTILE_TEXT = "1111x " + "1" * 2_000
ISOLATION_TIMEOUT = 60.0
REPO_ROOT = Path(__file__).resolve().parents[1]


def _run_isolated(body: str) -> dict:
    """Run ``body`` in a fresh interpreter; it must print one JSON line."""
    prelude = textwrap.dedent(
        """
        import asyncio, json, multiprocessing, time
        import dayi.scanner as s
        s.MAX_FLAG_REGEX_CALL_SECONDS = 1.0
        HOSTILE_PATTERN = %r
        HOSTILE_TEXT = %r
        def events(p):
            return [
                [e.source, e.reason, e.action, e.limit, e.unit, e.count]
                for e in getattr(p, "limit_events", [])
            ]
        """
    ) % (HOSTILE_PATTERN, HOSTILE_TEXT)
    completed = subprocess.run(
        [sys.executable, "-c", prelude + textwrap.dedent(body)],
        capture_output=True,
        text=True,
        timeout=ISOLATION_TIMEOUT,
        cwd=REPO_ROOT,
    )
    if completed.returncode != 0:
        raise AssertionError(
            f"isolated case failed rc={completed.returncode}:\n{completed.stderr}"
        )
    return json.loads(completed.stdout.strip().splitlines()[-1])


def _user_pattern(raw: str) -> BoundedFlagPattern:
    config = build_flag_pattern_config(raw)
    assert config is not None and isinstance(config.compiled, BoundedFlagPattern)
    return config.compiled


def _result(name: str, flags: list[str]) -> ToolResult:
    return ToolResult(
        tool_name=name,
        command=[name],
        return_code=0,
        stdout="",
        stderr="",
        flags_found=flags,
        elapsed_seconds=0.0,
    )


class HostileInputIsolatedTests(unittest.TestCase):
    """Catastrophic matches end at the deadline (each case in its own process)."""

    def test_hostile_call_is_killed_at_deadline_and_keeps_earlier_matches(self) -> None:
        out = _run_isolated(
            """
            p = s.build_flag_pattern_config(HOSTILE_PATTERN).compiled
            started = time.monotonic()
            hits = s.scan_text(HOSTILE_TEXT, p)
            elapsed = time.monotonic() - started
            print(json.dumps({"hits": hits, "elapsed": elapsed,
                              "events": events(p),
                              "children": len(multiprocessing.active_children())}))
            """
        )
        self.assertEqual(out["hits"], ["1111x"])
        self.assertLess(out["elapsed"], 15.0)
        self.assertEqual(
            out["events"],
            [["flag_regex", "flag_regex_timeout", "partial", 1000, "milliseconds", 1]],
        )
        # The killed worker is reaped; nothing is left running.
        self.assertEqual(out["children"], 0)

    def test_scan_budget_bounds_repeated_hostile_calls(self) -> None:
        out = _run_isolated(
            """
            p = s.build_flag_pattern_config(HOSTILE_PATTERN).compiled
            p.start_scan(budget_seconds=2.5)
            started = time.monotonic()
            results = [s.scan_text(HOSTILE_TEXT, p) for _ in range(6)]
            elapsed = time.monotonic() - started
            after = s.scan_text("2222x", p)
            print(json.dumps({"results": results, "elapsed": elapsed,
                              "after": after, "events": events(p)}))
            """
        )
        # Start-up + 1 s + 1 s, then the remaining < 0.5 s ends the third call
        # (reported as budget, not as the 1 s call limit); then nothing runs.
        self.assertEqual(out["results"][:3], [["1111x"]] * 3)
        self.assertEqual(out["results"][3:], [[]] * 3)
        self.assertEqual(out["after"], [])
        self.assertLess(out["elapsed"], 20.0)
        self.assertEqual(
            out["events"],
            [
                ["flag_regex", "flag_regex_timeout", "partial", 1000, "milliseconds", 2],
                ["flag_regex", "flag_regex_budget_exhausted", "partial", 2500,
                 "milliseconds", 1],
                ["flag_regex", "flag_regex_budget_exhausted", "skipped", 2500,
                 "milliseconds", 4],
            ],
        )

    def test_event_loop_wait_is_bounded_by_charged_budget(self) -> None:
        out = _run_isolated(
            """
            p = s.build_flag_pattern_config(HOSTILE_PATTERN).compiled
            p.start_scan(budget_seconds=1.5)
            async def main():
                worker = asyncio.create_task(
                    asyncio.to_thread(s.scan_text, HOSTILE_TEXT, p))
                await asyncio.sleep(0.3)
                started = time.monotonic()
                s.scan_text(HOSTILE_TEXT, p)  # blocks the loop: waits, then runs
                blocked = time.monotonic() - started
                await worker
                return blocked
            blocked = asyncio.run(main())
            print(json.dumps({"blocked": blocked, "events": events(p)}))
            """
        )
        # Lock wait + own call never exceed the remaining scan budget
        # (+ kill/reap grace), instead of call limit x number of waiters.
        self.assertLess(out["blocked"], 1.5 + 2.0)
        reasons = {event[1] for event in out["events"]}
        self.assertIn("flag_regex_budget_exhausted", reasons)

    def test_hostile_call_in_thread_does_not_starve_event_loop(self) -> None:
        out = _run_isolated(
            """
            p = s.build_flag_pattern_config(HOSTILE_PATTERN).compiled
            async def main():
                ticks = 0
                async def ticker():
                    nonlocal ticks
                    while True:
                        ticks += 1
                        await asyncio.sleep(0.01)
                task = asyncio.create_task(ticker())
                hits = await asyncio.to_thread(s.scan_text, HOSTILE_TEXT, p)
                task.cancel()
                return hits, ticks
            hits, ticks = asyncio.run(main())
            print(json.dumps({"hits": hits, "ticks": ticks}))
            """
        )
        self.assertEqual(out["hits"], ["1111x"])
        # ~100 ticks fit into the 1 s deadline when the GIL is not held.
        self.assertGreaterEqual(out["ticks"], 30)

    def test_cancelled_scan_task_and_close_release_worker_promptly(self) -> None:
        out = _run_isolated(
            """
            s.MAX_FLAG_REGEX_CALL_SECONDS = 30.0
            p = s.build_flag_pattern_config(HOSTILE_PATTERN).compiled
            async def main():
                task = asyncio.create_task(
                    asyncio.to_thread(s.scan_text, "1" * 2000, p)
                )
                await asyncio.sleep(0.5)
                started = time.monotonic()
                task.cancel()
                try:
                    await task
                except asyncio.CancelledError:
                    pass
                cancel_latency = time.monotonic() - started
                started = time.monotonic()
                await asyncio.to_thread(p.close)
                close_latency = time.monotonic() - started
                return cancel_latency, close_latency
            cancel_latency, close_latency = asyncio.run(main())
            print(json.dumps({"cancel": cancel_latency, "close": close_latency,
                              "children": len(multiprocessing.active_children())}))
            """
        )
        self.assertLess(out["cancel"], 1.0)
        # close() does not wait for the 30 s deadline of the pending call.
        self.assertLess(out["close"], 5.0)
        self.assertEqual(out["children"], 0)

    def test_runner_reports_regex_timeout_and_finishes(self) -> None:
        out = _run_isolated(
            """
            import tempfile
            from pathlib import Path
            from dayi.reporter import ToolResult, write_json_report
            from dayi.runner import DayiRunner
            from dayi.tools._plugin import PluginPhase, PluginRegistry, ToolPlugin

            def result(name, flags):
                return ToolResult(tool_name=name, command=[name], return_code=0,
                                  stdout="", stderr="", flags_found=flags,
                                  elapsed_seconds=0.0)

            async def hostile(context):
                hits = await asyncio.to_thread(
                    s.scan_text, HOSTILE_TEXT, context.flag_pattern)
                return result("hostile", hits)

            async def later(context):
                return result("later", s.scan_text("abc 9999x", context.flag_pattern))

            registry = PluginRegistry((
                ToolPlugin("hostile", PluginPhase.CONCURRENT, 1, hostile),
                ToolPlugin("later", PluginPhase.MAIN_FINAL, 1, later),
            ))
            config = s.build_flag_pattern_config(HOSTILE_PATTERN)
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                target = root / "target.bin"
                target.write_bytes(b"x")
                runner = DayiRunner(target, config.compiled, registry=registry,
                                    workspace_parent=root, timeout=5.0,
                                    pattern_display=config.display,
                                    pattern_source=config.source, full_scan=True)
                started = time.monotonic()
                report = asyncio.run(runner.run_all())
                elapsed = time.monotonic() - started
                write_json_report(report, root / "r.json")
                data = json.loads((root / "r.json").read_text())
            print(json.dumps({
                "status": report.scan_status, "flags": report.all_flags,
                "limits": data["analysis_limits"], "elapsed": elapsed,
                "pattern": data["meta"]["flag_pattern"],
                "children": len(multiprocessing.active_children())}))
            """
        )
        self.assertEqual(out["status"], "completed")
        self.assertEqual(out["flags"], ["1111x", "9999x"])
        self.assertEqual(out["pattern"], HOSTILE_PATTERN)
        self.assertLess(out["elapsed"], 20.0)
        self.assertEqual(len(out["limits"]), 1)
        self.assertEqual(
            {k: out["limits"][0][k] for k in ("tool", "source", "reason", "action")},
            {
                "tool": "hostile",
                "source": "flag_regex",
                "reason": "flag_regex_timeout",
                "action": "partial",
            },
        )
        self.assertEqual(out["children"], 0)


# Synthetic workers that break the reply protocol. They exit on their own
# once their parent is gone, so a failing case cannot leave them behind.
_STALL_WORKER_SOURCE = textwrap.dedent(
    """
    import os, time
    import dayi.scanner as s

    def _handshake(connection):
        fd = connection.fileno()
        s._send_frame(fd, b"R", float("inf"))
        s._recv_frame(fd, 1 << 26, float("inf"))
        return fd

    def _linger():
        parent = os.getppid()
        while os.getppid() == parent:
            time.sleep(0.05)

    def partial_reply(connection, *args):
        # Within the reply size limit (request "F{a}" + 1), but incomplete.
        fd = _handshake(connection)
        os.write(fd, s._FRAME_HEADER.pack(5) + b"Mx")
        _linger()

    def never_ready(connection, *args):
        _linger()

    def oversized_reply(connection, *args):
        fd = _handshake(connection)
        os.write(fd, s._FRAME_HEADER.pack(1 << 62))
        _linger()
    """
)


class NonFiniteBudgetIsolatedTests(unittest.TestCase):
    """A non-finite or huge ``--timeout`` must not remove the cumulative cap."""

    def test_infinite_and_huge_budgets_still_bound_repeated_hostile_calls(
        self,
    ) -> None:
        out = _run_isolated(
            """
            s.MAX_FLAG_REGEX_BUDGET_SECONDS = 2.5
            results = {}
            for label, budget in (("inf", float("inf")), ("nan", float("nan")),
                                  ("huge", 1e300)):
                p = s.build_flag_pattern_config(HOSTILE_PATTERN).compiled
                p.start_scan(budget_seconds=budget)
                started = time.monotonic()
                hits = [s.scan_text(HOSTILE_TEXT, p) for _ in range(6)]
                results[label] = {"elapsed": time.monotonic() - started,
                                  "hits": hits, "events": events(p)}
                p.close()
            results["children"] = len(multiprocessing.active_children())
            print(json.dumps(results))
            """
        )
        self.assertEqual(out.pop("children"), 0)
        for label, result in out.items():
            with self.subTest(budget=label):
                # Without a cap: 6 x 1 s and no budget event.
                self.assertLess(result["elapsed"], 2.5 + 2.0)
                self.assertEqual(result["hits"][0], ["1111x"])
                self.assertEqual(result["hits"][-1], [])
                self.assertIn(
                    ["flag_regex", "flag_regex_budget_exhausted", "skipped", 2500,
                     "milliseconds", 3],
                    result["events"],
                )


class IpcDeadlineIsolatedTests(unittest.TestCase):
    """Every parent-side wait on the worker is bounded by the call deadline."""

    def test_stalled_worker_cannot_block_sending_a_large_request(self) -> None:
        out = _run_isolated(
            r"""
            import os, signal, threading
            p = s.build_flag_pattern_config(r"F\{\w+\}").compiled
            p.start_scan(budget_seconds=30.0)
            warm = s.scan_text("F{warm}", p)
            process = p._engine._process
            os.kill(process.pid, signal.SIGSTOP)
            # Safety net for an unbounded send: kill the worker so the case
            # fails by assertion instead of leaving a stopped process.
            safety = threading.Timer(15.0, os.kill, (process.pid, signal.SIGKILL))
            safety.daemon = True
            safety.start()
            started = time.monotonic()
            hits = s.scan_text("F{late} " + "a" * (8 * 1024 * 1024), p)
            elapsed = time.monotonic() - started
            safety.cancel()
            stopped_events = events(p)
            reaped = process.exitcode is not None
            after = s.scan_text("F{next}", p)
            starts = p.worker_starts
            p.close()
            print(json.dumps({
                "warm": warm, "hits": hits, "elapsed": elapsed,
                "events": stopped_events, "reaped": reaped, "after": after,
                "starts": starts,
                "children": len(multiprocessing.active_children())}))
            """
        )
        self.assertEqual(out["warm"], ["F{warm}"])
        self.assertEqual(out["hits"], [])
        self.assertLess(out["elapsed"], 1.0 + 2.0)
        self.assertEqual(
            out["events"],
            [["flag_regex", "flag_regex_timeout", "partial", 1000, "milliseconds", 1]],
        )
        self.assertTrue(out["reaped"])
        self.assertEqual(out["after"], ["F{next}"])
        self.assertEqual(out["starts"], 2)
        self.assertEqual(out["children"], 0)

    def test_worker_stalled_or_lying_inside_a_reply_frame(self) -> None:
        out = _run_isolated(
            """
            import os, sys, tempfile
            tmp = tempfile.mkdtemp()
            with open(os.path.join(tmp, "stall_worker.py"), "w") as handle:
                handle.write(%r)
            sys.path.insert(0, tmp)
            import stall_worker
            results = {}
            for name in ("partial_reply", "oversized_reply"):
                s._flag_regex_worker = getattr(stall_worker, name)
                p = s.build_flag_pattern_config(r"F\\{\\w+\\}").compiled
                p.start_scan(budget_seconds=30.0)
                started = time.monotonic()
                hits = s.scan_text("F{a}", p)
                results[name] = {
                    "elapsed": time.monotonic() - started, "hits": hits,
                    "events": events(p),
                    "children": len(multiprocessing.active_children())}
                p.close()
            print(json.dumps(results))
            """ % _STALL_WORKER_SOURCE
        )
        partial = out["partial_reply"]
        self.assertEqual(partial["hits"], [])
        self.assertLess(partial["elapsed"], 1.0 + 2.0)
        self.assertEqual(
            partial["events"],
            [["flag_regex", "flag_regex_timeout", "partial", 1000, "milliseconds", 1]],
        )
        self.assertEqual(partial["children"], 0)
        oversized = out["oversized_reply"]
        self.assertEqual(oversized["hits"], [])
        self.assertLess(oversized["elapsed"], 1.0)
        self.assertEqual(
            oversized["events"],
            [["flag_regex", "flag_regex_worker_failure", "skipped", 0, "none", 1]],
        )
        self.assertEqual(oversized["children"], 0)

    def test_worker_that_never_becomes_ready_fails_closed_at_start_deadline(
        self,
    ) -> None:
        out = _run_isolated(
            """
            import os, sys, tempfile
            tmp = tempfile.mkdtemp()
            with open(os.path.join(tmp, "stall_worker.py"), "w") as handle:
                handle.write(%r)
            sys.path.insert(0, tmp)
            import stall_worker
            s._FLAG_REGEX_START_SECONDS = 1.0
            s._flag_regex_worker = stall_worker.never_ready
            p = s.build_flag_pattern_config(r"F\\{\\w+\\}").compiled
            p.start_scan(budget_seconds=30.0)
            started = time.monotonic()
            hits = s.scan_text("F{a}", p)
            elapsed = time.monotonic() - started
            print(json.dumps({
                "hits": hits, "elapsed": elapsed, "events": events(p),
                "children": len(multiprocessing.active_children())}))
            p.close()
            """ % _STALL_WORKER_SOURCE
        )
        self.assertEqual(out["hits"], [])
        self.assertGreaterEqual(out["elapsed"], 0.9)
        self.assertLess(out["elapsed"], 1.0 + 2.0)
        self.assertEqual(
            out["events"],
            [["flag_regex", "flag_regex_worker_failure", "skipped", 0, "none", 1]],
        )
        self.assertEqual(out["children"], 0)

    def test_worker_death_during_a_match_fails_closed_promptly(self) -> None:
        out = _run_isolated(
            """
            import os, signal, threading
            s.MAX_FLAG_REGEX_CALL_SECONDS = 5.0
            p = s.build_flag_pattern_config(HOSTILE_PATTERN).compiled
            p.start_scan(budget_seconds=30.0)
            s.scan_text("0000x", p)
            pid = p._engine._process.pid
            threading.Timer(0.3, os.kill, (pid, signal.SIGKILL)).start()
            started = time.monotonic()
            hits = s.scan_text(HOSTILE_TEXT, p)
            elapsed = time.monotonic() - started
            after = s.scan_text("2222x", p)
            print(json.dumps({
                "hits": hits, "elapsed": elapsed, "after": after,
                "events": events(p), "starts": p.worker_starts,
                "children": len(multiprocessing.active_children())}))
            p.close()
            """
        )
        self.assertEqual(out["hits"], ["1111x"])  # found before the death
        self.assertLess(out["elapsed"], 3.0)  # not the 5 s deadline
        self.assertEqual(out["after"], [])  # fail closed, no restart
        self.assertEqual(out["starts"], 1)
        self.assertEqual(
            out["events"],
            [["flag_regex", "flag_regex_worker_failure", "skipped", 0, "none", 2]],
        )
        self.assertEqual(out["children"], 0)

    def test_frame_helpers_honour_deadlines_and_size_limits(self) -> None:
        out = _run_isolated(
            """
            import socket
            def pair():
                a, b = socket.socketpair()
                a.setblocking(False)
                b.setblocking(False)
                return a, b
            out = {}
            a, b = pair()
            out["sent"] = s._send_frame(a.fileno(), b"abc", time.monotonic() + 5)
            out["round_trip"] = s._recv_frame(
                b.fileno(), 3, time.monotonic() + 5).decode()
            started = time.monotonic()
            out["send_to_idle_reader"] = s._send_frame(
                a.fileno(), b"x" * (8 * 1024 * 1024), started + 0.3)
            out["send_elapsed"] = time.monotonic() - started
            a, b = pair()
            b.send(s._FRAME_HEADER.pack(100) + b"x" * 10)
            started = time.monotonic()
            out["partial"] = s._recv_frame(a.fileno(), 100, started + 0.3)
            out["partial_elapsed"] = time.monotonic() - started
            a, b = pair()
            b.send(s._FRAME_HEADER.pack(1 << 62))
            try:
                s._recv_frame(a.fileno(), 1024, time.monotonic() + 5)
                out["oversized"] = "accepted"
            except ValueError:
                out["oversized"] = "rejected"
            a, b = pair()
            b.close()
            try:
                s._recv_frame(a.fileno(), 1024, time.monotonic() + 5)
                out["eof"] = "no error"
            except EOFError:
                out["eof"] = "eof"
            print(json.dumps(out))
            """
        )
        self.assertTrue(out["sent"])
        self.assertEqual(out["round_trip"], "abc")
        self.assertFalse(out["send_to_idle_reader"])
        self.assertGreaterEqual(out["send_elapsed"], 0.25)
        self.assertLess(out["send_elapsed"], 2.0)
        self.assertIsNone(out["partial"])
        self.assertGreaterEqual(out["partial_elapsed"], 0.25)
        self.assertLess(out["partial_elapsed"], 2.0)
        self.assertEqual(out["oversized"], "rejected")
        self.assertEqual(out["eof"], "eof")


class BoundedPatternSemanticsTests(unittest.TestCase):
    """Benign inputs: identical results to in-process ``re``."""

    COMMON = (
        r"CTF\{[^}]+\}",
        r"(CUSTOM)\{([A-Z0-9_]+)\}",
        r"(?i)flag\{.*?\}",
        r"flag\{.*\}",
        r"[a-z]{2,8}\{\w+\}",
        r"(?:\d{1,3}\.){3}\d{1,3}",
        r"HTB\{[^}]{1,64}\}",
        r"x",
    )
    TEXT = (
        "CTF{one} CTF{one} flag{a}b} FLAG{Mixed} CUSTOM{FULL_MATCH}\n"
        "10.0.0.1 picoctf{abc_123} xx çş HTB{h} ctf{two}\x00flag{z}"
    )

    def test_common_patterns_match_like_in_process_re(self) -> None:
        for raw in self.COMMON:
            with self.subTest(raw=raw):
                bounded = _user_pattern(raw)
                self.assertEqual(bounded.pattern, raw)
                self.assertEqual(bounded.flags, re.compile(raw).flags)
                self.assertEqual(
                    scan_text(self.TEXT, bounded),
                    scan_text(self.TEXT, re.compile(raw)),
                )
                self.assertEqual(bounded.limit_events, [])
                bounded.close()

    def test_empty_and_no_match_inputs_record_nothing(self) -> None:
        bounded = _user_pattern(r"CUSTOM\{\w+\}")
        try:
            self.assertEqual(scan_text("", bounded), [])
            self.assertEqual(scan_text("nothing here", bounded), [])
            self.assertEqual(bounded.limit_events, [])
        finally:
            bounded.close()

    def test_direct_finditer_callers_get_identical_values(self) -> None:
        raw = r"FLAG\{[^}]*\}"
        text = "FLAG{a} FLAG{b} FLAG{a} " + "FLAG{" + "y" * 3000 + "}"
        bounded = _user_pattern(raw)
        try:
            self.assertEqual(
                extraction_flags(text.encode(), bounded),
                extraction_flags(text.encode(), re.compile(raw)),
            )
            self.assertEqual(
                _find_flags(text, bounded), _find_flags(text, re.compile(raw))
            )
            self.assertEqual(
                [m.group(0) for m in bounded.finditer("FLAG{q} FLAG{q}")],
                ["FLAG{q}"],
            )
        finally:
            bounded.close()

    def test_surrogates_and_non_ascii_round_trip(self) -> None:
        bounded = _user_pattern(r"F\{.\}")
        try:
            self.assertEqual(
                scan_text("F{\udcff} F{ç} F{\U0001f600}", bounded),
                ["F{\udcff}", "F{ç}", "F{\U0001f600}"],
            )
        finally:
            bounded.close()

    def test_repeated_calls_reuse_one_worker(self) -> None:
        bounded = _user_pattern(r"K\d+")
        try:
            for index in range(200):
                self.assertEqual(scan_text(f"a K{index} b", bounded), [f"K{index}"])
            self.assertEqual(bounded.worker_starts, 1)
        finally:
            bounded.close()

    def test_builtin_pattern_stays_in_process(self) -> None:
        config = build_flag_pattern_config(None)
        assert config is not None
        self.assertIs(config.compiled, scanner.get_builtin_flag_pattern())
        self.assertIsInstance(config.compiled, re.Pattern)

    def test_invalid_and_rejected_patterns_still_return_none(self) -> None:
        for raw in ("(", r"(a+)+$", r"(a{1,})+b", "a" * 513):
            with self.subTest(raw=raw[:20]):
                self.assertIsNone(build_flag_pattern_config(raw))


class BoundedPatternLimitTests(unittest.TestCase):
    def test_match_count_limit_is_recorded(self) -> None:
        bounded = _user_pattern(r"k\d{4}")
        try:
            text = " ".join(f"k{index:04d}" for index in range(1_100))
            hits = scan_text(text, bounded)
            self.assertEqual(hits, scan_text(text, re.compile(r"k\d{4}")))
            self.assertEqual(len(hits), scanner.MAX_FLAG_MATCHES)
            self.assertEqual(
                bounded.limit_events,
                [scanner.AnalysisLimit(
                    "flag_regex", "flag_match_limit", "partial",
                    scanner.MAX_FLAG_MATCHES, "matches",
                )],
            )
        finally:
            bounded.close()

    def test_exactly_max_unique_matches_is_not_a_limit(self) -> None:
        bounded = _user_pattern(r"k\d{4}")
        try:
            text = " ".join(
                f"k{index:04d}" for index in range(scanner.MAX_FLAG_MATCHES)
            )
            self.assertEqual(len(scan_text(text, bounded)), scanner.MAX_FLAG_MATCHES)
            self.assertEqual(bounded.limit_events, [])
        finally:
            bounded.close()

    def test_input_above_cap_is_skipped_and_recorded(self) -> None:
        bounded = _user_pattern(r"F\{\w+\}")
        try:
            with patch.object(scanner, "MAX_FLAG_REGEX_INPUT_CHARS", 16):
                self.assertEqual(scan_text("F{exactly_sixte}", bounded), ["F{exactly_sixte}"])
                self.assertEqual(scan_text("F{seventeen_chr}x", bounded), [])
            self.assertEqual(
                bounded.limit_events,
                [scanner.AnalysisLimit(
                    "flag_regex", "flag_regex_input_limit", "skipped",
                    16, "characters", 17,
                )],
            )
        finally:
            bounded.close()

    def test_worker_start_failure_fails_closed_without_retry(self) -> None:
        bounded = _user_pattern(r"F\{\w+\}")
        try:
            with patch.object(
                scanner._FlagRegexEngine, "_start_worker",
                side_effect=OSError("boom"),
            ) as start:
                for _ in range(3):
                    self.assertEqual(scan_text("F{a}", bounded), [])
            self.assertEqual(start.call_count, 1)
            self.assertEqual(
                bounded.limit_events,
                [scanner.AnalysisLimit(
                    "flag_regex", "flag_regex_worker_failure", "skipped", 0, "none",
                    count=3,
                )],
            )
        finally:
            bounded.close()

    def test_interrupt_while_waiting_kills_worker(self) -> None:
        bounded = _user_pattern(r"F\{\w+\}")
        try:
            self.assertEqual(scan_text("F{warm}", bounded), ["F{warm}"])
            engine = bounded._engine
            process = engine._process
            assert process is not None
            with patch.object(scanner, "_recv_frame", side_effect=KeyboardInterrupt):
                with self.assertRaises(KeyboardInterrupt):
                    scan_text("F{a}", bounded)
            self.assertFalse(process.is_alive())
            # The next call starts a fresh worker.
            self.assertEqual(scan_text("F{b}", bounded), ["F{b}"])
            self.assertEqual(bounded.worker_starts, 2)
        finally:
            bounded.close()

    def test_budget_is_clamped_to_a_finite_maximum(self) -> None:
        cap = scanner.MAX_FLAG_REGEX_BUDGET_SECONDS
        bounded = _user_pattern(r"F\{\w+\}")
        try:
            for budget, expected in (
                (float("inf"), cap),
                (float("nan"), cap),
                (1e300, cap),
                (cap * 10, cap),
                (cap, cap),
                (60.0, 60.0),
                (2.5, 2.5),
            ):
                with self.subTest(budget=budget):
                    bounded.start_scan(budget_seconds=budget)
                    self.assertEqual(bounded._engine._budget, expected)
                    self.assertEqual(scan_text("x F{ok} y", bounded), ["F{ok}"])
                    self.assertEqual(bounded.limit_events, [])
        finally:
            bounded.close()

    def test_negative_budgets_skip_matching_and_are_reported(self) -> None:
        bounded = _user_pattern(r"F\{\w+\}")
        try:
            for budget in (float("-inf"), -1.0, 0.0):
                with self.subTest(budget=budget):
                    bounded.start_scan(budget_seconds=budget)
                    self.assertEqual(scan_text("F{a}", bounded), [])
                    self.assertEqual(
                        bounded.limit_events,
                        [scanner.AnalysisLimit(
                            "flag_regex", "flag_regex_budget_exhausted", "skipped",
                            0, "milliseconds",
                        )],
                    )
            self.assertEqual(bounded.worker_starts, 0)
        finally:
            bounded.close()

    def test_direct_construction_clamps_non_finite_budgets(self) -> None:
        cap = scanner.MAX_FLAG_REGEX_BUDGET_SECONDS
        for budget in (float("inf"), float("nan"), 1e300, 10**400):
            with self.subTest(budget=budget):
                bounded = BoundedFlagPattern(
                    re.compile(r"F\{\w+\}"), budget_seconds=budget
                )
                try:
                    self.assertEqual(bounded._engine._budget, cap)
                    self.assertEqual(scan_text("F{direct}", bounded), ["F{direct}"])
                finally:
                    bounded.close()

    def test_deadline_ipc_is_required_or_matching_fails_closed(self) -> None:
        bounded = _user_pattern(r"F\{\w+\}")
        try:
            with patch.object(scanner, "_DEADLINE_IPC_SUPPORTED", False):
                self.assertEqual(scan_text("F{a}", bounded), [])
            self.assertIsNone(bounded._engine._process)
            self.assertEqual(bounded.worker_starts, 0)
            self.assertEqual(
                [e.reason for e in bounded.limit_events],
                ["flag_regex_worker_failure"],
            )
        finally:
            bounded.close()

    def test_worker_start_up_is_charged_to_the_budget(self) -> None:
        bounded = _user_pattern(r"F\{\w+\}")
        try:
            bounded.start_scan(budget_seconds=0.001)  # far below a spawn
            self.assertEqual(scan_text("F{a}", bounded), [])
            self.assertEqual(bounded.worker_starts, 1)
            self.assertEqual(
                bounded.limit_events,
                [scanner.AnalysisLimit(
                    "flag_regex", "flag_regex_budget_exhausted", "skipped",
                    1, "milliseconds",
                )],
            )
        finally:
            bounded.close()

    def test_start_scan_replaces_a_running_worker(self) -> None:
        bounded = _user_pattern(r"F\{\w+\}")
        try:
            self.assertEqual(scan_text("F{a}", bounded), ["F{a}"])
            old = bounded._engine._process
            assert old is not None
            bounded.start_scan(budget_seconds=10.0)
            self.assertFalse(old.is_alive())
            self.assertEqual(scan_text("F{b}", bounded), ["F{b}"])
            self.assertEqual(bounded.worker_starts, 2)
        finally:
            bounded.close()

    def test_close_racing_worker_start_kills_the_new_worker(self) -> None:
        bounded = _user_pattern(r"F\{\w+\}")
        engine = bounded._engine
        closer = threading.Thread(target=bounded.close)
        started: list = []
        original_start = SpawnProcess.start

        def close_then_start(process) -> None:
            closer.start()  # close() sees no pid, then waits for the request
            closer.join(0.3)
            original_start(process)
            started.append(process)

        try:
            with patch.object(
                SpawnProcess, "start", close_then_start
            ), self.assertNoLogs("dayi", level="ERROR"):
                self.assertEqual(scan_text("F{a}", bounded), [])
            closer.join(10)
            self.assertFalse(closer.is_alive())
            self.assertEqual(len(started), 1)
            self.assertFalse(started[0].is_alive())
            self.assertIsNone(engine._process)
            self.assertEqual(
                [e.reason for e in bounded.limit_events],
                ["flag_regex_worker_failure"],
            )
        finally:
            bounded.close()

    def test_start_scan_resets_state_and_close_refuses_until_reset(self) -> None:
        bounded = _user_pattern(r"F\{\w+\}")
        try:
            with patch.object(scanner, "MAX_FLAG_REGEX_INPUT_CHARS", 4):
                scan_text("F{toolong}", bounded)
            self.assertEqual(len(bounded.limit_events), 1)
            bounded.start_scan(budget_seconds=10.0)
            self.assertEqual(bounded.limit_events, [])
            self.assertEqual(scan_text("F{a}", bounded), ["F{a}"])
            process = bounded._engine._process
            assert process is not None
            bounded.close()
            self.assertFalse(process.is_alive())
            self.assertIsNone(bounded._engine._process)
            self.assertEqual(scan_text("F{b}", bounded), [])
            self.assertEqual(
                [e.reason for e in bounded.limit_events],
                ["flag_regex_worker_failure"],
            )
            bounded.start_scan(budget_seconds=10.0)
            self.assertEqual(scan_text("F{c}", bounded), ["F{c}"])
        finally:
            bounded.close()

    def test_plugin_views_share_worker_but_not_events(self) -> None:
        root = _user_pattern(r"F\{\w+\}")
        first = root.for_plugin()
        second = root.for_plugin()
        try:
            self.assertEqual((first.pattern, first.flags), (root.pattern, root.flags))
            with patch.object(scanner, "MAX_FLAG_REGEX_INPUT_CHARS", 4):
                scan_text("F{toolong}", first)
            self.assertEqual(scan_text("F{x}", second), ["F{x}"])
            self.assertEqual(len(first.limit_events), 1)
            self.assertEqual(second.limit_events, [])
            self.assertEqual(root.limit_events, [])
            self.assertEqual(root.worker_starts, 1)
        finally:
            root.close()


class BoundedPatternIntegrationTests(unittest.IsolatedAsyncioTestCase):
    async def test_incremental_scanner_finds_flag_across_chunks(self) -> None:
        bounded = _user_pattern(r"CUSTOM\{[a-z]+\}")
        try:
            observer = IncrementalFlagScanner(bounded)
            for chunk in (b"xx CUS", b"TOM{spl", b"it} CUSTOM{two}"):
                observer.feed(chunk)
            observer.finish()
            self.assertEqual(observer.flags, ("CUSTOM{split}", "CUSTOM{two}"))
        finally:
            bounded.close()

    async def test_subprocess_stream_observer_uses_bounded_pattern(self) -> None:
        bounded = _user_pattern(r"CUSTOM\{[a-z]+\}")
        try:
            stream = scanner.SubprocessFlagScanner(bounded)
            rc, stdout, stderr, _elapsed, timed_out = await async_run_command(
                [sys.executable, "-c",
                 "import sys; print('a CUSTOM{out}'); "
                 "print('CUSTOM{err}', file=sys.stderr)"],
                "fixture",
                timeout=30,
                stdout_observer=stream.stdout,
                stderr_observer=stream.stderr,
            )
            self.assertEqual((rc, timed_out), (0, False))
            self.assertEqual(
                stream.findings(stdout, stderr),
                {"stdout": ["CUSTOM{out}"], "stderr": ["CUSTOM{err}"]},
            )
        finally:
            bounded.close()

    async def test_extracted_file_scan_uses_bounded_pattern(self) -> None:
        bounded = _user_pattern(r"CUSTOM\{[a-z]+\}")
        try:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp)
                (root / "a.txt").write_text("x CUSTOM{file} y", encoding="utf-8")
                (root / "b.txt").write_text("none", encoding="utf-8")
                self.assertEqual(
                    await asyncio.to_thread(scan_directory, root, bounded),
                    {"a.txt": ["CUSTOM{file}"]},
                )
        finally:
            bounded.close()

    async def _run(self, registry: PluginRegistry, pattern, **kwargs):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target.bin"
            target.write_bytes(b"x")
            runner = DayiRunner(
                target, pattern, registry=registry, workspace_parent=root, **kwargs
            )
            report = await asyncio.wait_for(runner.run_all(), timeout=30)
            return runner, report

    def _registry(self, seen: list):
        async def first(context: PluginContext) -> ToolResult:
            seen.append(context.flag_pattern)
            hits = await asyncio.to_thread(
                scan_text, "CUSTOM{found}", context.flag_pattern
            )
            return _result("first", hits)

        async def later(context: PluginContext) -> ToolResult:
            seen.append(context.flag_pattern)
            return _result("later", scan_text("CUSTOM{later}", context.flag_pattern))

        return PluginRegistry((
            ToolPlugin("first", PluginPhase.CONCURRENT, 1, first),
            ToolPlugin("later", PluginPhase.MAIN_FINAL, 1, later),
        ))

    async def test_default_early_stop_unchanged_with_bounded_pattern(self) -> None:
        seen: list = []
        pattern = _user_pattern(r"CUSTOM\{[a-z]+\}")
        runner, report = await self._run(self._registry(seen), pattern)
        self.assertEqual(report.all_flags, ["CUSTOM{found}"])
        self.assertEqual(report.scan_status, "early_stopped")
        self.assertEqual(len(seen), 1)
        self.assertIsNot(seen[0], pattern)
        self.assertEqual(report.tool_results[0].analysis_limits, [])
        self.assertIsNone(pattern._engine._process)

    async def test_full_scan_and_repeated_runs_have_no_stale_state(self) -> None:
        seen: list = []
        pattern = _user_pattern(r"CUSTOM\{[a-z]+\}")
        registry = self._registry(seen)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / "target.bin"
            target.write_bytes(b"x")
            runner = DayiRunner(
                target, pattern, registry=registry, workspace_parent=root,
                full_scan=True,
            )
            first = await asyncio.wait_for(runner.run_all(), timeout=30)
            self.assertIsNone(pattern._engine._process)
            second = await asyncio.wait_for(runner.run_all(), timeout=30)
        for report in (first, second):
            self.assertEqual(report.all_flags, ["CUSTOM{found}", "CUSTOM{later}"])
            self.assertEqual(report.scan_status, "completed")
            self.assertTrue(all(not r.analysis_limits for r in report.tool_results))
        self.assertEqual(len({id(view) for view in seen}), 4)
        self.assertIsNone(pattern._engine._process)
        self.assertEqual(pattern.worker_starts, 2)

    async def test_runner_merges_plugin_regex_events_into_its_result(self) -> None:
        async def oversized(context: PluginContext) -> ToolResult:
            with patch.object(scanner, "MAX_FLAG_REGEX_INPUT_CHARS", 4):
                hits = scan_text("CUSTOM{toolong}", context.flag_pattern)
            return _result("oversized", hits)

        async def clean(context: PluginContext) -> ToolResult:
            return _result("clean", scan_text("CUSTOM{ok}", context.flag_pattern))

        registry = PluginRegistry((
            ToolPlugin("oversized", PluginPhase.CONCURRENT, 1, oversized),
            ToolPlugin("clean", PluginPhase.MAIN_FINAL, 1, clean),
        ))
        _runner, report = await self._run(
            registry, _user_pattern(r"CUSTOM\{[a-z]+\}"), full_scan=True
        )
        by_tool = {r.tool_name: r.analysis_limits for r in report.tool_results}
        self.assertEqual(
            [e.reason for e in by_tool["oversized"]], ["flag_regex_input_limit"]
        )
        self.assertEqual(by_tool["clean"], [])
        self.assertEqual(report.all_flags, ["CUSTOM{ok}"])

    async def test_regex_events_survive_a_failing_plugin(self) -> None:
        async def failing(context: PluginContext) -> ToolResult:
            with patch.object(scanner, "MAX_FLAG_REGEX_INPUT_CHARS", 4):
                scan_text("CUSTOM{toolong}", context.flag_pattern)
            raise RuntimeError("plugin bug")

        registry = PluginRegistry((
            ToolPlugin("failing", PluginPhase.CONCURRENT, 1, failing),
        ))
        _runner, report = await self._run(
            registry, _user_pattern(r"CUSTOM\{[a-z]+\}")
        )
        (result,) = report.tool_results
        self.assertTrue(result.error)
        self.assertEqual(
            [e.reason for e in result.analysis_limits], ["flag_regex_input_limit"]
        )

    async def test_runner_with_infinite_timeout_uses_finite_regex_budget(self) -> None:
        seen: list = []
        pattern = _user_pattern(r"CUSTOM\{[a-z]+\}")
        _runner, report = await self._run(
            self._registry(seen), pattern, timeout=float("inf")
        )
        self.assertEqual(report.all_flags, ["CUSTOM{found}"])
        self.assertEqual(
            pattern._engine._budget, scanner.MAX_FLAG_REGEX_BUDGET_SECONDS
        )
        self.assertIsNone(pattern._engine._process)

    async def test_builtin_runner_passes_pattern_unchanged(self) -> None:
        seen: list = []
        pattern = scanner.get_builtin_flag_pattern()
        await self._run(self._registry(seen), pattern)
        self.assertIs(seen[0], pattern)


if __name__ == "__main__":
    unittest.main()
