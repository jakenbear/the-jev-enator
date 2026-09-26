#!/usr/bin/env python3
"""Regressions for the self-edit guard, unusable replies, and the request deadline.

No API key and no network. Jev is either not called, replayed from the cassette,
or replaced with a fake response in-process. A case that reaches a real host
is a failed case.

Usage:
  python3 tests/test_jev_security.py
"""

import email.message
import http.client
import io
import json
import os
import subprocess
import sys
import time
import urllib.error
from pathlib import Path
from unittest.mock import patch

REPO = Path(__file__).resolve().parent.parent
GATE = REPO / "src" / "jev_gate.py"
SRC = REPO / "src"

sys.path.insert(0, str(SRC))
sys.path.insert(0, str(REPO / "tests"))

import jev_client  # noqa: E402
import jev_gate  # noqa: E402
from fixture_env import PINNED_CWD, fixture_log, hook_env  # noqa: E402
from jev_client import BRAND, JevError, JevReplyError  # noqa: E402

HOOKS = (
    "jev_gate.py",
    "jev_notice.py",
    "jev_finish.py",
    "jev_scope.py",
    "jev_reads.py",
    "jev_clear.py",
)

NOUL = {"type": "noul"}
CHOICE = {"type": "choice"}


def quiet_env(log_path: str, **extra: str) -> dict:
    """Subprocess env that cannot reach the network or the cassette.

    The off switches are dropped too, so a developer shell that has them set
    does not make every denial look like an allow.
    """
    env = hook_env(log_path, **extra)
    for name in (
        "TYPESAFE_API_KEY",
        "JEV_REPLAY",
        "JEV_GATE_REPLAY",
        "JEV_DISABLE",
        "JEV_GATE_DISABLE",
        "JEV_GATE_OFF",
    ):
        env.pop(name, None)
    env.update(extra)
    return env


def run_gate(payload: dict, env: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(GATE)],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=env,
    )


def decision_of(proc: subprocess.CompletedProcess) -> tuple[str, str]:
    out = proc.stdout.strip()
    if not out:
        return "allow", ""
    try:
        body = json.loads(out)["hookSpecificOutput"]
        return body["permissionDecision"], body.get("permissionDecisionReason", "")
    except (json.JSONDecodeError, KeyError, TypeError):
        return "?", out


def records(path: str) -> list[dict]:
    file = Path(path)
    if not file.exists() or file.stat().st_size == 0:
        return []
    return [json.loads(line) for line in file.read_text().splitlines() if line.strip()]


def payload(tool: str, tool_input: dict, cwd: str) -> dict:
    return {
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": tool_input,
        "cwd": cwd,
    }


def assert_denied(results: list, log_path: str, kind: str, label: str, body: dict, cwd: str, tool: str = "Write"):
    env = quiet_env(log_path, JEV_REPLAY=str(REPO / "tests" / "cassette.json"))
    proc = run_gate(payload(tool, body, cwd), env)
    decision, reason = decision_of(proc)
    logged = records(log_path)
    results.append((decision == "deny", f"{label}: decision is deny (got {decision})"))
    results.append((BRAND in reason, f"{label}: the refusal names itself"))
    results.append(("jev replay:" not in (proc.stderr or ""), f"{label}: Jev was not called"))
    results.append((proc.returncode == 0, f"{label}: exits 0 with a decision"))
    results.append(
        (
            any(row.get("reason") == "self_edit" and row.get("protected") == kind for row in logged),
            f"{label}: audit line says self_edit/{kind}",
        )
    )


class _Body:
    def __init__(self, raw: bytes):
        self._raw = raw

    def read(self, amt=-1):
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class _SlowBody:
    """One read that ignores the socket timeout and blocks past the deadline."""

    def __init__(self, seconds: float):
        self.seconds = seconds

    def read(self, amt=-1):
        time.sleep(self.seconds)
        return b"{}"

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


class _Incomplete:
    def read(self, amt=-1):
        raise http.client.IncompleteRead(partial=b"{")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def _no_replay(env_extra: dict | None = None):
    env = {k: v for k, v in os.environ.items() if k not in ("JEV_REPLAY", "JEV_GATE_REPLAY")}
    env.update(env_extra or {})
    return patch.dict(os.environ, env, clear=True)


def case_self_edit_guard():
    """Writes and commands that would change the live gate are denied before Jev."""
    log_path = fixture_log("security-guard")
    # Truncate between assertions that share the file, so each one sees its own line.
    results = []
    gate_file = str(SRC / "jev_gate.py")
    project = "/tmp/jev-security-project"

    def check(label, kind, body, cwd, tool="Write"):
        Path(log_path).write_text("")
        assert_denied(results, log_path, kind, label, body, cwd, tool)

    check("edit the running gate", "hooks", {"file_path": gate_file, "old_string": "x", "new_string": "y"}, project, "Edit")
    check(
        "write the running client",
        "hooks",
        {"file_path": str(SRC / "jev_client.py"), "content": "x = 1\n"},
        project,
    )
    check(
        "multiedit inside the install tree",
        "hooks",
        {"file_path": gate_file, "edits": [{"old_string": "a", "new_string": "b"}]},
        project,
        "MultiEdit",
    )
    check(
        "notebook edit inside the install tree",
        "hooks",
        {"notebook_path": str(SRC / "notes.ipynb"), "new_source": "1"},
        project,
        "NotebookEdit",
    )
    check(
        "path that resolves into the install tree",
        "hooks",
        {"file_path": str(SRC / "nested" / ".." / "jev_gate.py"), "content": "x"},
        project,
    )
    check(
        "user settings file",
        "settings",
        {"file_path": str(Path.home() / ".claude" / "settings.json"), "content": "{}\n"},
        project,
    )
    check(
        "user settings.local.json",
        "settings",
        {"file_path": str(Path.home() / ".claude" / "settings.local.json"), "content": "{}\n"},
        project,
    )
    check(
        "project settings file",
        "settings",
        {"file_path": ".claude/settings.local.json", "content": "{}\n"},
        project,
    )
    check(
        "the audit log",
        "log",
        {"file_path": log_path, "content": ""},
        project,
    )
    check(
        "bash that names the gate file",
        "hooks",
        {"command": f"echo poke >> {gate_file}"},
        project,
        "Bash",
    )
    check(
        "bash whose cwd is the install tree",
        "hooks",
        {"command": "echo poke >> jev_gate.py"},
        str(SRC),
        "Bash",
    )
    check(
        "bash that names a settings file",
        "settings",
        {"command": "echo '{}' > .claude/settings.json"},
        project,
        "Bash",
    )
    check(
        "bash that names the log",
        "log",
        {"command": f"rm -f {log_path}"},
        project,
        "Bash",
    )
    check(
        "git checkout aimed at the install tree",
        "hooks",
        {"command": f"git -C {SRC} checkout -- jev_gate.py"},
        project,
        "Bash",
    )
    check(
        "relative path under the install tree",
        "hooks",
        {"command": "echo poke >> src/jev_gate.py"},
        str(REPO),
        "Bash",
    )

    # A normal project edit still reaches Jev. Replay supplies the verdict, so
    # a guard that fired here would deny instead of allowing.
    Path(log_path).write_text("")
    env = quiet_env(log_path, JEV_REPLAY=str(REPO / "tests" / "cassette.json"))
    proc = run_gate(
        payload(
            "Write",
            {"file_path": f"{PINNED_CWD}/src/utils/format.ts", "content": "export const x = 1\n"},
            PINNED_CWD,
        ),
        env,
    )
    decision, _reason = decision_of(proc)
    results.append((decision == "allow", f"ordinary source edit still allowed (got {decision})"))
    results.append(("jev replay:" not in (proc.stderr or ""), "ordinary source edit found its recording"))
    results.append(
        (
            not any(row.get("reason") == "self_edit" for row in records(log_path)),
            "ordinary source edit is not a self-edit",
        )
    )

    Path(log_path).write_text("")
    proc = run_gate(
        payload(
            "Bash",
            {"command": "git status --short", "description": "Show working tree status"},
            PINNED_CWD,
        ),
        env,
    )
    decision, _reason = decision_of(proc)
    results.append((decision == "allow", f"git status outside the install tree still allowed (got {decision})"))
    results.append(("jev replay:" not in (proc.stderr or ""), "git status found its recording"))

    # git checkout in an ordinary project is not the install tree, so the guard
    # stays quiet. No key and no cassette: silence is "not denied", and a real
    # call would need a key we have removed.
    Path(log_path).write_text("")
    proc = run_gate(
        payload("Bash", {"command": "git checkout main"}, PINNED_CWD),
        quiet_env(log_path),
    )
    decision, _reason = decision_of(proc)
    results.append((decision == "allow", f"git checkout in a project is not a self-edit (got {decision})"))
    results.append(
        (
            not any(row.get("reason") == "self_edit" for row in records(log_path)),
            "git checkout in a project left no self-edit line",
        )
    )

    # The off switch still works, including past this guard.
    Path(log_path).write_text("")
    proc = run_gate(
        payload("Edit", {"file_path": gate_file, "old_string": "a", "new_string": "b"}, project),
        quiet_env(log_path, JEV_DISABLE="1"),
    )
    decision, _reason = decision_of(proc)
    results.append((decision == "allow", f"JEV_DISABLE still skips the guard (got {decision})"))

    # Republishing the checkout is a write to the live hooks, even though the
    # command line does not contain the install directory.
    manifest = SRC / "jev-install.json"
    source = Path("/tmp/jev-security-source")
    manifest.write_text(json.dumps({"source_repo": str(source)}) + "\n")
    try:
        Path(log_path).write_text("")
        proc = run_gate(
            payload("Bash", {"command": "./install.sh"}, str(source)),
            quiet_env(log_path),
        )
        decision, _reason = decision_of(proc)
        results.append((decision == "deny", f"install.sh from the published checkout is denied (got {decision})"))
        results.append(
            (
                any(row.get("protected") == "hooks" for row in records(log_path)),
                "install.sh is logged as a hook-tree write",
            )
        )
        Path(log_path).write_text("")
        proc = run_gate(
            payload("Bash", {"command": "./install.sh"}, "/tmp/some-other-project"),
            quiet_env(log_path),
        )
        decision, _reason = decision_of(proc)
        results.append(
            (decision == "allow", f"install.sh in an unrelated project is not the gate (got {decision})")
        )
    finally:
        manifest.unlink(missing_ok=True)

    # Once the live hooks are the published copy, a relative src/ path in the
    # checkout is ordinary development and must not be denied.
    results.append(
        (
            jev_gate._invokes_reinstall("python3 install.sh", "/proj/the-jev-enator", Path("/proj/the-jev-enator")),
            "python3 install.sh from the published checkout counts as a republish",
        )
    )
    results.append(
        (
            not jev_gate._invokes_reinstall("python3 install.sh", "/proj/other", Path("/proj/the-jev-enator")),
            "python3 install.sh in another project is left alone",
        )
    )

    outside = jev_gate._bash_category(
        "cat src/app.py",
        "/proj/app",
        [Path("/home/example/.local/share/jev-enator/abc")],
        Path("/tmp/jev-log.jsonl"),
        None,
    )
    inside = jev_gate._bash_category(
        "cat src/jev_gate.py",
        "/proj/the-jev-enator",
        [Path("/proj/the-jev-enator/src")],
        Path("/tmp/jev-log.jsonl"),
        None,
    )
    results.append((outside is None, "a project src/ is not the published copy"))
    results.append((inside == "hooks", "the same relative path is denied when that src/ is the live gate"))
    return results


def case_unusable_replies():
    """A reply that is not a score for every asked question never becomes a verdict."""
    questions = {"destructive": NOUL, "outside_workspace": NOUL}
    choice_questions = {"failure_kind": CHOICE, "output_shows_failure": NOUL}
    results = []

    def parse(answers, asked=questions):
        return jev_client.parse_answers(answers, asked)

    def raises(label, answers, needle, asked=questions):
        try:
            parse(answers, asked)
        except JevReplyError as exc:
            results.append((needle in str(exc), f"{label}: {exc}"))
            return
        except Exception as exc:  # noqa: BLE001
            results.append((False, f"{label}: raised {type(exc).__name__}, not JevReplyError"))
            return
        results.append((False, f"{label}: accepted {answers!r}"))

    raises("missing question", {"destructive": {"noul": 0.1}}, "missing answers")
    raises("noul field absent", {"destructive": {}, "outside_workspace": {"noul": 0.1}}, "no noul")
    raises("noul null", {"destructive": {"noul": None}, "outside_workspace": {"noul": 0.1}}, "no noul")
    raises("noul string", {"destructive": {"noul": "0.97"}, "outside_workspace": {"noul": 0.1}}, "str")
    raises("noul bool", {"destructive": {"noul": True}, "outside_workspace": {"noul": 0.1}}, "bool")
    raises("noul above 1", {"destructive": {"noul": 1.7}, "outside_workspace": {"noul": 0.1}}, "[0, 1]")
    raises("noul below 0", {"destructive": {"noul": -0.1}, "outside_workspace": {"noul": 0.1}}, "[0, 1]")
    raises("answers list", [{"noul": 0.1}], "list")
    raises("answers missing", None, "missing")
    raises(
        "choice sums to 0.5",
        {
            "failure_kind": {"probabilities": {"transient": 0.2, "other": 0.3}},
            "output_shows_failure": {"noul": 0.4},
        },
        "sum to",
        choice_questions,
    )
    raises(
        "choice probability above 1",
        {
            "failure_kind": {"probabilities": {"transient": 1.2, "other": -0.2}},
            "output_shows_failure": {"noul": 0.4},
        },
        "[0, 1]",
        choice_questions,
    )
    raises(
        "choice with no probabilities",
        {"failure_kind": {"type": "choice"}, "output_shows_failure": {"noul": 0.4}},
        "no probabilities",
        choice_questions,
    )

    try:
        scores = parse(
            {"destructive": {"noul": 0}, "outside_workspace": {"noul": 1}},
        )
        results.append(
            (
                scores == {"destructive": 0.0, "outside_workspace": 1.0},
                f"0 and 1 are real probabilities (got {scores})",
            )
        )
    except JevReplyError as exc:
        results.append((False, f"0 and 1 were rejected: {exc}"))

    try:
        scores = parse(
            {
                "failure_kind": {"type": "choice", "probabilities": {"transient": 0.25, "other": 0.75}},
                "output_shows_failure": {"noul": 0.5},
            },
            choice_questions,
        )
        total = sum(scores["failure_kind"].values())
        results.append((abs(total - 1.0) < 1e-9, f"a real choice distribution is kept (sum {total})"))
    except JevReplyError as exc:
        results.append((False, f"a valid choice was rejected: {exc}"))

    # Through ask_jev, with urlopen replaced. These used to crash the hook or
    # land in the log as scores.
    bodies = [
        ("null body", b"null", "expected an object"),
        ("top-level list", b"[1]", "list"),
        ("answers list", b'{"answers": []}', "list"),
        ("truncated JSON", b'{"answers":', "unreadable"),
        ("HTML body", b"<html>nope</html>", "unreadable"),
        ("empty body", b"", "empty"),
        ("NaN", b'{"answers": {"destructive": {"noul": NaN}, "outside_workspace": {"noul": 0.1}}}', "unreadable"),
        (
            "Infinity",
            b'{"answers": {"destructive": {"noul": Infinity}, "outside_workspace": {"noul": 0.1}}}',
            "unreadable",
        ),
    ]

    def ask(raw: bytes):
        with _no_replay(), patch("jev_client.urllib.request.urlopen", return_value=_Body(raw)):
            return jev_client.ask_jev("state", questions, "not-a-real-key")

    for label, raw, needle in bodies:
        try:
            ask(raw)
        except JevReplyError as exc:
            results.append((needle in str(exc), f"{label}: {exc}"))
        except JevError as exc:
            results.append((False, f"{label}: JevError, so the gate would fail open ({exc})"))
        except Exception as exc:  # noqa: BLE001
            results.append((False, f"{label}: crashed with {type(exc).__name__}: {exc}"))
        else:
            results.append((False, f"{label}: treated as a verdict"))

    try:
        with _no_replay(), patch("jev_client.urllib.request.urlopen", return_value=_Incomplete()):
            jev_client.ask_jev("state", questions, "not-a-real-key")
    except JevReplyError:
        results.append((True, "truncated body is an unusable reply"))
    except Exception as exc:  # noqa: BLE001
        results.append((False, f"truncated body crashed with {type(exc).__name__}: {exc}"))
    else:
        results.append((False, "truncated body was treated as a verdict"))

    try:
        err = urllib.error.HTTPError(
            "https://api.typesafe.ai/v1/systemone",
            500,
            "err",
            email.message.Message(),
            io.BytesIO(b"down"),
        )
        with _no_replay(), patch("jev_client.urllib.request.urlopen", side_effect=err):
            jev_client.ask_jev("state", questions, "not-a-real-key")
    except JevReplyError as exc:
        results.append((False, f"HTTP 500 was an unusable reply ({exc})"))
    except JevError as exc:
        results.append(("HTTP 500" in str(exc), f"HTTP 500 stays a transport error ({exc})"))
    except Exception as exc:  # noqa: BLE001
        results.append((False, f"HTTP 500 crashed with {type(exc).__name__}: {exc}"))
    else:
        results.append((False, "HTTP 500 was treated as a verdict"))

    good = json.dumps(
        {"answers": {"destructive": {"noul": 0.25}, "outside_workspace": {"noul": 0.5}}, "usage": {}}
    ).encode()
    try:
        scores, _ms, _usage = ask(good)
        results.append(
            (
                scores == {"destructive": 0.25, "outside_workspace": 0.5},
                f"a complete reply is returned as scores (got {scores})",
            )
        )
    except JevError as exc:
        results.append((False, f"a complete reply was rejected: {exc}"))
    return results


def case_gate_asks_on_unusable_reply():
    """The danger gate asks. It does not allow, and it does not crash."""
    log_path = fixture_log("security-reply")
    project = "/tmp/jev-security-project"
    base = payload("Bash", {"command": "npm test", "description": "Run tests"}, project)
    results = []

    def run(side_effect=None, returned=None):
        Path(log_path).write_text("")
        buf = io.StringIO()
        env = quiet_env(log_path)
        env["TYPESAFE_API_KEY"] = "not-a-real-key"
        kwargs = {}
        if side_effect is not None:
            kwargs["side_effect"] = side_effect
        if returned is not None:
            kwargs["return_value"] = returned
        with patch.dict(os.environ, env, clear=True), patch("sys.stdin", io.StringIO(json.dumps(base))), patch(
            "sys.stdout", buf
        ), patch("jev_gate.ask_jev", **kwargs):
            try:
                jev_gate.main()
            except SystemExit as exc:
                code = exc.code
            else:
                code = None
        return code, buf.getvalue(), records(log_path)

    code, out, rows = run(side_effect=JevReplyError("missing answers: destructive"))
    decision, reason = decision_of(type("P", (), {"stdout": out})())
    results.append((code == 0 and decision == "ask", f"invalid reply asks (code {code}, {decision})"))
    results.append((BRAND in reason, "the ask names itself"))
    results.append(
        (
            any(row.get("error_class") == "invalid_reply" for row in rows),
            "invalid reply is logged as invalid_reply",
        )
    )
    results.append(
        (not any("scores" in row and "error" not in row for row in rows), "invalid reply is not logged as scores")
    )

    # The old failure: a partial map was scored from the keys that came back,
    # so a high `destructive` with everything else missing was a real deny or,
    # with the missing ones read as 0, a real allow. Neither is a verdict.
    partial = ({"destructive": 0.99}, 12, {})
    code, out, rows = run(returned=partial)
    decision, _reason = decision_of(type("P", (), {"stdout": out})())
    results.append((decision == "ask", f"partial scores ask rather than deny or allow (got {decision})"))
    results.append(
        (
            any(row.get("error_class") == "invalid_reply" for row in rows),
            "partial scores are logged as invalid_reply",
        )
    )

    code, out, rows = run(side_effect=JevError("timed out after 12s"))
    decision, _reason = decision_of(type("P", (), {"stdout": out})())
    results.append((code == 0 and decision == "allow", f"a transport error still fails open (got {decision})"))
    results.append(
        (
            any(row.get("error") and row.get("error_class") == "error" for row in rows),
            "a transport error is logged",
        )
    )

    # Top-level catch: a crash logs and asks, instead of exiting 1 with no JSON.
    Path(log_path).write_text("")
    buf = io.StringIO()

    def boom():
        raise RuntimeError("sensor fell off")

    env = quiet_env(log_path)
    with patch.dict(os.environ, env, clear=True), patch("sys.stdout", buf):
        try:
            jev_client.guard_main("gate", boom, jev_gate._ask_on_crash)
        except SystemExit as exc:
            code = exc.code
        else:
            code = None
    decision, reason = decision_of(type("P", (), {"stdout": buf.getvalue()})())
    rows = records(log_path)
    results.append((code == 0 and decision == "ask", f"a crash asks (code {code}, {decision})"))
    results.append((BRAND in reason, "the crash ask names itself"))
    results.append(
        (
            any(row.get("error_class") == "crash" and "RuntimeError" in row.get("error", "") for row in rows),
            "a crash is logged with error_class crash",
        )
    )

    for name in HOOKS:
        hook = name.removesuffix(".py").removeprefix("jev_")
        text = (SRC / name).read_text()
        results.append((f'guard_main("{hook}"' in text, f"{name} calls guard_main"))
    return results


def case_total_deadline():
    """A read that blocks past TIMEOUT_S cannot hold the call for the whole block."""
    results = []
    questions = {"destructive": NOUL}
    raw = b'{"answers": {"destructive": {"noul": 0.2}}}'
    old = jev_client.TIMEOUT_S
    jev_client.TIMEOUT_S = 0.3
    try:
        started = time.monotonic()
        try:
            with _no_replay(), patch("jev_client.urllib.request.urlopen", return_value=_SlowBody(1.5)):
                jev_client.ask_jev("state", questions, "not-a-real-key")
        except JevError as exc:
            elapsed = time.monotonic() - started
            results.append(("timed out" in str(exc), f"slow read raises a timeout ({exc})"))
            results.append((elapsed < 1.0, f"slow read returned in {elapsed:.2f}s, under the blocked read"))
        except Exception as exc:  # noqa: BLE001
            results.append((False, f"slow read crashed with {type(exc).__name__}: {exc}"))
        else:
            elapsed = time.monotonic() - started
            results.append((False, f"slow read was treated as a verdict after {elapsed:.2f}s"))

        try:
            with _no_replay(), patch("jev_client.urllib.request.urlopen", return_value=_Body(raw)):
                scores, _ms, _usage = jev_client.ask_jev("state", questions, "not-a-real-key")
            results.append((scores.get("destructive") == 0.2, f"a fast reply still returns scores (got {scores})"))
        except JevError as exc:
            results.append((False, f"a fast reply was rejected: {exc}"))
    finally:
        jev_client.TIMEOUT_S = old

    results.append(
        (
            jev_client.HOOK_TIMEOUT_S >= jev_client.TIMEOUT_S + 5,
            f"hook timeout {jev_client.HOOK_TIMEOUT_S}s is above the {jev_client.TIMEOUT_S}s deadline",
        )
    )
    return results


CASES = [
    ("self-edit guard denies before Jev", case_self_edit_guard),
    ("unusable replies are not verdicts", case_unusable_replies),
    ("the danger gate asks when the reply is unusable", case_gate_asks_on_unusable_reply),
    ("the Jev request has a total deadline", case_total_deadline),
]


def main() -> int:
    failures = 0
    for label, fn in CASES:
        print(f"\n{label}")
        try:
            results = fn()
        except Exception as exc:  # noqa: BLE001 -- a crashing case is a failing case
            print(f"  FAIL  case raised {type(exc).__name__}: {exc}")
            failures += 1
            continue
        for ok, detail in results:
            if not ok:
                failures += 1
            print(f"  {'PASS' if ok else 'FAIL'}  {detail}")
    print()
    if failures:
        print(f"{failures} assertion(s) failed")
    else:
        print("all assertions passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
