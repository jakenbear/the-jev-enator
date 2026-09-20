#!/usr/bin/env python3
"""Shared Jev (TypeSafe System One) client for Claude Code hooks.

Standard library only. Every hook in this repo goes through ask_jev(), so TLS
handling, timeouts, logging, and the fail-open contract live in one place.
"""

import hashlib
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request

API_URL = "https://api.typesafe.ai/v1/systemone"
MODEL = "jev-latest"

# Typical latency is ~350ms, but cold starts have been observed above 6s.
# Generous enough to avoid failing open on a slow call, short enough that a
# genuinely hung API doesn't stall the session.
TIMEOUT_S = 12.0

# python.org builds ship without a usable CA bundle, so urllib fails TLS
# verification with CERTIFICATE_VERIFY_FAILED. Resolve a real bundle rather than
# trusting the interpreter default, since Claude Code may invoke a hook with any
# python on PATH.
CA_CANDIDATES = (
    os.environ.get("SSL_CERT_FILE"),
    "/etc/ssl/cert.pem",
    "/opt/homebrew/etc/ca-certificates/cert.pem",
)


class JevError(Exception):
    """Any failure that should cause the calling hook to fail open."""


def disabled() -> bool:
    return os.environ.get("JEV_GATE_DISABLE") == "1"


def api_key() -> str | None:
    # In replay mode no request is made, so a key would only be a barrier to
    # running the suites. This is what lets CI and a first-time contributor run
    # them with no account at all.
    if os.environ.get("JEV_GATE_REPLAY"):
        return os.environ.get("TYPESAFE_API_KEY") or "replay"
    return os.environ.get("TYPESAFE_API_KEY")


def read_payload() -> dict | None:
    try:
        return json.load(sys.stdin)
    except (json.JSONDecodeError, ValueError):
        return None


def ssl_context() -> ssl.SSLContext:
    for path in CA_CANDIDATES:
        if path and os.path.exists(path):
            return ssl.create_default_context(cafile=path)
    try:
        import certifi

        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()


def cassette_key(state: str, questions: dict) -> str:
    """Stable id for one (state, questions) pair.

    Hashed rather than stored plainly because states run to thousands of
    characters and contain absolute paths. Question names are included but not
    their instruction text: rewording a question should not silently invalidate
    every recording, since the whole point of a live run is to catch the score
    change that rewording causes.
    """
    payload = state + "\x00" + ",".join(sorted(questions))
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def replay_path() -> str | None:
    return os.environ.get("JEV_GATE_REPLAY") or None


def _load_cassette(path: str) -> dict:
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        # Not a JevError: a broken cassette is a broken test harness, and
        # failing open here would let CI pass while checking nothing.
        raise SystemExit(f"jev replay: cannot read {path}: {exc}")


def ask_jev(state: str, questions: dict, key: str) -> tuple[dict, int, dict]:
    """Return (scores, latency_ms, usage).

    scores maps question name -> probability. Raises JevError on any failure so
    the caller can fail open.
    """
    # Replay mode: serve a recorded response instead of calling the API, so the
    # suites run offline, deterministically, and without a key. A miss exits
    # non-zero rather than raising JevError -- fail-open is right for a hook
    # protecting a real session, and wrong for a test, where it would turn "no
    # recording for this case" into a silent pass.
    replay = replay_path()
    if replay:
        cassette = _load_cassette(replay)
        hit = cassette.get("responses", {}).get(cassette_key(state, questions))
        if hit is None:
            raise SystemExit(
                f"jev replay: no recording for this call in {replay}\n"
                f"  key:       {cassette_key(state, questions)}\n"
                f"  questions: {', '.join(sorted(questions))}\n"
                f"  state:     {state[:200]!r}\n"
                "Re-record with: tests/record_cassette.py"
            )
        scores = {k: v for k, v in hit.get("scores", {}).items()}
        if not scores:
            raise SystemExit(f"jev replay: recording has no scores for {cassette_key(state, questions)}")
        return scores, hit.get("latency_ms", 0), hit.get("usage", {})

    body = json.dumps({"model": MODEL, "state": state, "questions": questions}).encode()
    req = urllib.request.Request(
        API_URL,
        data=body,
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        method="POST",
    )

    started = time.monotonic()
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S, context=ssl_context()) as resp:
            result = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        try:
            detail = exc.read().decode()[:500]
        except OSError:
            detail = ""
        raise JevError(f"HTTP {exc.code}: {detail}") from exc
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        raise JevError(str(exc)) from exc

    elapsed_ms = round((time.monotonic() - started) * 1000)
    answers = result.get("answers", {})
    scores = {k: v.get("noul", 0.0) for k, v in answers.items()}
    if not scores:
        raise JevError("no answers in response")

    # Recording is a side effect of a normal live call, so what gets recorded is
    # exactly what the suites just ran against -- there is no separate code path
    # that could record something the tests never exercised.
    record = os.environ.get("JEV_GATE_RECORD")
    if record:
        try:
            with open(record, "a") as fh:
                fh.write(
                    json.dumps(
                        {
                            "key": cassette_key(state, questions),
                            "scores": scores,
                            "latency_ms": elapsed_ms,
                            "usage": result.get("usage", {}),
                            "state_head": state[:300],
                        }
                    )
                    + "\n"
                )
        except OSError:
            pass

    return scores, elapsed_ms, result.get("usage", {})


def log(record: dict) -> None:
    """Append one JSONL audit line. Never raises."""
    path = os.environ.get("JEV_GATE_LOG")
    if not path:
        return
    # Stamped here rather than at each call site so no hook can forget it.
    # Without a timestamp there is no way to read a log from a cutoff, which
    # is the only recourse once a log has old records you want to exclude.
    record.setdefault("ts", time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime()))
    try:
        with open(os.path.expanduser(path), "a") as fh:
            fh.write(json.dumps(record) + "\n")
    except OSError:
        pass
