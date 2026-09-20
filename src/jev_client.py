#!/usr/bin/env python3
"""Shared Jev (TypeSafe System One) client for Claude Code hooks.

Standard library only. Every hook in this repo goes through ask_jev(), so TLS
handling, timeouts, logging, and the fail-open contract live in one place.
"""

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


def ask_jev(state: str, questions: dict, key: str) -> tuple[dict, int, dict]:
    """Return (scores, latency_ms, usage).

    scores maps question name -> probability. Raises JevError on any failure so
    the caller can fail open.
    """
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
