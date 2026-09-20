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


# --- Branding -------------------------------------------------------------
#
# Every message these hooks emit is prefixed so it is instantly identifiable as
# coming from The Jev-enator and not from Claude Code itself, the tool that ran,
# or the model's own reasoning. Before this, a blocked call read as a generic
# permission error and people reasonably assumed Claude Code had refused.
#
# Two levels, because the audiences differ:
#
#   banner()  goes to a human, in a terminal, rarely. A blocked tool call is the
#             one moment this tool is the most annoying thing on screen, so it
#             gets to look like something rather than like a stack trace.
#
#   tag()     goes into the model's context, on every single Bash call. It stays
#             on one line. A multi-line ASCII banner there would be tokens spent
#             on decoration in the hot path, repeated hundreds of times a day.
#
# ART is deliberately narrow (11 cols) so it survives a split pane.
ART = "[ ⊙ ─ ]"

# Plain text, no ANSI. Claude Code renders permissionDecisionReason itself, and
# escape codes either show as literal garbage or get stripped -- verified while
# debugging report.sh, where color codes broke a grep that looked correct.
BRAND = "THE JEV-ENATOR"


def banner(headline: str, verdict: str) -> str:
    """Human-facing header for a decision that interrupts someone.

    verdict is a short all-caps word: TERMINATED, FLAGGED. headline is the
    one-line summary that follows it.
    """
    return f"{ART} {BRAND} · {verdict}\n{headline}"


def tag(hook: str, elapsed_ms: int) -> str:
    """One-line prefix for context injected into the model's transcript."""
    return f"{ART} jev-{hook} · {elapsed_ms}ms"


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

    The type is part of the key. Without it, changing a question from noul to
    choice under the same name keeps the old key, so replay serves a float where
    the caller now expects a distribution -- a stale recording passing as fresh,
    which is the one failure a cassette must never have.
    """
    shape = ",".join(f"{name}:{questions[name].get('type', 'noul')}" for name in sorted(questions))
    payload = state + "\x00" + shape
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


def parse_answers(answers: dict) -> dict:
    """Flatten an API answers block to name -> score.

    A `noul` answer is a single probability, so its score is a float. A `choice`
    answer is a distribution over labels, so its score is a dict of
    label -> probability. Callers that only ask noul questions see no difference.

    Keeping the full distribution rather than just the winning label is the whole
    reason to use choice: the margin between first and second place is the signal
    that three independent binaries threw away.
    """
    scores = {}
    for name, answer in answers.items():
        if not isinstance(answer, dict):
            continue
        if answer.get("type") == "choice" or "probabilities" in answer:
            probs = answer.get("probabilities") or {}
            # An empty distribution is not a zero-confidence answer, it is a
            # response we cannot read. Skip it so the caller's "did I get an
            # answer" check fails rather than silently seeing no options.
            if probs:
                scores[name] = {k: float(v) for k, v in probs.items()}
        else:
            scores[name] = answer.get("noul", 0.0)
    return scores


def top_two(dist: dict) -> tuple[str, float, float]:
    """Return (winning label, its probability, runner-up probability).

    Returns ("", 0.0, 0.0) for an empty distribution. The runner-up is 0.0 when
    there is only one option, which makes the margin the winner's own probability
    -- correct, since a single-option choice has nothing to be confused with.
    """
    if not dist:
        return "", 0.0, 0.0
    ranked = sorted(dist.items(), key=lambda kv: kv[1], reverse=True)
    label, top = ranked[0]
    second = ranked[1][1] if len(ranked) > 1 else 0.0
    return label, float(top), float(second)


def ask_jev(state: str, questions: dict, key: str) -> tuple[dict, int, dict]:
    """Return (scores, latency_ms, usage).

    scores maps question name -> probability (noul) or to a dict of
    label -> probability (choice). Raises JevError on any failure so the caller
    can fail open.
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
    scores = parse_answers(result.get("answers", {}))
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
