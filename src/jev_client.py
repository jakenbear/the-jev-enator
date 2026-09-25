#!/usr/bin/env python3
"""Shared Jev (TypeSafe System One) client for Claude Code hooks.

Standard library only. Every hook in this repo goes through ask_jev(), so TLS
handling, timeouts, logging, and the fail-open contract live in one place.
"""

import hashlib
import http.client
import json
import math
import os
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

API_URL = "https://api.typesafe.ai/v1/systemone"
MODEL = "jev-latest"

# Typical latency is ~350ms, but cold starts have been observed above 6s.
# Generous enough to avoid failing open on a slow call, short enough that a
# genuinely hung API doesn't stall the session.
#
# This is a total deadline, not a per-read socket timeout. urllib's timeout
# resets on every recv, so a server that trickles bytes never trips it, and
# DNS is not covered at all. A PreToolUse hook that instead hits Claude Code's
# own timeout does not block the tool call, and that default is 600s.
# install.sh writes HOOK_TIMEOUT_S onto each hook, above this deadline by
# enough to cover interpreter startup. A circuit breaker for repeated
# timeouts is issue #38 and is deliberately not implemented here.
TIMEOUT_S = 12.0
HOOK_TIMEOUT_S = 20

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
    """A failure the calling hook can recover from without crashing.

    Network errors, timeouts, and HTTP errors use this class. The danger gate
    fails open on those: it logs and emits no decision. A reply that arrived
    but is not a verdict for every asked question is a JevReplyError. The gate
    turns that into ask, because a score we could not read is not "safe"
    (issue #35).
    """

    error_class = "error"


class JevReplyError(JevError):
    """The server replied, but not with a usable score for every question."""

    error_class = "invalid_reply"


# --- Environment ----------------------------------------------------------
#
# These four settings are read by all three hooks, so the GATE in their old
# names was wrong rather than merely stale: JEV_GATE_DISABLE also silences the
# notice and the completion check, which is not what anyone setting a variable
# named after the gate would expect. JEV_GATE_EXTRA_TOOLS keeps its name, since
# it really is gate-only.
#
# The old names keep working. Someone whose settings.json says JEV_GATE_LOG
# would otherwise get a hook that silently stops logging -- no error, just an
# audit trail that quietly ends, which is the failure this repo exists to argue
# against. LEGACY_ENV maps new name -> old name.
LEGACY_ENV = {
    "JEV_LOG": "JEV_GATE_LOG",
    "JEV_DISABLE": "JEV_GATE_DISABLE",
    "JEV_REPLAY": "JEV_GATE_REPLAY",
    "JEV_RECORD": "JEV_GATE_RECORD",
}

# Default audit log path, and the pre-rename one. Order matters: readers prefer
# the new file but must keep finding an existing old one, because a log nobody
# can find is indistinguishable from a log that was never written.
LOG_NAME = "jev-enator.jsonl"
LEGACY_LOG_NAME = "jev-gate.jsonl"


def env_var(name: str) -> str | None:
    """Read a setting by its current name, falling back to the pre-rename one.

    Empty string is treated as unset for the new name so that explicitly
    clearing JEV_LOG cannot resurrect a stale JEV_GATE_LOG from settings.json --
    a redirect that came back from the dead would send fixture scores into a
    real audit log, which is the bug tests/fixture_env.py exists to prevent.
    """
    value = os.environ.get(name)
    if value:
        return value
    legacy = LEGACY_ENV.get(name)
    return os.environ.get(legacy) if legacy else None


def legacy_env_in_use() -> list[str]:
    """Old variable names that are set while their replacement is not.

    verify.sh check 5b reports these. A fallback that works but is never
    mentioned is how a deprecated name outlives the thing it was renamed from.

    verify.sh had its own inline copy of this loop for a while, which is the same
    two-copies-of-one-rule shape as issue #2 -- there the hardcoded tool matcher
    drifted from the real one and MultiEdit stopped being gated. Adding a name to
    LEGACY_ENV should not require remembering a shell script also knows the rule.
    """
    return sorted(
        old
        for new, old in LEGACY_ENV.items()
        if os.environ.get(old) and not os.environ.get(new)
    )


def default_log_path() -> str:
    """Where to log when nothing says otherwise.

    An existing pre-rename log wins. Defaulting to the new filename on a machine
    that already has history would split the trail across two files, and
    report.sh's totals are the argument for enforcement -- they have to cover
    everything that happened, not everything since the rename.
    """
    home = os.path.expanduser("~")
    legacy = os.path.join(home, LEGACY_LOG_NAME)
    if os.path.exists(legacy) and not os.path.exists(os.path.join(home, LOG_NAME)):
        return legacy
    return os.path.join(home, LOG_NAME)


def source_fingerprint(source_dir: Path | None = None) -> str:
    """Content hash of the hook sources.

    install.sh names the published copy with this, so two different versions
    never share a directory and an edit to the checkout does not overwrite
    the copy Claude Code is running.
    """
    directory = source_dir or Path(__file__).resolve().parent
    digest = hashlib.sha256()
    files = sorted(path for path in directory.glob("*.py") if path.is_file())
    if not files:
        raise SystemExit(f"jev install: no hook sources in {directory}")
    for path in files:
        digest.update(path.name.encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()[:16]


def hook_install_root(home: str | os.PathLike | None = None) -> Path:
    """Directory that holds every published copy. Not the git checkout."""
    base = Path(home) if home is not None else Path.home()
    return base / ".local" / "share" / "jev-enator"


def hook_install_dir(home: str | os.PathLike | None = None, source_dir: Path | None = None) -> Path:
    """Where install.sh puts the hooks Claude Code actually runs.

    A separate tree from the checkout: editing src/ in the repo must not
    change the live gate. The leaf is a fingerprint of the sources.
    """
    return hook_install_root(home) / source_fingerprint(source_dir)


def disabled() -> bool:
    return env_var("JEV_DISABLE") == "1"


def api_key() -> str | None:
    # In replay mode no request is made, so a key would only be a barrier to
    # running the suites. This is what lets CI and a first-time contributor run
    # them with no account at all.
    if env_var("JEV_REPLAY"):
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
    return env_var("JEV_REPLAY")


def _load_cassette(path: str) -> dict:
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        # Not a JevError: a broken cassette is a broken test harness, and
        # failing open here would let CI pass while checking nothing.
        raise SystemExit(f"jev replay: cannot read {path}: {exc}")


def _reject_nonfinite(constant: str):
    """json.loads accepts NaN and Infinity unless this rejects them.

    A NaN score compares false against every threshold, so it would be logged
    as a real verdict and the call allowed. It is not a probability.
    """
    raise ValueError(f"non-finite number: {constant}")


def _unit_interval(value, label: str) -> float:
    """A probability: a finite float in [0, 1]. Booleans are ints; reject them."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        got = "null" if value is None else type(value).__name__
        raise JevReplyError(f"{label} is {got}, expected a number in [0, 1]")
    number = float(value)
    if not math.isfinite(number) or number < 0.0 or number > 1.0:
        raise JevReplyError(f"{label} is not a finite probability in [0, 1]")
    return number


# Choice probabilities are a distribution. The API says they sum to 1. Allow
# a little rounding and reject one that is not a distribution (issue #35).
CHOICE_SUM_TOLERANCE = 0.02


def parse_answers(answers, questions: dict) -> dict:
    """Map every asked question to a validated score, or raise JevReplyError.

    A noul score is a float. A choice score is label -> probability. Every
    asked name must be present and readable. A missing noul used to become
    0.0, which is "definitely safe" for every question in this repo, and a
    partial map used to be logged as a real verdict (issue #35).
    """
    if not isinstance(answers, dict):
        kind = "missing" if answers is None else type(answers).__name__
        raise JevReplyError(f"answers was {kind}, expected an object")
    missing = [name for name in questions if name not in answers]
    if missing:
        raise JevReplyError("missing answers: " + ", ".join(sorted(missing)))
    return {
        name: _score_one(name, spec if isinstance(spec, dict) else {}, answers[name])
        for name, spec in questions.items()
    }


def _score_one(name: str, spec: dict, answer):
    if not isinstance(answer, dict):
        raise JevReplyError(f"{name}: answer was {type(answer).__name__}, expected an object")
    if spec.get("type", "noul") == "choice":
        probs = answer.get("probabilities")
        if not isinstance(probs, dict) or not probs:
            raise JevReplyError(f"{name}: choice answer has no probabilities")
        parsed = {
            str(label): _unit_interval(value, f"{name}.{label}") for label, value in probs.items()
        }
        total = sum(parsed.values())
        if abs(total - 1.0) > CHOICE_SUM_TOLERANCE:
            raise JevReplyError(f"{name}: choice probabilities sum to {total:.3f}, not 1")
        return parsed
    if "noul" not in answer or answer.get("noul") is None:
        raise JevReplyError(f"{name}: noul answer has no noul")
    return _unit_interval(answer.get("noul"), name)


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
        raw = _read_body(req, ssl_context())
        result = _parse_body(raw)
        scores = parse_answers(result.get("answers"), questions)
    except JevError:
        raise
    except (http.client.HTTPException, json.JSONDecodeError, ValueError, AttributeError) as exc:
        # A crash while reading the reply used to kill the hook with no audit
        # line. Claude Code then lets the tool call run.
        raise JevReplyError(str(exc)) from exc

    elapsed_ms = round((time.monotonic() - started) * 1000)

    # Recording is a side effect of a normal live call, so what gets recorded is
    # exactly what the suites just ran against -- there is no separate code path
    # that could record something the tests never exercised.
    record = env_var("JEV_RECORD")
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


def _parse_body(raw: bytes) -> dict:
    """Decode a response body into an object, or raise JevReplyError.

    The message stays generic on purpose: the body can echo the state, and
    the state can contain a secret. The log records that the reply was
    unusable, not the reply.
    """
    if not raw or not raw.strip():
        raise JevReplyError("empty response body")
    try:
        text = raw.decode()
    except UnicodeDecodeError as exc:
        raise JevReplyError("unreadable response") from exc
    try:
        result = json.loads(text, parse_constant=_reject_nonfinite)
    except (json.JSONDecodeError, ValueError) as exc:
        raise JevReplyError("unreadable response") from exc
    if not isinstance(result, dict):
        raise JevReplyError(f"response was {type(result).__name__}, expected an object")
    return result


def _read_body(req, context) -> bytes:
    """Read the response body within TIMEOUT_S for the whole request.

    The worker is a daemon so a slow read cannot keep the hook process alive
    after the deadline. join() is the deadline; the socket timeout is only a
    hint to a peer that checks it.
    """
    box: dict = {}
    limit = TIMEOUT_S

    def run() -> None:
        try:
            with urllib.request.urlopen(req, timeout=limit, context=context) as resp:
                box["body"] = resp.read()
        except urllib.error.HTTPError as exc:
            try:
                detail = exc.read().decode(errors="replace")[:500]
            except (OSError, http.client.HTTPException):
                detail = ""
            box["http"] = (exc.code, detail)
        except Exception as exc:  # noqa: BLE001 -- converted to JevError below
            box["error"] = exc

    worker = threading.Thread(target=run, name="jev-request", daemon=True)
    worker.start()
    worker.join(limit)
    if worker.is_alive():
        raise JevError(f"timed out after {limit:g}s")
    if "http" in box:
        code, detail = box["http"]
        raise JevError(f"HTTP {code}: {detail}")
    if "error" in box:
        exc = box["error"]
        # IncompleteRead and a truncated body are an unusable reply. A down
        # network is not: that still fails open.
        if isinstance(exc, (http.client.HTTPException, json.JSONDecodeError, ValueError, AttributeError)):
            raise JevReplyError(str(exc)) from exc
        raise JevError(str(exc)) from exc
    body = box.get("body")
    if body is None:
        raise JevReplyError("empty response body")
    return body


_CLI_FLAGS = {"--matcher", "--report"}


def guard_main(hook: str, main, fail) -> None:
    """Run a hook and log any crash instead of dying with no decision.

    Claude Code treats a hook that exits non-zero with no JSON as non-blocking,
    so an uncaught exception is a silent allow and it leaves no audit line.
    `fail` is that hook's failure behaviour: the danger gate asks, and the
    others emit nothing. `--matcher` and `--report` are command-line uses;
    a crash there should still be a non-zero exit.
    """
    try:
        main()
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001 -- the whole point is the last-resort catch
        log(
            {
                "hook": hook,
                "error": f"{type(exc).__name__}: {exc}",
                "error_class": "crash",
            }
        )
        if _CLI_FLAGS.intersection(sys.argv[1:]):
            print(f"{type(exc).__name__}: {exc}", file=sys.stderr)
            raise SystemExit(1) from exc
        fail()


def log(record: dict) -> None:
    """Append one JSONL audit line. Never raises."""
    path = env_var("JEV_LOG")
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
