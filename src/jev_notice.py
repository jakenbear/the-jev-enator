#!/usr/bin/env python3
"""Jev-backed PostToolUse notice for Claude Code.

Reads the output of a Bash call and, if it contains a failure, says so in the
agent's context before the agent gets to interpret it.

This is the one hook in this repo aimed at making the agent better rather than
stopping it doing damage. The failure mode it targets is real and common: a test
runner exits 0 while printing failures, `| tail -3` truncates the failure off
the screen, a build prints one error under two hundred warnings. The agent skims
the visible part, sees nothing red, and reports success.

It does not block. It injects a plain sentence, which is the whole point -- the
correction lands while there is still time to act on it, instead of costing the
user a turn afterwards.

When a failure is found it also classifies the kind -- transient, missing
dependency, wrong invocation, or needs a code change -- and names the matching
recovery. That saves the agent re-deriving from the same output what a cheap
classifier already knows: a 429 wants a retry, not an edit. The limit is real and
worth stating: a hook can only inject text, so it suggests the recovery and
cannot perform it.

The kind is one `choice` question returning a distribution over the four, rather
than three independent yes/no questions. Three binaries cannot be compared to one
another, so picking between them needed a hardcoded priority order that let a
weak first-listed answer beat a strong later one.

Fails open: any error, timeout, or missing key emits nothing.

Env:
  TYPESAFE_API_KEY   required, else the hook no-ops
  JEV_GATE_LOG       optional path for a JSONL audit log
  JEV_GATE_DISABLE   set to 1 to bypass entirely
  JEV_NOTICE_OFF     set to 1 to disable just this hook
"""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from jev_client import JevError, api_key, ask_jev, disabled, log, read_payload, tag, top_two

# Below this, there is nothing to misread. Saves a call on the many Bash results
# that are a single line or empty.
MIN_OUTPUT_CHARS = 40

# Jev is priced per input token, and command output is the largest state in this
# repo. Keep the head and the tail: the head holds compile errors, the tail holds
# test summaries, and the middle is usually a file list.
MAX_HEAD = 4000
MAX_TAIL = 4000

# Say something at all.
NOTICE_AT = 0.85
# Say it emphatically: the output is shaped so that skimming it would give the
# wrong impression, which is exactly when a reminder changes the outcome.
EMPHATIC_AT = 0.45

# Name the kind of failure. Lower bar than NOTICE_AT on purpose: by the time we
# are here a failure is already established, so this only picks which of several
# recoveries to name. Guessing "transient" costs a retry; staying silent costs a
# reasoning call that re-derives what the output already said.
#
# The margin is what actually decides, and it must win clearly rather than merely
# place first. With three independent binaries this check could not be written at
# all, so a fixed priority order stood in for it and a 0.61 "transient" beat a
# 0.94 "wrong invocation" purely for being listed earlier.
#
# KIND_AT is 0.45 and not higher for a reason worth recording: with four options,
# any top over 0.50 already forces second place under 0.50, so a bar of 0.60 makes
# the margin check unreachable -- proven by deleting it and watching all 19
# fixtures still pass. A bar that high IS the margin check, just a cruder one. So
# the bar drops to "more likely than not, roughly" and the margin does the real
# work. An observed honest tie -- a Docker daemon that is down, which is equally
# read as a missing dependency (0.49) or a transient outage (0.42) -- stays silent
# on the margin, which is correct: a human could not call that one either.
KIND_AT = 0.45
KIND_MARGIN = 0.20

QUESTIONS = {
    "output_shows_failure": {
        "type": "noul",
        "instructions": (
            "Does this command output report a failure, error, or unmet "
            "expectation that the developer needs to act on?"
        ),
        "criteria": {
            "true": (
                "A failing test or assertion; a compile or type error; a stack "
                "trace or unhandled exception; a non-zero failure count; a "
                "linter error as opposed to a warning; 'command not found'; a "
                "connection refused or permission denied; output that is "
                "truncated in a way that shows a failure count without showing "
                "which tests failed."
            ),
            "false": (
                "All tests passing; a clean build; a successful install; "
                "deprecation warnings or peer-dependency notices with no error; "
                "informational log lines; a linter reporting only warnings; "
                "normal output of a read-only command such as git status, ls, "
                "or grep finding no matches."
            ),
        },
    },
    "exit_status_misleads": {
        "type": "noul",
        "instructions": (
            "Would someone skimming this output conclude the command succeeded "
            "when it actually did not?"
        ),
        "criteria": {
            "true": (
                "The command exited 0 but the output text contains failures; a "
                "failure appears early and is followed by many lines of normal "
                "output; the output is piped through tail or head so the "
                "failure detail is cut off and only a summary count remains; a "
                "test runner reports 'Tests: 1 failed, 3 passed' with no other "
                "visible sign of a problem."
            ),
            "false": (
                "The failure is stated plainly and prominently, so it cannot be "
                "missed; or there is no failure at all and the output is "
                "genuinely a success."
            ),
        },
    },
    # One question, not three, because the kinds are mutually exclusive and a
    # `choice` returns a distribution over them rather than three unrelated
    # binaries. That distinction is the whole fix: three binaries give no way to
    # compare confidences, so the old code walked them in a hardcoded order and a
    # barely-there 0.61 beat a near-certain 0.94 that happened to be listed
    # second. The distribution is calibrated across the options, so the winner is
    # the winner and the margin over second place is a real number.
    #
    # Asked in the same request as the two above -- Jev is priced per input token
    # and the command output is the expensive part, so this costs barely more than
    # asking nothing.
    #
    # needs_code_change is the escape hatch, and having it is what makes the
    # others honest. Without a "none of the above" option the probability mass has
    # to land somewhere, so an ordinary assertion failure would be forced to look
    # like a bad invocation. It maps to no hint on purpose: an agent facing a real
    # test failure needs to read the diff, and there is no shortcut to suggest.
    "failure_kind": {
        "type": "choice",
        "instructions": (
            "What is the underlying cause of this command failure, and therefore "
            "what kind of fix does it need?"
        ),
        "criteria": {
            "transient": (
                "The cause is outside the code and re-running the same command "
                "unchanged is the right next step. A network timeout, connection "
                "reset, or DNS failure; an HTTP 429, 502, 503, or 504; a rate "
                "limit or throttling message, including one asking you to retry "
                "after a delay; a lock held by another process; a service still "
                "starting up; 'temporarily unavailable'; a test that failed on "
                "timing. Choose this even if a first retry might also fail; what "
                "matters is that no edit is needed."
            ),
            "missing_dependency": (
                "Something is not installed or not present in the environment. "
                "'command not found'; 'No module named X'; 'Cannot find module'; "
                "'Module not found: Can't resolve'; an unresolved import; a "
                "missing binary, package, virtualenv, or system library; a "
                "missing environment variable or unset credential."
            ),
            "wrong_invocation": (
                "The command as written is wrong, independent of the code it "
                "ran. An unknown flag or option; a bad or misspelled subcommand; "
                "a usage or argument-count error; a path that does not exist "
                "because it was mistyped or was relative to the wrong directory; "
                "a glob that matched nothing."
            ),
            "needs_code_change": (
                "The command was well formed and the environment was fine; the "
                "problem is in the code. A compile or type error; a failing "
                "assertion about values; a syntax error; an unhandled exception "
                "from a logic bug; a permission denial or bad credentials that "
                "configuration must fix. Choose this for any failure that needs "
                "a human or agent to read the output and edit something, and "
                "whenever none of the other three clearly fits."
            ),
        },
    },
}

# The recovery to suggest for each kind. This is a lookup, not a priority list:
# the distribution already decided which kind won, so the order here carries no
# meaning and changing it changes nothing.
#
# needs_code_change is deliberately absent. It is a valid answer -- often the
# right one -- and its recovery is "read the output and fix the code", which is
# what the agent was going to do anyway. Saying it adds tokens and no information.
KINDS = (
    (
        "missing_dependency",
        "Something is missing from the environment. Install or provide it rather "
        "than changing the code that depends on it.",
    ),
    (
        "transient",
        "This looks transient. Waiting briefly and re-running the same command "
        "unchanged is the cheapest next step -- do that before editing anything.",
    ),
    (
        "wrong_invocation",
        "The command itself looks wrong, not the code it ran. Check the flags, "
        "subcommand, and paths before editing any source file.",
    ),
)
HINTS = dict(KINDS)


def kind_verdict(scores: dict) -> tuple[str | None, float, float]:
    """Return (kind, probability, margin) for the winning failure kind.

    kind is None when the distribution is missing, when the winner does not clear
    KIND_AT, or when it does not beat second place by KIND_MARGIN. All three mean
    the same thing to the caller: no recovery is confident enough to name.
    """
    dist = scores.get("failure_kind")
    if not isinstance(dist, dict):
        return None, 0.0, 0.0
    label, top, second = top_two(dist)
    margin = top - second
    if top < KIND_AT or margin < KIND_MARGIN:
        return None, top, margin
    return label, top, margin


def recovery_hint(kind: str | None) -> str | None:
    """The recovery text for a winning kind, or None if there is nothing to say."""
    hint = HINTS.get(kind or "")
    return f" {hint}" if hint else None


def emit(context: str | None) -> None:
    """Inject additional context, or nothing at all."""
    if context is None:
        sys.exit(0)
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PostToolUse",
                    "additionalContext": context,
                }
            }
        )
    )
    sys.exit(0)


def tool_output(payload: dict) -> str:
    """Pull the Bash result text out of a PostToolUse payload.

    tool_response is a dict for Bash (stdout/stderr/interrupted) but hook
    payloads vary by tool and by Claude Code version, so fall back to a string.
    """
    resp = payload.get("tool_response")
    if isinstance(resp, str):
        return resp
    if isinstance(resp, dict):
        parts = [str(resp.get(k, "")) for k in ("stdout", "stderr", "output", "content")]
        joined = "\n".join(p for p in parts if p.strip())
        return joined or json.dumps(resp)[:MAX_HEAD]
    return ""


def truncate(text: str) -> str:
    if len(text) <= MAX_HEAD + MAX_TAIL:
        return text
    cut = len(text) - MAX_HEAD - MAX_TAIL
    return f"{text[:MAX_HEAD]}\n\n[... {cut} characters omitted ...]\n\n{text[-MAX_TAIL:]}"


def build_state(payload: dict, output: str) -> str:
    tool_input = payload.get("tool_input", {}) or {}
    command = tool_input.get("command", "")
    resp = payload.get("tool_response")
    code = resp.get("exit_code", "unknown") if isinstance(resp, dict) else "unknown"
    return "\n\n".join(
        [
            f"Command that was run:\n{command}",
            f"Exit code: {code}",
            f"Output:\n{truncate(output)}",
        ]
    )


def main() -> None:
    if disabled() or os.environ.get("JEV_NOTICE_OFF") == "1":
        emit(None)

    key = api_key()
    if not key:
        emit(None)

    payload = read_payload()
    if payload is None or payload.get("tool_name") != "Bash":
        emit(None)

    output = tool_output(payload)
    if len(output.strip()) < MIN_OUTPUT_CHARS:
        emit(None)

    state = build_state(payload, output)
    try:
        scores, elapsed_ms, usage = ask_jev(state, QUESTIONS, key)
    except JevError as exc:
        log({"hook": "notice", "error": str(exc)})
        emit(None)

    fail = scores.get("output_shows_failure", 0.0)
    misleads = scores.get("exit_status_misleads", 0.0)
    noticed = fail >= NOTICE_AT
    kind, kind_p, kind_margin = kind_verdict(scores)
    hint = recovery_hint(kind) if noticed else None

    # The full distribution goes into scores, and the derived kind/probability/
    # margin alongside it. Logging the margin is what makes KIND_MARGIN tunable
    # from real data instead of by guess: the near-ties are visible even when no
    # hint was named, which is exactly the population the threshold governs.
    log(
        {
            "hook": "notice",
            "scores": scores,
            "latency_ms": elapsed_ms,
            "usage": usage,
            "noticed": noticed,
            "emphatic": noticed and misleads >= EMPHATIC_AT,
            "kind": kind if noticed else None,
            "kind_p": round(kind_p, 3),
            "kind_margin": round(kind_margin, 3),
            "command": (payload.get("tool_input", {}) or {}).get("command", "")[:200],
        }
    )

    if not noticed:
        emit(None)

    if misleads >= EMPHATIC_AT:
        emit(
            f"{tag('notice', elapsed_ms)} This output contains a failure that is "
            f"easy to miss on a skim (p={fail:.2f} failure, p={misleads:.2f} "
            "misleading). The command may have exited 0, or the failure may be "
            "truncated or buried. Read the output again before describing this as "
            "working, and do not report success unless you can point to the line "
            f"that shows it.{hint or ''}"
        )
    emit(
        f"{tag('notice', elapsed_ms)} This output reports a failure "
        f"(p={fail:.2f}). Address it or say so plainly; do not describe this step "
        f"as successful.{hint or ''}"
    )


if __name__ == "__main__":
    main()
