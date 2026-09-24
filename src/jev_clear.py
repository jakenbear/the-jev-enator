#!/usr/bin/env python3
"""Jev-backed UserPromptSubmit hook: "this is a new task -- /clear first?"

WHY THIS EXISTS

./tokens.sh on one developer's transcripts: median context 112k tokens, 92% of
calls over 60k, 219 automatic compactions and zero manual ones. Every call
re-reads the whole context, so a new, unrelated task started at 140k pays 140k
tokens per call for history it will never use -- until auto-compaction fires,
which is a summary of the old task, not an empty context.

/clear fixes that for free. Nobody runs it, because nobody notices the moment
the task changed. That moment is a classification: does this prompt need the
conversation so far? Cheap, calibrated, and asked once per prompt.

WHAT IT DOES

On a prompt sent with more than MIN_CONTEXT tokens in context, it asks two
questions in one call:

  new_task        is this a separate piece of work that does not need the
                  conversation so far?
  needs_history   does it lean on earlier turns -- "that", "same for X",
                  "it broke", "carry on"?

needs_history is the veto, the same shape as jev_finish's awaiting_user_input:
a continuation phrased like a fresh request ("now add tests") is the failure
mode, and a separate question catches it better than a higher bar on one.

WHAT YOU SEE

A note, to you only, via systemMessage:

  [ ⊙ ─ ] new task at 140k context -- /clear would save ~140k tokens per call

Claude does not see it. It costs no context and cannot derail the agent, so a
wrong note costs a glance -- which is why it is on by default, unlike the reads
ranker, whose mistakes the agent would act on.

Fails open like every hook here: any error, and the prompt goes through with no
note.

Env:
  TYPESAFE_API_KEY   required, else the hook no-ops
  JEV_LOG            path for the JSONL audit log
  JEV_DISABLE        set to 1 to bypass every hook in this repo
  JEV_CLEAR_OFF      set to 1 to turn off just this hook
  JEV_CLEAR_QUIET    set to 1 to keep judging and logging, but show no note

Also: `jev_clear.py --report` prints the log, for `./jev clear`.
"""

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# ORDER MATTERS -- see the same comment in jev_gate.py.
from jev_pyversion import require_python

require_python()

from jev_client import ART, JevError, api_key, ask_jev, disabled, env_var, log, read_payload  # noqa: E402
from jev_finish import is_local_command_echo, load_transcript  # noqa: E402
from jev_scope import recent_requests  # noqa: E402

# Below this there is little to save, and the prompt should not wait on a call.
# The same band tokens.sh reports against.
MIN_CONTEXT = 60_000

NEW_TASK_AT = 0.80
HISTORY_MAX = 0.30

MAX_PATHS = 15
FILE_TOOLS = {"Read", "Edit", "Write", "MultiEdit", "NotebookEdit"}

QUESTIONS = {
    "new_task": {
        "type": "noul",
        "instructions": (
            "The user has sent a new message in a long coding conversation. Is it "
            "a new, separate piece of work that could be done just as well in a "
            "fresh conversation with no history?"
        ),
        "criteria": {
            "true": (
                "The message starts a different task: another feature, another "
                "bug, another part of the codebase, or an unrelated question. "
                "Everything needed to do it is in the message itself or in files "
                "that can be read again."
            ),
            "false": (
                "The message continues, corrects, or follows up on the work in "
                "the conversation, or depends on decisions, findings, or output "
                "from earlier turns."
            ),
        },
    },
    "needs_history": {
        "type": "noul",
        "instructions": (
            "Does the new message depend on the earlier conversation to be "
            "understood or done correctly?"
        ),
        "criteria": {
            "true": (
                "It refers back to earlier turns: pronouns like 'it', 'that', "
                "'this'; 'the same for', 'also', 'now do', 'carry on', 'go', "
                "'yes'; a reply to a question the assistant asked; a report that "
                "something just done broke; or a request that only makes sense "
                "given a plan agreed earlier."
            ),
            "false": (
                "It is self-contained: someone reading only this message would "
                "know exactly what to do."
            ),
        },
    },
}


def emit(note: str | None = None) -> None:
    if note:
        print(json.dumps({"systemMessage": note}))
    sys.exit(0)


def context_tokens(rows: list[dict]) -> int:
    """Context size at the last API call: fresh input plus cache writes and reads."""
    for row in reversed(rows):
        if row.get("type") != "assistant" or row.get("isSidechain"):
            continue
        message = row.get("message")
        usage = message.get("usage") if isinstance(message, dict) else None
        if isinstance(usage, dict):
            return sum(
                usage.get(k) or 0
                for k in ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")
            )
    return 0


def touched_paths(rows: list[dict]) -> list[str]:
    seen: list[str] = []
    for row in rows:
        message = row.get("message")
        if row.get("type") != "assistant" or row.get("isSidechain") or not isinstance(message, dict):
            continue
        for block in message.get("content") or []:
            if isinstance(block, dict) and block.get("type") == "tool_use" and block.get("name") in FILE_TOOLS:
                path = (block.get("input") or {}).get("file_path") or (block.get("input") or {}).get("notebook_path")
                if path:
                    if path in seen:
                        seen.remove(path)
                    seen.append(str(path))
    return seen[-MAX_PATHS:]


def last_reply(rows: list[dict]) -> str:
    for row in reversed(rows):
        message = row.get("message")
        if row.get("type") != "assistant" or row.get("isSidechain") or not isinstance(message, dict):
            continue
        texts = [b.get("text", "") for b in message.get("content") or [] if isinstance(b, dict) and b.get("type") == "text"]
        if any(t.strip() for t in texts):
            return "\n".join(texts)
    return ""


def build_state(prompt: str, rows: list[dict]) -> str:
    earlier = recent_requests(rows)
    # The transcript may already hold the new prompt; it is not "earlier".
    if earlier and earlier[-1].strip() == prompt.strip():
        earlier = earlier[:-1]
    paths = touched_paths(rows)
    reply = last_reply(rows)
    return "\n\n".join(
        [
            "## The conversation so far: the user's recent requests, oldest first\n"
            + ("\n\n".join(f"[{i}] {t[:1200]}" for i, t in enumerate(earlier, 1)) or "(none)"),
            "## Files the assistant has worked with, most recent last\n" + ("\n".join(paths) or "(none)"),
            "## How the assistant's last reply ended\n" + (reply[-800:] or "(no reply)"),
            "## The user's new message\n" + prompt[:3000],
        ]
    )


def decide(scores: dict) -> str:
    new = scores.get("new_task", 0.0)
    history = scores.get("needs_history", 1.0)
    if new >= NEW_TASK_AT and history <= HISTORY_MAX:
        return "suggest_clear"
    if new >= NEW_TASK_AT:
        return "vetoed_needs_history"
    return "continuation"


def fmt_k(n: int) -> str:
    return f"{n / 1000:.0f}k"


def note_text(tokens: int, p: float) -> str:
    return (
        f"{ART} new task at {fmt_k(tokens)} context (p={p:.2f}) -- /clear would save "
        f"~{fmt_k(tokens)} tokens per call. Not what you meant? Ignore it; Claude did not see this."
    )


def report(limit: int = 25) -> int:
    path = env_var("JEV_LOG")
    if not path or not os.path.exists(os.path.expanduser(path)):
        print("No audit log yet. The clear advisor logs to JEV_LOG once installed.")
        return 1
    rows = []
    with open(os.path.expanduser(path)) as fh:
        for line in fh:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("hook") == "clear" and row.get("verdict"):
                rows.append(row)
    if not rows:
        print("No prompts judged yet. They appear once a session passes 60k tokens.")
        return 0
    counts = {}
    for r in rows:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    print(f"{len(rows)} prompts judged over {fmt_k(MIN_CONTEXT)} context\n")
    for verdict, count in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {verdict:22} {count:5}  {100 * count / len(rows):5.1f}%")
    hits = [r for r in rows if r["verdict"] == "suggest_clear"]
    print(f"\nLast {min(limit, len(hits))} /clear suggestions -- was each one really a new task?")
    for r in hits[-limit:]:
        s = r.get("scores", {})
        print(
            f"  {r.get('ts', '')[:16]}  {fmt_k(r.get('context_tokens', 0)):>5}  "
            f"new={s.get('new_task', 0):.2f} hist={s.get('needs_history', 0):.2f}  "
            f"{r.get('request_head', '')[:80]}"
        )
    return 0


def main() -> None:
    if "--report" in sys.argv[1:]:
        sys.exit(report())

    if disabled() or os.environ.get("JEV_CLEAR_OFF") == "1":
        emit()

    key = api_key()
    if not key:
        emit()

    payload = read_payload()
    if payload is None:
        emit()

    prompt = (payload.get("prompt") or "").strip()
    # Slash commands, including /clear itself, and `!` shell commands are not tasks.
    if not prompt or prompt.startswith("/") or is_local_command_echo(prompt):
        emit()

    transcript = payload.get("transcript_path")
    rows = load_transcript(transcript) if transcript else []
    tokens = context_tokens(rows)
    if tokens < MIN_CONTEXT:
        emit()

    try:
        scores, elapsed_ms, usage = ask_jev(build_state(prompt, rows), QUESTIONS, key)
    except JevError as exc:
        log({"hook": "clear", "error": str(exc)})
        emit()

    verdict = decide(scores)
    quiet = os.environ.get("JEV_CLEAR_QUIET") == "1"
    notify = verdict == "suggest_clear" and not quiet
    log(
        {
            "hook": "clear",
            "verdict": verdict,
            "notified": notify,
            "context_tokens": tokens,
            "scores": scores,
            "latency_ms": elapsed_ms,
            "usage": usage,
            "request_head": " ".join(prompt.split())[:220],
            "session_id": payload.get("session_id"),
        }
    )
    emit(note_text(tokens, scores.get("new_task", 0.0)) if notify else None)


if __name__ == "__main__":
    main()
