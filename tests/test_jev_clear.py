#!/usr/bin/env python3
"""Check jev_clear.py: the offline rules, then real prompts against real history.

The cases that decide whether this hook is worth having are the continuations
that read like fresh requests -- "now add tests", "do the same for X", "yes, go
with 2". Each is self-contained as a sentence and meaningless without the
conversation. A /clear note on one of those is the hook telling someone to throw
away exactly the context their next message needs.

Run:
  python3 tests/test_jev_clear.py                                 offline half only
  JEV_REPLAY=tests/cassette.json python3 tests/test_jev_clear.py  both, replayed
  source .env && python3 tests/test_jev_clear.py                  both, live
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK = os.path.join(REPO, "src", "jev_clear.py")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "src"))
from fixture_env import fixture_log, hook_env, replay_miss, replaying, report  # noqa: E402

import jev_clear  # noqa: E402

P = "/home/runner/some-project"
BIG = 140_000


def user(text):
    return {"type": "user", "message": {"role": "user", "content": text}}


_ids = iter(range(10**6))


def assistant(text="", paths=(), context=BIG):
    content = []
    for tool, path in paths:
        content.append({"type": "tool_use", "id": f"t{next(_ids)}", "name": tool, "input": {"file_path": path}})
    if text:
        content.append({"type": "text", "text": text})
    return {
        "type": "assistant",
        "message": {
            "id": f"m{next(_ids)}",
            "role": "assistant",
            "content": content,
            "usage": {"input_tokens": 10, "cache_creation_input_tokens": 2000, "cache_read_input_tokens": context - 2010},
        },
    }


# Histories. Each is a long task in progress; the size is in the usage block.
DATES = [
    user("The date formatter in src/utils/date.ts returns ISO strings. It should return en-CA local dates."),
    assistant("", [("Read", f"{P}/src/utils/date.ts"), ("Edit", f"{P}/src/utils/date.ts")]),
    assistant("Fixed: formatDate now uses toLocaleDateString('en-CA'). Invoice.tsx and Receipt.tsx call it."),
]
CHARTS = [
    user("Migrate the chart components in src/components/Statistics to the new palette."),
    assistant("", [("Edit", f"{P}/src/components/Statistics/Bar.tsx"), ("Edit", f"{P}/src/components/Statistics/Line.tsx")]),
    assistant("Done: Bar, Line and Pie in Statistics now read colours from palette.ts."),
]
UPLOAD = [
    user("Add retry logic with backoff to the upload client in src/upload.ts."),
    assistant("", [("Edit", f"{P}/src/upload.ts")]),
    assistant(
        "Added withRetry(): 5 attempts, exponential backoff capped at 30s. Two options for "
        "the cap: 1) keep 30s, 2) make it configurable via UPLOAD_MAX_BACKOFF. Which do you want?"
    ),
]
BILLING = [
    user("Quebec invoices charge 13% tax. compute_tax in src/billing.py should use 14.975% for QC."),
    assistant("", [("Read", f"{P}/src/billing.py"), ("Edit", f"{P}/src/billing.py")]),
    assistant("Fixed the QC rate and added a test in tests/test_billing.py. All 41 tests pass."),
]

# (label, history, new prompt, accepted verdicts)
QUIET = {"continuation", "vetoed_needs_history"}
SCORED = [
    ("quiet: 'now add tests for it'", DATES, "now add tests for it", QUIET),
    ("quiet: the change broke something", DATES, "that broke the build -- TypeError: formatDate is not a function in Invoice.tsx", QUIET),
    ("quiet: answering the assistant's question", UPLOAD, "go with 2", QUIET),
    ("quiet: 'carry on'", CHARTS, "carry on", QUIET),
    ("quiet: the same change somewhere else", CHARTS, "Do the same for the ArticleList component.", QUIET),
    ("quiet: a question about the work just done", UPLOAD, "Why cap the backoff at 30s rather than 60?", QUIET),
    (
        "CLEAR: an unrelated script",
        BILLING,
        "Unrelated: write a bash script that rotates the nginx logs in /var/log/nginx weekly and keeps 8 weeks.",
        {"suggest_clear"},
    ),
    (
        "CLEAR: a different bug in a different area",
        DATES,
        "Different issue: the clips list pagination in src/screens/MediaClips skips page 2. Find and fix it.",
        {"suggest_clear"},
    ),
    (
        "CLEAR: a general question",
        BILLING,
        "Quick one: what's the difference between git rebase and git merge, and when should I use each?",
        {"suggest_clear"},
    ),
]


# ---------------------------------------------------------------------------
# Offline half


def case_context_tokens():
    rows = DATES + [{"type": "assistant", "isSidechain": True, "message": {"usage": {"input_tokens": 5}}}]
    return [
        (jev_clear.context_tokens(rows) == BIG, f"context read from the last main-chain call ({jev_clear.context_tokens(rows)})"),
        (jev_clear.context_tokens([user("hi")]) == 0, "no calls yet means zero"),
    ]


def case_decide():
    return [
        (jev_clear.decide({"new_task": 0.9, "needs_history": 0.1}) == "suggest_clear", "clear new task suggests"),
        (jev_clear.decide({"new_task": 0.9, "needs_history": 0.6}) == "vetoed_needs_history", "history veto wins"),
        (jev_clear.decide({"new_task": 0.5, "needs_history": 0.1}) == "continuation", "unsure is not a suggestion"),
        (jev_clear.decide({}) == "continuation", "no scores is not a suggestion"),
    ]


def case_state_drops_the_new_prompt_from_history():
    state = jev_clear.build_state("carry on", CHARTS + [user("carry on")])
    earlier = state.split("## Files")[0]
    return [
        ("carry on" not in earlier, "the new prompt is not listed as an earlier request"),
        ("Statistics/Line.tsx" in state, "files worked on are in the state"),
    ]


def run_hook(prompt, rows, log_path, env_extra=None):
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")
        transcript = fh.name
    try:
        proc = subprocess.run(
            [sys.executable, HOOK],
            input=json.dumps({"hook_event_name": "UserPromptSubmit", "prompt": prompt, "transcript_path": transcript}),
            capture_output=True,
            text=True,
            env=hook_env(log_path, **(env_extra or {})),
        )
    finally:
        os.unlink(transcript)
    record = None
    if os.path.exists(log_path):
        lines = [l for l in open(log_path).read().splitlines() if l.strip()]
        record = json.loads(lines[-1]) if lines else None
    return proc, record


def case_skips_without_calling_jev():
    tmp = tempfile.mkdtemp()
    small = [user("hi"), assistant("hello", context=20_000)]
    results = []
    try:
        for label, prompt, rows, extra in (
            ("a small context", "Write a log rotation script.", small, {}),
            ("a slash command", "/clear", BILLING, {}),
            ("a ! shell command", "<bash-input>ls</bash-input>", BILLING, {}),
            ("JEV_CLEAR_OFF=1", "Write a log rotation script.", BILLING, {"JEV_CLEAR_OFF": "1"}),
        ):
            log = os.path.join(tmp, f"{len(results)}.jsonl")
            proc, record = run_hook(prompt, rows, log, {"TYPESAFE_API_KEY": "sk-not-used", **extra})
            results.append((record is None and not proc.stdout.strip() and proc.returncode == 0,
                            f"{label} is skipped with no call and no output"))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return results


OFFLINE = [
    ("context size", case_context_tokens),
    ("verdict rule", case_decide),
    ("state", case_state_drops_the_new_prompt_from_history),
    ("skips before any call", case_skips_without_calling_jev),
]


def scored_cases() -> int:
    log_path = fixture_log("clear")
    failures = 0
    for label, history, prompt, accepted in SCORED:
        case_log = log_path + ".case"
        proc, record = run_hook(prompt, history, case_log)
        if os.path.exists(case_log):
            with open(case_log) as src, open(log_path, "a") as out:
                out.write(src.read())
            os.unlink(case_log)
        if replay_miss(proc):
            print(f"FAIL  {label}\n      replay miss -- re-record the cassette")
            failures += 1
            continue
        if record is None or "verdict" not in record:
            print(f"FAIL  {label}\n      no verdict logged: {proc.stderr.strip()[:160]}")
            failures += 1
            continue
        noted = bool(proc.stdout.strip())
        ok = record["verdict"] in accepted and noted == (record["verdict"] == "suggest_clear")
        if noted:
            out = json.loads(proc.stdout)
            ok = ok and set(out) == {"systemMessage"} and "/clear" in out["systemMessage"]
        failures += not ok
        s = record.get("scores", {})
        print(f"{'PASS' if ok else 'FAIL'}  {label}")
        print(f"      {record['verdict']}  new_task={s.get('new_task', 0):.2f} needs_history={s.get('needs_history', 0):.2f}  note={'yes' if noted else 'no'}")
        if not ok:
            print(f"      expected {sorted(accepted)}")

    # Quiet mode judges and logs, but shows nothing.
    label, history, prompt, _ = SCORED[-1]
    case_log = log_path + ".quiet"
    proc, record = run_hook(prompt, history, case_log, {"JEV_CLEAR_QUIET": "1"})
    ok = record is not None and record.get("verdict") == "suggest_clear" and not record.get("notified") and not proc.stdout.strip()
    failures += not ok
    print(f"{'PASS' if ok else 'FAIL'}  JEV_CLEAR_QUIET=1 logs the suggestion and shows no note")
    report(log_path)
    return failures


def main() -> int:
    failures = 0
    for label, fn in OFFLINE:
        print(f"\n{label}")
        try:
            results = fn()
        except Exception as exc:  # noqa: BLE001 -- a crashing case is a failing case
            print(f"  FAIL  case raised {type(exc).__name__}: {exc}")
            failures += 1
            continue
        for ok, detail in results:
            failures += not ok
            print(f"  {'PASS' if ok else 'FAIL'}  {detail}")

    print()
    if replaying() or os.environ.get("TYPESAFE_API_KEY"):
        failures += scored_cases()
    else:
        print("scored cases skipped: no key and no JEV_REPLAY")

    print()
    print(f"{failures} failure(s)" if failures else "all clear-advisor checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
