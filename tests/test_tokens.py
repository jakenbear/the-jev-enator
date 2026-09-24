#!/usr/bin/env python3
"""Check the token accounting in src/jev_tokens.py against a hand-built transcript.

The two rules that are easy to get wrong, and wrong silently:

  - One assistant message is often written as several rows that each repeat the
    same usage block. Counting rows instead of message ids double-counts.
  - A result is re-read by every later call, but only until a compaction. Past
    the boundary it is summarised away and stops costing anything.

No API key, no network, no real transcript touched.

Usage:
  python3 tests/test_tokens.py
"""

import json
import os
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

import jev_tokens  # noqa: E402


def call(mid, fresh=10, write=100, read=1000, out=5, ts="2026-09-24", tool=None):
    content = [{"type": "text", "text": "..."}]
    if tool:
        content.append({"type": "tool_use", "id": tool[0], "name": tool[1], "input": tool[2]})
    return {
        "type": "assistant",
        "timestamp": ts,
        "message": {
            "id": mid,
            "content": content,
            "usage": {
                "input_tokens": fresh,
                "cache_creation_input_tokens": write,
                "cache_read_input_tokens": read,
                "output_tokens": out,
            },
        },
    }


def result(tid, text, ts="2026-09-24", persisted=False):
    row = {
        "type": "user",
        "timestamp": ts,
        "message": {"content": [{"type": "tool_result", "tool_use_id": tid, "content": text}]},
    }
    if persisted:
        row["toolUseResult"] = {"stdout": text, "persistedOutputPath": "/tmp/x.txt"}
    return row


COMPACT = {"type": "system", "subtype": "compact_boundary", "timestamp": "2026-09-24",
           "compactMetadata": {"trigger": "auto", "preTokens": 170000}}


def scan(rows, since=None):
    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")
        path = fh.name
    try:
        stats = jev_tokens.Stats()
        jev_tokens.scan_file(path, since, stats)
        return stats
    finally:
        os.unlink(path)


def case_dedupes_by_message_id():
    # The same message written as three rows, as the harness does for a message
    # with text, thinking and a tool call.
    stats = scan([call("m1"), call("m1"), call("m1"), call("m2")])
    return [
        (stats.calls == 2, f"two messages counted once each (got {stats.calls})"),
        (stats.cache_read == 2000, f"cache reads not double counted (got {stats.cache_read})"),
    ]


def case_carried_stops_at_compaction():
    log = "x" * 4000  # 1000 tokens
    stats = scan(
        [
            call("m1", tool=("t1", "Bash", {"command": "cat big.log"})),
            result("t1", log),
            call("m2"),
            call("m3"),
            call("m4"),
            COMPACT,
            call("m5"),
            call("m6"),
        ]
    )
    [r] = [r for r in stats.results if r.kind == "Bash"]
    return [
        (r.label == "cat big.log", f"result labelled with its command (got {r.label!r})"),
        (r.later_calls == 3, f"re-read by the 3 calls before the compaction, not 5 (got {r.later_calls})"),
        (r.carried == 3000, f"carried = 1000 tokens x 3 (got {r.carried})"),
        (stats.compactions == [("auto", 170000)], "compaction recorded with its trigger and size"),
    ]


def case_hook_injection_counted():
    rows = [
        {"type": "attachment", "timestamp": "2026-09-24", "attachment": {
            "type": "hook_success", "hookEvent": "SessionStart", "hookName": "SessionStart:startup",
            "content": "RULESET\n" + "r" * 3992}},
        # Content can also be a list of text blocks rather than strings.
        {"type": "attachment", "timestamp": "2026-09-24", "attachment": {
            "type": "hook_additional_context", "hookName": "PostToolUse:Bash",
            "content": [{"type": "text", "text": "n" * 400}]}},
        # A PreToolUse hook's stdout is not read by the model.
        {"type": "attachment", "timestamp": "2026-09-24", "attachment": {
            "type": "hook_success", "hookEvent": "PreToolUse", "hookName": "PreToolUse:Bash",
            "content": "ok"}},
        call("m1"),
        call("m2"),
    ]
    stats = scan(rows)
    hooks = [r for r in stats.results if r.kind.startswith("hook:")]
    return [
        (len(hooks) == 2, f"only the context-bearing hooks counted (got {len(hooks)})"),
        (any(h.carried == 2000 for h in hooks), "SessionStart injection carried by both calls"),
        (any(h.chars == 400 for h in hooks), "block-list content measured"),
    ]


def case_since_and_cut():
    stats = scan(
        [
            call("old", ts="2026-08-01"),
            call("m1", tool=("t1", "Bash", {"command": "npm test"})),
            result("t1", "preview", persisted=True),
            call("m2"),
        ],
        since="2026-09-01",
    )
    [r] = [r for r in stats.results if r.kind == "Bash"]
    return [
        (stats.calls == 2, f"rows before --since excluded (got {stats.calls})"),
        (r.hit_cut, "oversized output marked as having hit the cut"),
    ]


def case_report_renders():
    stats = scan([call("m1", tool=("t1", "Read", {"file_path": "/a.py"})), result("t1", "y" * 20000), call("m2")])
    text = jev_tokens.report(stats, 5)
    return [
        ("Tool results over 10.0k chars: 1" in text, "big result counted in the report"),
        ("/a.py" in text, "top list names the file"),
    ]


CASES = [
    ("dedupe by message id", case_dedupes_by_message_id),
    ("carried cost and compaction", case_carried_stops_at_compaction),
    ("hook injections", case_hook_injection_counted),
    ("--since and the size cut", case_since_and_cut),
    ("report renders", case_report_renders),
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
