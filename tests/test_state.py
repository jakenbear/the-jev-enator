#!/usr/bin/env python3
"""Check the state each hook builds from a real-shaped payload.

The replay suites prove a fixture scores the way it did when it was recorded.
They cannot prove the fixture looks like what Claude Code actually sends, and
twice it did not:

  - Real Bash results carry no exit_code. The notice fixtures passed one, so
    every fixture state said "Exit code: 1" while every production state said
    "Exit code: unknown".
  - A failed Bash call never reaches PostToolUse at all. It fires
    PostToolUseFailure, with the output in an error string rather than a
    tool_response. The notice was only ever registered for PostToolUse.

The payload shapes below are copied from real transcripts, not from the docs.

No API key, no network.

Usage:
  python3 tests/test_state.py
"""

import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stdout
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

import jev_gate  # noqa: E402
import jev_notice  # noqa: E402

# What a successful Bash call's tool_response looks like in a real transcript.
# Note what is absent: exit_code.
def success_payload(stdout, **extra):
    return {
        "hook_event_name": "PostToolUse",
        "tool_name": "Bash",
        "tool_input": {"command": "npm test"},
        "tool_response": {
            "stdout": stdout,
            "stderr": "",
            "interrupted": False,
            "isImage": False,
            "noOutputExpected": False,
            **extra,
        },
    }


def failure_payload(error, field="tool_error"):
    return {
        "hook_event_name": "PostToolUseFailure",
        "tool_name": "Bash",
        "tool_input": {"command": "npm test"},
        field: error,
    }


def case_success_has_no_unknown_exit():
    payload = success_payload("PASS src/a.spec.ts\nTests: 4 passed, 4 total")
    state = jev_notice.build_state(payload, jev_notice.tool_output(payload))
    return [
        ("Exit code: unknown" not in state, "success state does not claim the exit code is unknown"),
        ("Exit code: 0" in state, "success state says exit 0, which PostToolUse implies"),
    ]


def case_return_code_interpretation_is_kept():
    # grep exiting 1 with no matches is reported as a success with this note.
    payload = success_payload("", returnCodeInterpretation="No matches found")
    payload["tool_response"]["stdout"] = "x" * 50
    state = jev_notice.build_state(payload, jev_notice.tool_output(payload))
    return [("No matches found" in state, "harness's exit-status note reaches the state")]


def case_failure_event_output_and_exit():
    error = "Exit code 1\nFAIL src/auth.spec.ts\nTests: 2 failed, 18 passed, 20 total"
    results = []
    for field in ("tool_error", "error"):
        payload = failure_payload(error, field)
        output = jev_notice.tool_output(payload)
        state = jev_notice.build_state(payload, output)
        results += [
            ("2 failed" in output, f"failure output read from {field!r}"),
            ("Exit code: 1" in state, f"exit code parsed from {field!r}"),
        ]
    return results


def case_failure_event_is_emitted_as_itself():
    buf = io.StringIO()
    try:
        with redirect_stdout(buf):
            jev_notice.emit("ctx", "PostToolUseFailure")
    except SystemExit:
        pass
    out = json.loads(buf.getvalue())["hookSpecificOutput"]
    return [(out["hookEventName"] == "PostToolUseFailure", "emit answers with the event it was called for")]


def case_persisted_output_reads_the_real_tail():
    # Over ~30KB, stdout is cut at 30000 chars and the whole output goes to a
    # file. The test summary is at the end -- past the cut.
    full = "ok line\n" * 5000 + "Tests: 2 failed, 18 passed, 20 total\n"
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as fh:
        fh.write(full)
        path = fh.name
    try:
        payload = success_payload(
            full[:30000], persistedOutputPath=path, persistedOutputSize=len(full)
        )
        state = jev_notice.build_state(payload, jev_notice.tool_output(payload))
        return [
            ("2 failed" in state, "summary past the 30000-char cut reaches the state"),
            ("2KB preview" in state, "state says the agent only saw a preview"),
        ]
    finally:
        os.unlink(path)


def case_gate_edit_shows_what_is_removed():
    removed = "def charge_customer(card):\n    return stripe.charge(card)\n" * 20
    state = jev_gate.build_state(
        {
            "tool_name": "Edit",
            "cwd": "/repo",
            "tool_input": {"file_path": "/repo/billing.py", "old_string": removed, "new_string": ""},
        }
    )
    return [("charge_customer" in state, "Edit state includes the text being replaced")]


def case_gate_notebook_edit_has_content():
    state = jev_gate.build_state(
        {
            "tool_name": "NotebookEdit",
            "cwd": "/repo",
            "tool_input": {
                "notebook_path": "/repo/a.ipynb",
                "new_source": "import shutil; shutil.rmtree('/data')",
                "edit_mode": "replace",
            },
        }
    )
    return [
        ("shutil.rmtree" in state, "NotebookEdit state includes new_source"),
        ("/repo/a.ipynb" in state, "NotebookEdit state includes notebook_path"),
    ]


CASES = [
    ("success payload: exit status", case_success_has_no_unknown_exit),
    ("success payload: returnCodeInterpretation", case_return_code_interpretation_is_kept),
    ("PostToolUseFailure payload", case_failure_event_output_and_exit),
    ("PostToolUseFailure output event name", case_failure_event_is_emitted_as_itself),
    ("persisted large output", case_persisted_output_reads_the_real_tail),
    ("gate: Edit deletion", case_gate_edit_shows_what_is_removed),
    ("gate: NotebookEdit", case_gate_notebook_edit_has_content),
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
