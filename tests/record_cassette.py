#!/usr/bin/env python3
"""Record live Jev responses so the suites can run offline.

Run this when you change a question, add a fixture, or want to refresh the
recordings. It needs a real key. Everything after it does not.

  cd ~/the-jev-enator && source .env && python3 tests/record_cassette.py

Writes tests/cassette.json, which CI replays. The recorded scores are a snapshot
of real model behaviour at one moment: replay proves the plumbing still works,
not that calibration still holds. That is what the live CI job is for.

How it works: JEV_RECORD makes jev_client append every (state, questions) ->
scores it sees to a temp file, keyed the same way replay looks them up. This
script runs the three suites with that set, then merges what they captured.
"""

import json
import os
import pathlib
import subprocess
import sys
import tempfile

TESTS = pathlib.Path(__file__).resolve().parent
REPO = TESTS.parent
CASSETTE = TESTS / "cassette.json"

# Recording happens with a pinned working directory, because the fixtures build
# their state from $HOME and the recorded key includes that text. Without this
# pin, a cassette recorded on one machine misses on every other one.
PINNED_CWD = "/home/runner/some-project"

SUITES = ("test_jev_gate.py", "test_jev_notice.py", "test_jev_finish.py")


def main() -> int:
    if not os.environ.get("TYPESAFE_API_KEY"):
        print("TYPESAFE_API_KEY not set -- recording needs a real key", file=sys.stderr)
        return 1

    with tempfile.NamedTemporaryFile("w", suffix=".jsonl", delete=False) as fh:
        record_path = fh.name

    env = {
        **os.environ,
        "JEV_RECORD": record_path,
        "JEV_TEST_CWD": PINNED_CWD,
    }
    env.pop("JEV_REPLAY", None)

    failed = []
    for suite in SUITES:
        print(f"\n=== recording {suite} ===")
        proc = subprocess.run([sys.executable, str(TESTS / suite)], env=env)
        if proc.returncode:
            failed.append(suite)

    responses = {}
    with open(record_path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            entry = json.loads(line)
            responses[entry["key"]] = {
                "scores": entry["scores"],
                "latency_ms": entry.get("latency_ms", 0),
                "usage": entry.get("usage", {}),
                # Kept for a human reading a diff. Replay never uses it, and the
                # key is a hash of the full state, not of this excerpt.
                "note": entry.get("state_head", "")[:120],
            }
    os.unlink(record_path)

    if not responses:
        print("\nNo calls recorded. Nothing written.", file=sys.stderr)
        return 1

    CASSETTE.write_text(
        json.dumps(
            {
                "pinned_cwd": PINNED_CWD,
                "note": "Recorded by tests/record_cassette.py. Replay with JEV_REPLAY.",
                "responses": dict(sorted(responses.items())),
            },
            indent=2,
        )
        + "\n"
    )
    print(f"\nWrote {len(responses)} recordings to {CASSETTE.relative_to(REPO)}")

    if failed:
        # Still written on purpose: a fixture that legitimately fails live should
        # fail the same way in replay, and refusing to record would make that
        # impossible to reproduce offline.
        print(f"Note: these suites failed while recording: {', '.join(failed)}")
        print("The cassette reflects what the model actually returned, failures included.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
