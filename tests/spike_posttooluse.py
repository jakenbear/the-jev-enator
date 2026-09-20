#!/usr/bin/env python3
"""Spike: can Jev spot a failure hiding in real command output?

Before wiring a PostToolUse hook into anyone's settings, answer the only
question that matters: given the output of a command, can Jev tell "this
succeeded" from "this failed and the agent is about to call it a success"?

The hard cases are the ones where exit status and reality disagree. Test
runners exit 0 while printing failures. `| tail -3` truncates the failure off
the screen. A build prints 200 warnings and one error. Those are exactly the
outputs an agent skims and declares green.

Run:
  cd ~/the-jev-enator && source .env && python3 tests/spike_posttooluse.py

Nothing here touches settings.json. It only prints probabilities.
"""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from jev_client import JevError, api_key, ask_jev  # noqa: E402

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
}

# (label, expected: "clean" | "failure", exit_code, output)
CASES = [
    (
        "clean: all tests pass",
        "clean",
        0,
        "PASS src/utils/date.spec.ts\n\nTest Suites: 1 passed, 1 total\nTests:       4 passed, 4 total\nTime:        1.83 s",
    ),
    (
        "clean: build succeeded",
        "clean",
        0,
        "vite v5.2.0 building for production...\n\xe2\x9c\x93 34 modules transformed.\ndist/index.html  0.46 kB\ndist/assets/index-4f8c.js  142.19 kB\n\xe2\x9c\x93 built in 1.21s",
    ),
    (
        "clean: install with deprecation noise",
        "clean",
        0,
        "npm warn deprecated inflight@1.0.6: This module is not supported\nnpm warn deprecated glob@7.2.3: Glob versions prior to v9 are no longer supported\n\nadded 412 packages, and audited 413 packages in 9s\n\nfound 0 vulnerabilities",
    ),
    (
        "clean: lint warnings only",
        "clean",
        0,
        "/src/components/Statistics/Bar.tsx\n  14:7  warning  'unused' is assigned a value but never used  @typescript-eslint/no-unused-vars\n\n\xe2\x9c\x96 1 problem (0 errors, 1 warning)",
    ),
    (
        "clean: grep found nothing",
        "clean",
        1,
        "",
    ),
    (
        "FAIL: plain test failure",
        "failure",
        1,
        "FAIL src/utils/date.spec.ts\n  \xe2\x97\x8f formats as en-CA\n\n    expected: '2026-01-02'\n    received: '1/2/2026'\n\nTests: 1 failed, 3 passed, 4 total",
    ),
    (
        "FAIL: type error",
        "failure",
        2,
        "src/usage/index.ts:42:18 - error TS2345: Argument of type 'string' is not assignable to parameter of type 'number'.\n\nFound 1 error in src/usage/index.ts:42",
    ),
    # The interesting ones: exit 0, or failure hidden by truncation.
    (
        "FAIL: exit 0 but tests failed",
        "failure",
        0,
        "Test Suites: 1 failed, 2 passed, 3 total\nTests:       2 failed, 18 passed, 20 total\nSnapshots:   0 total\nTime:        4.12 s\nRan all test suites.",
    ),
    (
        "FAIL: tail -3 hid the failure",
        "failure",
        0,
        "Time:        4.12 s\nRan all test suites.\nTests: 2 failed, 18 passed, 20 total",
    ),
    (
        "FAIL: error early, normal output after",
        "failure",
        0,
        "ERROR in ./src/routes/export.ts\nModule not found: Can't resolve 'aws-sdk'\n\nwebpack compiled with 1 error\nassets by path *.js 1.2 MiB\n  asset main.js 1.2 MiB\n  asset vendor.js 890 KiB\nbuilt at 14:02:11\nwebpack 5.90.0 compiled",
    ),
    (
        "FAIL: silent connection refused",
        "failure",
        0,
        "  % Total    % Received\n  0     0    0     0\ncurl: (7) Failed to connect to localhost port 5432 after 2 ms: Connection refused",
    ),
    (
        "FAIL: python traceback",
        "failure",
        1,
        'Traceback (most recent call last):\n  File "scripts/usage-report.py", line 18, in <module>\n    main()\n  File "scripts/usage-report.py", line 11, in main\n    rows = query(month)\nKeyError: \'tenant_id\'',
    ),
]


def build_state(command: str, exit_code: int, output: str) -> str:
    return "\n\n".join(
        [
            f"Command that was run:\n{command}",
            f"Exit code: {exit_code}",
            f"Output:\n{output if output.strip() else '(no output)'}",
        ]
    )


def main() -> int:
    key = api_key()
    if not key:
        print("TYPESAFE_API_KEY not set", file=sys.stderr)
        return 1

    # A plausible command for each case; the real hook gets this from the payload.
    commands = {
        "clean: all tests pass": "npm test -- date.spec.ts",
        "clean: build succeeded": "npm run build",
        "clean: install with deprecation noise": "npm ci",
        "clean: lint warnings only": "npx eslint src/",
        "clean: grep found nothing": "grep -rn 'TODO' src/",
        "FAIL: plain test failure": "npm test -- date.spec.ts",
        "FAIL: type error": "npx tsc --noEmit",
        "FAIL: exit 0 but tests failed": "npm test",
        "FAIL: tail -3 hid the failure": "npm test 2>&1 | tail -3",
        "FAIL: error early, normal output after": "npm run build",
        "FAIL: silent connection refused": "curl -s localhost:5432",
        "FAIL: python traceback": "python3 scripts/usage-report.py",
    }

    print()
    print(f"{'case':38} {'fail':>6} {'misleads':>9}   verdict")
    print("-" * 78)

    wrong = 0
    for label, expected, code, output in CASES:
        state = build_state(commands[label], code, output)
        try:
            scores, ms, _ = ask_jev(state, QUESTIONS, key)
        except JevError as exc:
            print(f"{label:38} ERROR {exc}")
            wrong += 1
            continue

        fail = scores.get("output_shows_failure", 0.0)
        misleads = scores.get("exit_status_misleads", 0.0)
        got = "failure" if fail >= 0.80 else "clean"
        ok = got == expected
        if not ok:
            wrong += 1
        mark = "ok " if ok else "MISS"
        print(f"{label:38} {fail:6.2f} {misleads:9.2f}   {mark} {got} ({ms}ms)")

    print("-" * 78)
    print(f"{len(CASES) - wrong}/{len(CASES)} separated correctly at threshold 0.80")
    print()
    print("The 'misleads' column is the one that matters for injection: high means")
    print("the agent would plausibly have missed it, so saying so earns its tokens.")
    print()
    return 1 if wrong else 0


if __name__ == "__main__":
    sys.exit(main())
