#!/usr/bin/env python3
"""Fire real PostToolUse payloads at jev_notice.py and check what it injects.

The cases that matter are the ones where exit status and reality disagree: a
runner that exits 0 while printing failures, output piped through `tail -3` so
the failure detail is gone, an error buried under normal build output. Those are
the outputs an agent skims and calls green.

The "quiet" expectation is the one that protects your workflow. A hook that
injects a warning into ordinary successful output would make the agent second
guess working code, which is worse than saying nothing.

Usage:
  cd ~/the-jev-enator && source .env && python3 tests/test_jev_notice.py
"""

import json
import os
import subprocess
import sys

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK = os.path.join(REPO, "src", "jev_notice.py")

sys.path.insert(0, os.path.join(REPO, "src"))
from jev_notice import KINDS  # noqa: E402  -- assert against the real hint text

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from fixture_env import fixture_log, hook_env, replay_miss, report, require_key, test_cwd  # noqa: E402

# (label, expected, command, exit_code, output[, kind])
# expected: "quiet"     -> must inject nothing
#           "notice"    -> must inject something
#           "emphatic"  -> must inject the stronger easy-to-miss wording
# kind (optional): substring the recovery hint must contain, or None to require
#           that no recovery is named. Omit to not check the hint at all.
#
# The kind fixtures are asserted on the injected hint text, not on the winning
# label, and that is deliberate: it is what the agent actually reads. It also
# meant the noul -> choice migration could be checked against these unchanged.
CASES = [
    # --- must stay quiet: ordinary success ---
    (
        "quiet: all tests pass",
        "quiet",
        "npm test -- date.spec.ts",
        0,
        "PASS src/utils/date.spec.ts\n\nTest Suites: 1 passed, 1 total\nTests:       4 passed, 4 total\nTime:        1.83 s",
    ),
    (
        "quiet: clean build",
        "quiet",
        "npm run build",
        0,
        "vite v5.2.0 building for production...\n34 modules transformed.\ndist/index.html  0.46 kB\ndist/assets/index-4f8c.js  142.19 kB\nbuilt in 1.21s",
    ),
    (
        "quiet: install with deprecation noise",
        "quiet",
        "npm ci",
        0,
        "npm warn deprecated inflight@1.0.6: This module is not supported\nnpm warn deprecated glob@7.2.3: Glob versions prior to v9 are no longer supported\n\nadded 412 packages, and audited 413 packages in 9s\n\nfound 0 vulnerabilities",
    ),
    (
        "quiet: lint warnings only",
        "quiet",
        "npx eslint src/",
        0,
        "/src/components/Statistics/Bar.tsx\n  14:7  warning  'unused' is assigned a value but never used  @typescript-eslint/no-unused-vars\n\n1 problem (0 errors, 1 warning)",
    ),
    (
        "quiet: git status output",
        "quiet",
        "git status --short",
        0,
        " M src/utils/date.ts\n M src/usage/index.ts\n?? scripts/usage-report.ts\n?? tests/fixtures/sample.json",
    ),
    (
        "quiet: short output skipped without a call",
        "quiet",
        "git rev-parse --short HEAD",
        0,
        "36cca86",
    ),

    # --- must speak up: failure is plainly visible ---
    (
        "notice: plain test failure",
        "notice",
        "npm test -- date.spec.ts",
        1,
        "FAIL src/utils/date.spec.ts\n  formats as en-CA\n\n    expected: '2026-01-02'\n    received: '1/2/2026'\n\nTests: 1 failed, 3 passed, 4 total",
    ),
    (
        "notice: type error",
        "notice",
        "npx tsc --noEmit",
        2,
        "src/usage/index.ts:42:18 - error TS2345: Argument of type 'string' is not assignable to parameter of type 'number'.\n\nFound 1 error in src/usage/index.ts:42",
    ),
    (
        "notice: python traceback",
        "notice",
        "python3 scripts/usage-report.py",
        1,
        'Traceback (most recent call last):\n  File "scripts/usage-report.py", line 18, in <module>\n    main()\n  File "scripts/usage-report.py", line 11, in main\n    rows = query(month)\nKeyError: \'tenant_id\'',
    ),
    (
        "notice: connection refused under exit 0",
        "notice",
        "curl -s localhost:5432",
        0,
        "  % Total    % Received\n  0     0    0     0\ncurl: (7) Failed to connect to localhost port 5432 after 2 ms: Connection refused",
    ),

    # --- the point of the hook: failure present, skim says success ---
    # Was asserted "emphatic" and scored 0.44-0.46 against EMPHATIC_AT = 0.45 --
    # it passed or failed on the roll. Expectation corrected rather than the
    # threshold lowered: this output scores the same as "notice: plain test
    # failure" below, and the reason is sound. `Tests: 2 failed` is right there
    # in the summary. Exit 0 disagreeing with the text is what the hook catches,
    # but nothing here is *hidden*, so a plain notice is the honest verdict.
    # Dropping EMPHATIC_AT to 0.40 to force this would also make every ordinary
    # test failure emphatic, which is the wording losing its meaning.
    (
        "notice: exit 0 but tests failed",
        "notice",
        "npm test",
        0,
        "Test Suites: 1 failed, 2 passed, 3 total\nTests:       2 failed, 18 passed, 20 total\nSnapshots:   0 total\nTime:        4.12 s\nRan all test suites.",
    ),
    (
        "emphatic: tail -3 hid the failure",
        "emphatic",
        "npm test 2>&1 | tail -3",
        0,
        "Time:        4.12 s\nRan all test suites.\nTests: 2 failed, 18 passed, 20 total",
    ),
    (
        "emphatic: error early, normal output after",
        "emphatic",
        "npm run build",
        0,
        "ERROR in ./src/routes/export.ts\nModule not found: Can't resolve 'aws-sdk'\n\nwebpack compiled with 1 error\nassets by path *.js 1.2 MiB\n  asset main.js 1.2 MiB\n  asset vendor.js 890 KiB\nbuilt at 14:02:11\nwebpack 5.90.0 compiled",
    ),

    # --- failure kind: the notice should name the matching recovery ---
    # A retry is the cheap correct move here, and the one an agent skips in
    # favour of "investigating" a rate limit that needs no investigation.
    (
        "kind transient: HTTP 429 from an API",
        "notice",
        "curl -sS -X POST https://api.stripe.com/v1/customers -u $KEY:",
        0,
        '{\n  "error": {\n    "message": "Too many requests. Please retry after a short delay.",\n    "type": "rate_limit_error"\n  }\n}\nHTTP/2 429',
        "transient",
    ),
    (
        "kind transient: connection reset mid-install",
        "notice",
        "npm ci",
        1,
        "npm error code ECONNRESET\nnpm error network aborted\nnpm error network This is a problem related to network connectivity.\nnpm error network In most cases you are behind a proxy or have bad network settings.",
        "transient",
    ),
    (
        "kind dependency: module not installed",
        "notice",
        "python3 scripts/usage-report.py",
        1,
        'Traceback (most recent call last):\n  File "scripts/usage-report.py", line 3, in <module>\n    import psycopg2\nModuleNotFoundError: No module named \'psycopg2\'',
        "missing from the environment",
    ),
    (
        "kind dependency: binary not on PATH",
        "notice",
        "tsx scripts/usage-report.ts",
        127,
        "zsh: command not found: tsx\n\nDid you mean to run this through npx? The repo does not install tsx globally.",
        "missing from the environment",
    ),
    (
        "kind invocation: unknown flag",
        "notice",
        "npm test --coverage-all",
        1,
        "npm error Unknown option: '--coverage-all'\nnpm error\nnpm error To see a list of supported npm commands, run:\nnpm error   npm help",
        "command itself looks wrong",
    ),
    # A plain assertion failure is needs_code_change, which maps to no hint. It is
    # the case where the agent does need to read the diff and think, and there is
    # no shortcut worth naming.
    (
        "kind none: real assertion failure gets no hint",
        "notice",
        "npm test -- date.spec.ts",
        1,
        "FAIL src/utils/date.spec.ts\n  formats as en-CA\n\n    expected: '2026-01-02'\n    received: '1/2/2026'\n\nTests: 1 failed, 3 passed, 4 total",
        None,
    ),
    # The fixture that pins KIND_MARGIN. Everything above is classified with near
    # total confidence, so the margin check was unreachable and deleting it left
    # all 19 cases passing -- an untested threshold.
    #
    # A dead Docker daemon is a genuine tie: missing_dependency 0.49 against
    # transient 0.42, because it is honestly both. Docker may not be installed, or
    # it may simply not be up yet. Naming either recovery would send the agent
    # confidently in a direction that is a coin flip, so the notice fires without a
    # hint. If this case ever starts naming a recovery, the margin check is gone.
    (
        "kind none: honest tie between two kinds stays hintless",
        "notice",
        "docker compose up -d",
        1,
        "Cannot connect to the Docker daemon at unix:///var/run/docker.sock. Is the docker daemon running?",
        None,
    ),
]


def main() -> int:
    require_key()

    log_path = fixture_log("notice")
    failures = 0
    for case in CASES:
        label, expected, command, code, output = case[:5]
        want_kind = case[5] if len(case) > 5 else "unchecked"
        payload = {
            "hook_event_name": "PostToolUse",
            "tool_name": "Bash",
            "tool_input": {"command": command},
            "tool_response": {"stdout": output, "stderr": "", "exit_code": code},
        }
        proc = subprocess.run(
            [sys.executable, HOOK],
            input=json.dumps(payload),
            capture_output=True,
            text=True,
            env=hook_env(log_path),
        )
        out = proc.stdout.strip()

        if not out:
            actual, detail = "quiet", ""
        else:
            try:
                ctx = json.loads(out)["hookSpecificOutput"]["additionalContext"]
                actual = "emphatic" if "easy to miss" in ctx else "notice"
                detail = ctx
            except (json.JSONDecodeError, KeyError):
                actual, detail = "?", f"unparseable: {out}"

        # An emphatic injection satisfies a plain "notice" expectation: both
        # tell the agent not to claim success, which is the behaviour under test.
        ok = actual == expected or (expected == "notice" and actual == "emphatic")
        if replay_miss(proc):
            ok, detail = False, "REPLAY MISS -- no recording; re-record the cassette"

        kind_note = ""
        if want_kind is None:
            if any(h in detail for _, h in KINDS):
                ok, kind_note = False, "  [named a recovery, expected none]"
        elif want_kind != "unchecked" and want_kind not in detail:
            ok, kind_note = False, f"  [no hint matching {want_kind!r}]"

        if not ok:
            failures += 1
        mark = "PASS" if ok else "FAIL"
        print(f"{mark}  {label:42} -> {actual:9} {detail[:58]}{kind_note}")
        if proc.stderr.strip():
            print(f"      stderr: {proc.stderr.strip()[:300]}")

    print()
    print(f"{len(CASES) - failures}/{len(CASES)} as expected")
    report(log_path)
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
