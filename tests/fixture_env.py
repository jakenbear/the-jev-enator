"""Keep fixture classifications out of the real audit log.

The hooks log through jev_client.log(), which writes to whatever JEV_GATE_LOG
points at. The test suites invoke those hooks as subprocesses, so without an
override every fixture lands in the same ~/jev-gate.jsonl as real tool calls.

That is not cosmetic. The fixtures are deliberately extreme -- `rm -rf /`, force
pushes, credentials in source -- so they sit at the top of every score
distribution and dominate exactly the rows report.sh asks you to review. On the
machine this was found, 185 of 860 gate records were fixtures, and of 80
high-scoring calls, 58 were fixtures, 21 were verify.sh, and 1 was real work.
Enforcement is supposed to be a decision made from that list. It cannot be.

Each suite gets its own file so a failing fixture is still debuggable: the path
is printed at the end of the run, and NamedTemporaryFile(delete=False) leaves it
in place afterwards rather than vanishing with the process.
"""

import os
import sys
import tempfile

# Must match record_cassette.py. The fixtures build their state from $HOME, and
# the recorded key is a hash of that state, so a cassette recorded under one home
# directory misses under every other one unless the path is pinned.
PINNED_CWD = "/home/runner/some-project"


def replaying() -> bool:
    return bool(os.environ.get("JEV_GATE_REPLAY"))


def require_key() -> None:
    """Exit unless the suite can actually run: a live key, or a cassette."""
    if replaying() or os.environ.get("TYPESAFE_API_KEY"):
        return
    print(
        "TYPESAFE_API_KEY not set.\n"
        "Either export a key, or run offline against the recorded responses:\n"
        "  JEV_GATE_REPLAY=tests/cassette.json python3 tests/<suite>.py",
        file=sys.stderr,
    )
    raise SystemExit(1)


def test_cwd() -> str:
    """The working directory the fixtures pretend to run in.

    Pinned in replay mode regardless of JEV_TEST_CWD, because the cassette keys
    were recorded against PINNED_CWD. Letting an override through here would
    produce a wall of cassette misses that look like a code bug.
    """
    if replaying():
        return PINNED_CWD
    return os.environ.get("JEV_TEST_CWD", os.path.join(os.path.expanduser("~"), "some-project"))


def fixture_log(suite: str) -> str:
    """Return a fresh temp log path for one suite's run."""
    fh = tempfile.NamedTemporaryFile(
        "w", prefix=f"jev-fixtures-{suite}-", suffix=".jsonl", delete=False
    )
    fh.close()
    return fh.name


def hook_env(log_path: str, **extra: str) -> dict:
    """Subprocess env with the audit log redirected at log_path.

    Passed explicitly to every subprocess.run rather than mutated into
    os.environ, so a suite that forgets it fails loudly in review instead of
    silently inheriting a redirect from whichever test ran first.
    """
    env = {**os.environ, "JEV_GATE_LOG": log_path, **extra}
    # Resolve the cassette to an absolute path. Callers naturally pass a
    # repo-relative one, and the hook subprocess does not necessarily inherit a
    # CWD where that resolves -- a miss there reads as "no recording" rather
    # than "wrong path", which is a confusing way to spend an afternoon.
    replay = env.get("JEV_GATE_REPLAY")
    if replay:
        env["JEV_GATE_REPLAY"] = os.path.abspath(replay)
    return env


def replay_miss(proc) -> bool:
    """True if this hook run died on a missing or unreadable recording.

    Without this check, replay mode can pass vacuously. A cassette miss exits the
    hook before it emits anything, and "emitted nothing" is exactly what an
    allow-expected fixture looks for -- so every safe case would still report
    PASS while testing nothing at all. Any fixture whose run hit the replay path
    error is a failure regardless of what it did or didn't print.
    """
    return "jev replay:" in (proc.stderr or "")


def report(log_path: str) -> None:
    """Tell the reader where the fixture scores went, if anything was written."""
    if os.path.exists(log_path) and os.path.getsize(log_path):
        print(f"fixture scores: {log_path}")
