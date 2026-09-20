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
import tempfile


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
    return {**os.environ, "JEV_GATE_LOG": log_path, **extra}


def report(log_path: str) -> None:
    """Tell the reader where the fixture scores went, if anything was written."""
    if os.path.exists(log_path) and os.path.getsize(log_path):
        print(f"fixture scores: {log_path}")
