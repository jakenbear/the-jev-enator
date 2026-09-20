#!/usr/bin/env python3
"""Check install.sh against settings files it has never seen.

install.sh had only ever run on its author's machine, against one settings.json
that only ever contained this repo's own hooks. Everything here is a shape a real
user's file can have that that one never did.

The uninstall cases are the ones that matter most. install.sh edits a file it does
not own, in place, and the failure mode is "quietly deleted a coworker's hook" --
which nobody notices until the hook they relied on stops firing.

No API key needed. Nothing here makes a network call; it runs install.sh against
a throwaway HOME and reads back the JSON.

Usage:
  python3 tests/test_install.py
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INSTALL = REPO / "install.sh"
GATE = str(REPO / "src" / "jev_gate.py")
NOTICE = str(REPO / "src" / "jev_notice.py")
FINISH = str(REPO / "src" / "jev_finish.py")

# A hook belonging to someone else, in the same events this repo installs into.
# Nothing may ever remove or reorder these.
FOREIGN_PRE = {
    "matcher": "Bash",
    "hooks": [{"type": "command", "command": "/opt/corp/audit-hook.sh"}],
}
FOREIGN_POST = {
    "matcher": "Write|Edit",
    "hooks": [{"type": "command", "command": "/opt/corp/format-on-write.sh"}],
}
FOREIGN_STOP = {"hooks": [{"type": "command", "command": "/opt/corp/notify-done.sh"}]}


def run(home: Path, *args, env_extra=None):
    env = {
        **os.environ,
        "HOME": str(home),
        "TYPESAFE_API_KEY": "test-key-not-real",
        **(env_extra or {}),
    }
    return subprocess.run(
        ["bash", str(INSTALL), *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(REPO),
    )


def settings_of(home: Path) -> dict:
    return json.loads((home / ".claude" / "settings.json").read_text())


def commands(data: dict, event: str) -> list[str]:
    return [
        h.get("command")
        for entry in data.get("hooks", {}).get(event, [])
        for h in entry.get("hooks", [])
    ]


def make_home(initial: dict) -> Path:
    home = Path(tempfile.mkdtemp(prefix="jev-install-test-"))
    claude = home / ".claude"
    claude.mkdir()
    (claude / "settings.json").write_text(json.dumps(initial, indent=2) + "\n")
    return home


# --- cases -----------------------------------------------------------------
# Each returns a list of (ok, description) so one case can assert several things.


def case_fresh_install():
    """An empty settings.json: all three hooks land, with the derived matcher."""
    home = make_home({})
    try:
        proc = run(home)
        if proc.returncode:
            return [(False, f"install failed: {proc.stderr.strip()[:120]}")]
        data = settings_of(home)
        matcher = subprocess.run(
            [sys.executable, GATE, "--matcher"], capture_output=True, text=True
        ).stdout.strip()
        pre = data["hooks"]["PreToolUse"]
        return [
            (GATE in commands(data, "PreToolUse"), "gate wired to PreToolUse"),
            (NOTICE in commands(data, "PostToolUse"), "notice wired to PostToolUse"),
            (FINISH in commands(data, "Stop"), "finish wired to Stop"),
            (
                any(e.get("matcher") == matcher for e in pre),
                "PreToolUse matcher matches --matcher output",
            ),
            (
                data.get("env", {}).get("TYPESAFE_API_KEY") == "test-key-not-real",
                "key written to env",
            ),
        ]
    finally:
        shutil.rmtree(home, ignore_errors=True)


def case_idempotent():
    """Installing twice must not duplicate anything."""
    home = make_home({})
    try:
        run(home)
        first = settings_of(home)
        run(home)
        second = settings_of(home)
        return [
            (first == second, "second install is a no-op"),
            (
                commands(second, "PreToolUse").count(GATE) == 1,
                "gate appears exactly once after two installs",
            ),
        ]
    finally:
        shutil.rmtree(home, ignore_errors=True)


def case_preserves_foreign_hooks():
    """Someone else's hooks in the same events must survive an install."""
    home = make_home(
        {
            "hooks": {
                "PreToolUse": [FOREIGN_PRE],
                "PostToolUse": [FOREIGN_POST],
                "Stop": [FOREIGN_STOP],
            },
            "env": {"SOME_OTHER_VAR": "keep-me"},
            "theme": "dark",
        }
    )
    try:
        run(home)
        data = settings_of(home)
        return [
            ("/opt/corp/audit-hook.sh" in commands(data, "PreToolUse"), "foreign PreToolUse kept"),
            ("/opt/corp/format-on-write.sh" in commands(data, "PostToolUse"), "foreign PostToolUse kept"),
            ("/opt/corp/notify-done.sh" in commands(data, "Stop"), "foreign Stop kept"),
            (data.get("env", {}).get("SOME_OTHER_VAR") == "keep-me", "unrelated env var kept"),
            (data.get("theme") == "dark", "unrelated top-level setting kept"),
            (GATE in commands(data, "PreToolUse"), "gate still installed alongside"),
        ]
    finally:
        shutil.rmtree(home, ignore_errors=True)


def case_uninstall_leaves_foreign_hooks():
    """Issue #4 point 4: uninstall must remove only this repo's hooks.

    The dangerous version of this bug is not a crash. It is install.sh doing
    `hooks[event] = []` and taking a coworker's audit hook with it, which nobody
    notices until the thing they relied on silently stops running.
    """
    home = make_home(
        {
            "hooks": {
                "PreToolUse": [FOREIGN_PRE],
                "PostToolUse": [FOREIGN_POST],
                "Stop": [FOREIGN_STOP],
            },
            "env": {"SOME_OTHER_VAR": "keep-me"},
        }
    )
    try:
        run(home)
        proc = run(home, "--uninstall")
        if proc.returncode:
            return [(False, f"uninstall failed: {proc.stderr.strip()[:120]}")]
        data = settings_of(home)
        return [
            ("/opt/corp/audit-hook.sh" in commands(data, "PreToolUse"), "foreign PreToolUse survived uninstall"),
            ("/opt/corp/format-on-write.sh" in commands(data, "PostToolUse"), "foreign PostToolUse survived uninstall"),
            ("/opt/corp/notify-done.sh" in commands(data, "Stop"), "foreign Stop survived uninstall"),
            (GATE not in commands(data, "PreToolUse"), "gate removed"),
            (NOTICE not in commands(data, "PostToolUse"), "notice removed"),
            (FINISH not in commands(data, "Stop"), "finish removed"),
            ("TYPESAFE_API_KEY" not in data.get("env", {}), "key removed from env"),
            (data.get("env", {}).get("SOME_OTHER_VAR") == "keep-me", "unrelated env var survived uninstall"),
        ]
    finally:
        shutil.rmtree(home, ignore_errors=True)


def case_shared_entry_uninstall():
    """A hook entry listing our command alongside someone else's.

    Claude Code allows several commands per entry. install.sh used to drop the
    whole entry whenever it owned any command inside it, which deleted the
    co-tenant's hook as collateral -- a silent one, since nobody checks that their
    formatting hook still fires until it does not.
    """
    home = make_home(
        {
            "hooks": {
                "Stop": [
                    {
                        "hooks": [
                            {"type": "command", "command": "/opt/corp/notify-done.sh"},
                            {"type": "command", "command": FINISH},
                        ]
                    }
                ]
            }
        }
    )
    try:
        run(home, "--uninstall")
        data = settings_of(home)
        entries = data.get("hooks", {}).get("Stop", [])
        return [
            (FINISH not in commands(data, "Stop"), "our hook removed from a shared entry"),
            (
                "/opt/corp/notify-done.sh" in commands(data, "Stop"),
                "co-tenant command in the same entry survives",
            ),
            (
                all(e.get("hooks") for e in entries),
                "no empty hook entries left behind",
            ),
        ]
    finally:
        shutil.rmtree(home, ignore_errors=True)


def case_rejects_broken_json():
    """A corrupt settings.json must be refused, not overwritten."""
    home = Path(tempfile.mkdtemp(prefix="jev-install-test-"))
    try:
        claude = home / ".claude"
        claude.mkdir()
        broken = '{"hooks": {"PreToolUse": [  <-- this file is not JSON\n'
        (claude / "settings.json").write_text(broken)
        proc = run(home)
        return [
            (proc.returncode != 0, "install refuses a settings.json that is not JSON"),
            (
                (claude / "settings.json").read_text() == broken,
                "the unreadable file is left exactly as it was",
            ),
            ("not valid JSON" in proc.stderr, "the error says what is wrong"),
        ]
    finally:
        shutil.rmtree(home, ignore_errors=True)


def case_rejects_old_python():
    """With an old python3 first on PATH, install must refuse.

    Skipped rather than faked when no <3.10 interpreter exists: a stub that prints
    a version string would test the stub, not the guard.
    """
    old = None
    for cand in ("/usr/bin/python3", "/usr/bin/python3.9", "/usr/local/bin/python3.9"):
        if not os.path.exists(cand):
            continue
        # Print the numbers and compare as ints. Comparing the repr of a tuple as
        # a string says "(3, 9)" >= "(3, 10)", because '9' > '1' -- which silently
        # turned this case into a skip on a machine that had a 3.9 to test with.
        out = subprocess.run(
            [cand, "-c", "import sys;print(sys.version_info[0], sys.version_info[1])"],
            capture_output=True,
            text=True,
        )
        if out.returncode != 0:
            continue
        try:
            found = tuple(int(p) for p in out.stdout.split())
        except ValueError:
            continue
        if found < (3, 10):
            old = cand
            break
    if old is None:
        return [(None, "no interpreter older than 3.10 found to test against")]

    home = make_home({})
    shim = Path(tempfile.mkdtemp(prefix="jev-oldpy-"))
    try:
        (shim / "python3").symlink_to(old)
        proc = run(home, env_extra={"PATH": f"{shim}:{os.environ['PATH']}"})
        return [
            (proc.returncode != 0, f"install refuses {old}"),
            ("Refusing to install" in proc.stderr, "the error explains the refusal"),
            (
                not (home / ".claude" / "settings.json").read_text().strip("{}\n \t"),
                "settings.json was left untouched",
            ),
        ]
    finally:
        shutil.rmtree(home, ignore_errors=True)
        shutil.rmtree(shim, ignore_errors=True)


def case_brand_not_drifted():
    """jev_pyversion hardcodes the brand; assert it still matches the real one.

    It cannot import jev_client -- that is the entire point of the module, since
    jev_client is unimportable on the interpreters this runs on. So the string is
    duplicated, and a duplicate without a test is a future inconsistency.
    """
    sys.path.insert(0, str(REPO / "src"))
    from jev_client import ART, BRAND
    from jev_pyversion import MIN_VERSION, _BRAND

    return [
        (_BRAND == f"{ART} {BRAND}", f"jev_pyversion brand matches jev_client ({_BRAND!r})"),
        (MIN_VERSION == (3, 10), f"MIN_VERSION is still {MIN_VERSION}"),
    ]


CASES = [
    ("fresh install wires all three hooks", case_fresh_install),
    ("installing twice changes nothing", case_idempotent),
    ("install preserves foreign hooks and settings", case_preserves_foreign_hooks),
    ("uninstall removes only our hooks", case_uninstall_leaves_foreign_hooks),
    ("uninstall of a shared hook entry", case_shared_entry_uninstall),
    ("broken settings.json is refused", case_rejects_broken_json),
    ("old python3 on PATH is refused", case_rejects_old_python),
    ("version-guard brand has not drifted", case_brand_not_drifted),
]


def main() -> int:
    failures = 0
    skipped = 0
    for label, fn in CASES:
        print(f"\n{label}")
        try:
            results = fn()
        except Exception as exc:  # noqa: BLE001 -- a crashing case is a failing case
            print(f"  FAIL  case raised {type(exc).__name__}: {exc}")
            failures += 1
            continue
        for ok, detail in results:
            if ok is None:
                print(f"  SKIP  {detail}")
                skipped += 1
                continue
            if not ok:
                failures += 1
            print(f"  {'PASS' if ok else 'FAIL'}  {detail}")

    print()
    if failures:
        print(f"{failures} assertion(s) failed")
    else:
        print(f"all assertions passed{f' ({skipped} skipped)' if skipped else ''}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
