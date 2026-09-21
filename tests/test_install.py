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
SCOPE = str(REPO / "src" / "jev_scope.py")

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


def case_backup_path_is_real():
    """The backup install.sh names on stdout must be the file it actually wrote.

    These drifted immediately once the rename split them: the copy went to
    .bak-jevenator while the closing message still said .bak-jevgate. Nobody reads
    that line until they need it, and then it points at nothing.
    """
    home = make_home({"theme": "dark"})
    try:
        proc = run(home)
        named = [
            line.split("Backup:", 1)[1].strip()
            for line in proc.stdout.splitlines()
            if "Backup:" in line
        ]
        if not named:
            return [(False, "install.sh printed no Backup: line")]
        path = Path(named[0])
        return [
            (path.exists(), f"the backup it names exists ({path.name})"),
            (
                path.exists() and json.loads(path.read_text()).get("theme") == "dark",
                "the backup holds the pre-install settings",
            ),
        ]
    finally:
        shutil.rmtree(home, ignore_errors=True)


def case_fresh_install_log_path():
    """A machine with no history gets the current filename."""
    home = make_home({})
    try:
        run(home)
        env = settings_of(home).get("env", {})
        return [
            (
                env.get("JEV_LOG", "").endswith("jev-enator.jsonl"),
                f"fresh install logs to the current name (got {env.get('JEV_LOG')!r})",
            ),
            ("JEV_GATE_LOG" not in env, "no pre-rename name written on a fresh install"),
        ]
    finally:
        shutil.rmtree(home, ignore_errors=True)


def case_legacy_log_is_kept():
    """A pre-rename ~/jev-gate.jsonl must keep being written to.

    Pointing an existing user at the new filename would leave the history they
    already have in a file nothing reads again. report.sh's totals are the whole
    argument for turning enforcement on, so they have to cover everything that
    happened -- not everything since the rename.
    """
    home = make_home({})
    try:
        legacy = home / "jev-gate.jsonl"
        legacy.write_text('{"hook":"gate","scores":{}}\n')
        run(home)
        env = settings_of(home).get("env", {})
        return [
            (
                env.get("JEV_LOG") == str(legacy),
                f"existing log kept as the target (got {env.get('JEV_LOG')!r})",
            ),
            (legacy.read_text().startswith('{"hook"'), "the existing log was not truncated or moved"),
            (
                not (home / "jev-enator.jsonl").exists(),
                "no second log file created alongside it",
            ),
        ]
    finally:
        shutil.rmtree(home, ignore_errors=True)


def case_legacy_env_not_duplicated():
    """A settings.json already carrying JEV_GATE_LOG must not gain JEV_LOG too.

    Two names for one setting in one file is worse than the stale name alone:
    whichever one the reader later edits would appear to do nothing, because
    env_var() prefers the other.
    """
    home = make_home({"env": {"JEV_GATE_LOG": "/tmp/preexisting-jev.jsonl"}})
    try:
        run(home)
        env = settings_of(home).get("env", {})
        return [
            ("JEV_LOG" not in env, "no duplicate JEV_LOG added next to JEV_GATE_LOG"),
            (
                env.get("JEV_GATE_LOG") == "/tmp/preexisting-jev.jsonl",
                "the pre-rename setting is left exactly as the user wrote it",
            ),
        ]
    finally:
        shutil.rmtree(home, ignore_errors=True)


def case_uninstall_removes_both_spellings():
    """Uninstall must clear the old name too.

    Leaving JEV_GATE_LOG behind means a later reinstall writes JEV_LOG, sees the
    stale one still set, and honours whichever env_var() prefers -- logging to a
    path the reader thought they had removed.
    """
    home = make_home({"env": {"JEV_GATE_LOG": "/tmp/preexisting-jev.jsonl"}})
    try:
        run(home)
        run(home, "--uninstall")
        env = settings_of(home).get("env", {})
        return [
            ("JEV_GATE_LOG" not in env, "pre-rename log setting removed by uninstall"),
            ("JEV_LOG" not in env, "current log setting removed by uninstall"),
        ]
    finally:
        shutil.rmtree(home, ignore_errors=True)


def case_legacy_env_fallback():
    """Every renamed variable still works under its old name.

    This is the promise that keeps the rename from being a silent breakage. A
    hook that stops logging because a variable was renamed under it produces no
    error at all -- just an audit trail that quietly ends.
    """
    sys.path.insert(0, str(REPO / "src"))
    import jev_client

    results = []
    for new, old in sorted(jev_client.LEGACY_ENV.items()):
        probe = f"sentinel-for-{old}"
        saved = {k: os.environ.get(k) for k in (new, old)}
        try:
            os.environ.pop(new, None)
            os.environ[old] = probe
            results.append((jev_client.env_var(new) == probe, f"{old} still honoured as {new}"))
            os.environ[new] = f"wins-{new}"
            results.append(
                (jev_client.env_var(new) == f"wins-{new}", f"{new} takes precedence over {old}")
            )
        finally:
            for k, v in saved.items():
                if v is None:
                    os.environ.pop(k, None)
                else:
                    os.environ[k] = v
    return results


def case_disable_fallback_covers_pyversion():
    """jev_pyversion duplicates the disable fallback; assert it has not drifted.

    It cannot call jev_client.env_var() -- importing jev_client on an old
    interpreter is precisely what it exists to prevent -- so the JEV_GATE_DISABLE
    fallback is hardcoded there. A duplicate without a test is a future
    inconsistency, and this one would leave someone unable to turn the repo off.
    """
    src = (REPO / "src" / "jev_pyversion.py").read_text()
    return [
        ("JEV_DISABLE" in src, "jev_pyversion honours the current name"),
        ("JEV_GATE_DISABLE" in src, "jev_pyversion still honours the pre-rename name"),
    ]


def case_scope_hook_wired_separately():
    """The scope check needs its own PreToolUse entry with its own matcher.

    Claude Code applies a matcher per entry. Sharing the gate's entry would mean
    one of two silent breakages: the scope check runs on every Bash command,
    paying for a call whose state has no file in it, or the gate narrows to file
    writes and stops gating Bash -- which is most of what it exists for.
    """
    home = make_home({})
    try:
        run(home)
        data = settings_of(home)
        pre = data["hooks"]["PreToolUse"]
        gate_matcher = subprocess.run(
            [sys.executable, GATE, "--matcher"], capture_output=True, text=True
        ).stdout.strip()
        scope_matcher = subprocess.run(
            [sys.executable, SCOPE, "--matcher"], capture_output=True, text=True
        ).stdout.strip()
        entry_of = {
            h.get("command"): e.get("matcher")
            for e in pre
            for h in e.get("hooks", [])
        }
        return [
            (SCOPE in commands(data, "PreToolUse"), "scope hook wired to PreToolUse"),
            (bool(scope_matcher), f"--matcher returns a matcher ({scope_matcher!r})"),
            (
                entry_of.get(SCOPE) == scope_matcher,
                f"its entry uses the matcher the hook reports (got {entry_of.get(SCOPE)!r})",
            ),
            (
                entry_of.get(GATE) == gate_matcher,
                "the gate keeps its own, wider matcher",
            ),
            (
                entry_of.get(SCOPE) != entry_of.get(GATE),
                "the two do not share an entry, so neither narrows the other",
            ),
            ("Bash" not in (entry_of.get(SCOPE) or ""), "the scope check does not fire on Bash"),
        ]
    finally:
        shutil.rmtree(home, ignore_errors=True)


def case_scope_matcher_matches_watched_tools():
    """install.sh must not keep its own copy of the watched-tool list.

    This is the bug from issue #2 repeating: the gate's matcher was hardcoded in
    install.sh, drifted from GATED_TOOLS, and the tool it omitted was MultiEdit --
    the one that rewrites many files per call.
    """
    sys.path.insert(0, str(REPO / "src"))
    from jev_scope import WATCHED_TOOLS

    reported = subprocess.run(
        [sys.executable, SCOPE, "--matcher"], capture_output=True, text=True
    ).stdout.strip()
    install_src = (REPO / "install.sh").read_text()
    return [
        (
            reported == "|".join(sorted(WATCHED_TOOLS)),
            f"--matcher is derived from WATCHED_TOOLS ({reported!r})",
        ),
        (
            "MultiEdit" in reported,
            "MultiEdit is watched -- it is the one that rewrites many files at once",
        ),
        (
            'os.environ["SCOPE_MATCHER"]' in install_src,
            "install.sh reads the matcher from the hook rather than hardcoding it",
        ),
    ]


def case_scope_uninstall_removes_only_itself():
    """Uninstalling must take the scope entry and leave the gate's alone.

    Two of our own commands now live in PreToolUse. The removal loop matches on
    command path, so this asserts the obvious failure -- clearing the event and
    taking the gate with it -- cannot happen.
    """
    home = make_home({"hooks": {"PreToolUse": [FOREIGN_PRE]}})
    try:
        run(home)
        run(home, "--uninstall")
        data = settings_of(home)
        pre = commands(data, "PreToolUse")
        return [
            (SCOPE not in pre, "scope hook removed"),
            (GATE not in pre, "gate removed"),
            ("/opt/corp/audit-hook.sh" in pre, "foreign PreToolUse hook survived both removals"),
        ]
    finally:
        shutil.rmtree(home, ignore_errors=True)


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
    ("the named backup is the one written", case_backup_path_is_real),
    ("fresh install uses the current log filename", case_fresh_install_log_path),
    ("a pre-rename log file keeps being used", case_legacy_log_is_kept),
    ("a pre-rename env var is not duplicated", case_legacy_env_not_duplicated),
    ("uninstall clears both spellings", case_uninstall_removes_both_spellings),
    ("renamed vars still work under their old names", case_legacy_env_fallback),
    ("disable fallback is mirrored in jev_pyversion", case_disable_fallback_covers_pyversion),
    ("version-guard brand has not drifted", case_brand_not_drifted),
    ("scope hook gets its own PreToolUse entry", case_scope_hook_wired_separately),
    ("scope matcher is derived, not hardcoded", case_scope_matcher_matches_watched_tools),
    ("uninstall removes the scope hook and not the gate", case_scope_uninstall_removes_only_itself),
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
