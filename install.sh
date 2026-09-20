#!/usr/bin/env bash
# Install The Jev-enator hooks into Claude Code.
#
#   ./install.sh              install for the current user
#   ./install.sh --uninstall  remove the hook, leave the repo in place
#
# Appends to each hook array without touching existing hooks, and backs up
# settings.json first. Safe to run twice.

set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SETTINGS="$HOME/.claude/settings.json"
GATE="$REPO/src/jev_gate.py"
FINISH="$REPO/src/jev_finish.py"
NOTICE="$REPO/src/jev_notice.py"

# Refuse to install against an interpreter that cannot run the hooks. On 3.9 the
# annotations in jev_client raise TypeError at import, and a hook that dies on
# import is indistinguishable from one that approved the call -- so without this
# check the install "succeeds" and protects nothing.
if ! python3 "$REPO/src/jev_pyversion.py" >/dev/null; then
  echo >&2
  echo "Refusing to install: the python3 on PATH cannot run these hooks." >&2
  exit 1
fi

if [[ ! -f "$SETTINGS" ]]; then
  echo "No $SETTINGS found. Start Claude Code once, then re-run." >&2
  exit 1
fi

# Claude Code merges this file; a syntax error here means it is already ignoring
# your settings, and appending to it would destroy whatever is in there.
if ! python3 -c "import json,sys; json.load(open(sys.argv[1]))" "$SETTINGS" 2>/dev/null; then
  echo "$SETTINGS is not valid JSON. Refusing to overwrite it." >&2
  echo "Fix or move it, then re-run. Claude Code is ignoring it as-is." >&2
  exit 1
fi

# One variable for the backup path, because the copy and the message that tells
# you where to find it drifted the moment they were written separately: the file
# went to .bak-jevenator while the closing line still named .bak-jevgate. A
# recovery instruction pointing at a file that does not exist is worse than none.
BACKUP="$SETTINGS.bak-jevenator"

chmod +x "$GATE" "$FINISH" "$NOTICE"
cp "$SETTINGS" "$BACKUP"

MODE="install"
[[ "${1:-}" == "--uninstall" ]] && MODE="uninstall"

KEY="${TYPESAFE_API_KEY:-}"
if [[ "$MODE" == "install" && -z "$KEY" && -f "$REPO/.env" ]]; then
  # shellcheck disable=SC1091
  source "$REPO/.env"
  KEY="${TYPESAFE_API_KEY:-}"
fi

if [[ "$MODE" == "install" && -z "$KEY" ]]; then
  echo "TYPESAFE_API_KEY is not set and $REPO/.env has no key." >&2
  echo "Get a key at https://typesafe.ai, then: cp .env.example .env" >&2
  exit 1
fi

# Ask the gate which tools it checks rather than keeping a second list here. The
# two drifted before: this file's hardcoded matcher omitted KillShell, which
# GATED_TOOLS had, and neither list mentioned MultiEdit -- so multi-file rewrites
# reached no gate at all. One source of truth, no drift. See issue #2.
GATE_MATCHER="$(python3 "$GATE" --matcher)"
if [[ -z "$GATE_MATCHER" ]]; then
  echo "Could not read the gated tool list from $GATE --matcher." >&2
  echo "Refusing to install a gate that matches nothing." >&2
  exit 1
fi

# Ask the client where to log rather than hardcoding a filename, so that a
# machine with a pre-rename ~/jev-gate.jsonl keeps appending to it. Writing the
# new name into settings.json for an existing user would leave their history in a
# file nothing reads again -- and report.sh's totals are the argument for turning
# enforcement on, so they have to cover everything, not everything since today.
LOG="$(PYTHONPATH="$REPO/src" python3 -c 'import jev_client; print(jev_client.default_log_path())')"
if [[ -z "$LOG" ]]; then
  echo "Could not determine a log path from jev_client.default_log_path()." >&2
  exit 1
fi

MODE="$MODE" GATE="$GATE" FINISH="$FINISH" NOTICE="$NOTICE" KEY="$KEY" SETTINGS="$SETTINGS" \
GATE_MATCHER="$GATE_MATCHER" LOG="$LOG" python3 - <<'PY'
import json, os, pathlib

mode = os.environ["MODE"]
path = pathlib.Path(os.environ["SETTINGS"])

# (hook event, script, matcher or None)
WIRING = [
    ("PreToolUse", os.environ["GATE"], os.environ["GATE_MATCHER"]),
    ("PostToolUse", os.environ["NOTICE"], "Bash"),
    ("Stop", os.environ["FINISH"], None),
]

data = json.loads(path.read_text())
hooks = data.setdefault("hooks", {})
changed = []

for event, script, matcher in WIRING:
    entries = hooks.setdefault(event, [])

    def owns(entry, script=script):
        return any(h.get("command") == script for h in entry.get("hooks", []))

    name = pathlib.Path(script).stem
    if mode == "uninstall":
        # Remove our command, not the entry containing it. Claude Code allows
        # several commands per entry, so dropping the whole entry also deletes a
        # co-tenant's hook -- someone else's audit or formatting hook vanishing
        # from a file we were only supposed to remove ourselves from. Nobody
        # notices that until the hook they relied on stops firing.
        kept = []
        removed = False
        for entry in entries:
            if not owns(entry):
                kept.append(entry)
                continue
            removed = True
            others = [h for h in entry.get("hooks", []) if h.get("command") != script]
            # Keep the entry only if something else still lives in it; an entry
            # with an empty hooks list is noise Claude Code would iterate over.
            if others:
                entry["hooks"] = others
                kept.append(entry)
        if removed:
            changed.append(f"removed {name} from {event}")
        hooks[event] = kept
    else:
        mine = [e for e in entries if owns(e)]
        if not mine:
            entry = {"hooks": [{"type": "command", "command": script}]}
            if matcher:
                entry["matcher"] = matcher
            entries.append(entry)
            changed.append(f"added {name} to {event}")
        elif matcher:
            # Already installed, but the matcher may have widened since -- a new
            # gated tool ships as a code change, and without this a reinstall
            # would silently leave the old, narrower list in place. That is how
            # MultiEdit would have stayed ungated for everyone already running it.
            for entry in mine:
                if entry.get("matcher") != matcher:
                    entry["matcher"] = matcher
                    changed.append(f"updated {name} matcher on {event} -> {matcher}")

env = data.setdefault("env", {})
if mode == "uninstall":
    # Both spellings, or an uninstall leaves a JEV_GATE_LOG behind that a
    # reinstall would then silently keep honouring as the fallback.
    for k in ("TYPESAFE_API_KEY", "JEV_LOG", "JEV_GATE_LOG"):
        env.pop(k, None)
else:
    env["TYPESAFE_API_KEY"] = os.environ["KEY"]
    # setdefault on both: if JEV_GATE_LOG is already here from a pre-rename
    # install, adding JEV_LOG next to it would be two names for one setting in
    # one file, and whichever one someone later edited would appear to do nothing.
    if "JEV_GATE_LOG" not in env:
        env.setdefault("JEV_LOG", os.environ["LOG"])

path.write_text(json.dumps(data, indent=2) + "\n")
print("\n".join(f"  {c}" for c in changed) if changed else "  no change needed")
PY

echo
echo "Backup: $BACKUP"
echo "Restart Claude Code to apply."
if [[ "$MODE" == "install" ]]; then
  echo
  echo "Verify with:  $REPO/verify.sh"
fi
