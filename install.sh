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

if [[ ! -f "$SETTINGS" ]]; then
  echo "No $SETTINGS found. Start Claude Code once, then re-run." >&2
  exit 1
fi

chmod +x "$GATE" "$FINISH" "$NOTICE"
cp "$SETTINGS" "$SETTINGS.bak-jevgate"

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

MODE="$MODE" GATE="$GATE" FINISH="$FINISH" NOTICE="$NOTICE" KEY="$KEY" SETTINGS="$SETTINGS" \
GATE_MATCHER="$GATE_MATCHER" LOG="$HOME/jev-gate.jsonl" python3 - <<'PY'
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
        kept = [e for e in entries if not owns(e)]
        if len(kept) < len(entries):
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
    for k in ("TYPESAFE_API_KEY", "JEV_GATE_LOG"):
        env.pop(k, None)
else:
    env["TYPESAFE_API_KEY"] = os.environ["KEY"]
    env.setdefault("JEV_GATE_LOG", os.environ["LOG"])

path.write_text(json.dumps(data, indent=2) + "\n")
print("\n".join(f"  {c}" for c in changed) if changed else "  no change needed")
PY

echo
echo "Backup: $SETTINGS.bak-jevgate"
echo "Restart Claude Code to apply."
if [[ "$MODE" == "install" ]]; then
  echo
  echo "Verify with:  $REPO/verify.sh"
fi
