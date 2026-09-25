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
SCOPE="$REPO/src/jev_scope.py"
READS="$REPO/src/jev_reads.py"
CLEAR="$REPO/src/jev_clear.py"

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

chmod +x "$GATE" "$FINISH" "$NOTICE" "$SCOPE" "$READS" "$CLEAR" "$REPO/jev"
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

# Same for the scope check, for the same reason.
SCOPE_MATCHER="$(python3 "$SCOPE" --matcher)"
if [[ -z "$SCOPE_MATCHER" ]]; then
  echo "Could not read the watched tool list from $SCOPE --matcher." >&2
  echo "Refusing to install a hook that matches nothing." >&2
  exit 1
fi

READS_MATCHER="$(python3 "$READS" --matcher)"
if [[ -z "$READS_MATCHER" ]]; then
  echo "Could not read the watched tool list from $READS --matcher." >&2
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

# Publish a separate copy and point Claude Code at that, not at this checkout.
# An ordinary edit to src/ must not change the gate that is actually running.
# The leaf directory is a fingerprint of the sources, so a later install lands
# in a new directory instead of rewriting the one already in use. Mode 0555
# stops a text editor saving over the copy. It does not stop the owner from
# chmod, which is why the gate also denies tool calls that name this tree.
INSTALL_ROOT="$(PYTHONPATH="$REPO/src" python3 -c 'import jev_client; print(jev_client.hook_install_root())')"
INSTALL_DIR="$(PYTHONPATH="$REPO/src" python3 -c 'import jev_client; print(jev_client.hook_install_dir())')"
HOOK_TIMEOUT="$(PYTHONPATH="$REPO/src" python3 -c 'import jev_client; print(jev_client.HOOK_TIMEOUT_S)')"
if [[ -z "$INSTALL_DIR" || -z "$HOOK_TIMEOUT" || -z "$INSTALL_ROOT" ]]; then
  echo "Could not determine where to install the hooks." >&2
  exit 1
fi

if [[ "$MODE" == "install" ]]; then
  parent="$(dirname "$INSTALL_DIR")"
  mkdir -p "$parent"
  if [[ -d "$INSTALL_DIR" ]]; then
    chmod -R u+w "$INSTALL_DIR" || true
    rm -rf "$INSTALL_DIR"
  fi
  mkdir -p "$INSTALL_DIR"
  cp "$REPO"/src/*.py "$INSTALL_DIR/"
  python3 - "$INSTALL_DIR/jev-install.json" "$REPO" <<'PY'
import json, pathlib, sys
pathlib.Path(sys.argv[1]).write_text(json.dumps({"source_repo": sys.argv[2]}) + "\n")
PY
  chmod 555 "$INSTALL_DIR"/*.py
  chmod 444 "$INSTALL_DIR/jev-install.json"
  chmod 555 "$INSTALL_DIR"
fi

GATE="$INSTALL_DIR/jev_gate.py"
FINISH="$INSTALL_DIR/jev_finish.py"
NOTICE="$INSTALL_DIR/jev_notice.py"
SCOPE="$INSTALL_DIR/jev_scope.py"
READS="$INSTALL_DIR/jev_reads.py"
CLEAR="$INSTALL_DIR/jev_clear.py"

MODE="$MODE" GATE="$GATE" FINISH="$FINISH" NOTICE="$NOTICE" SCOPE="$SCOPE" READS="$READS" CLEAR="$CLEAR" KEY="$KEY" SETTINGS="$SETTINGS" \
GATE_MATCHER="$GATE_MATCHER" SCOPE_MATCHER="$SCOPE_MATCHER" READS_MATCHER="$READS_MATCHER" LOG="$LOG" \
INSTALL_ROOT="$INSTALL_ROOT" REPO="$REPO" HOOK_TIMEOUT="$HOOK_TIMEOUT" python3 - <<'PY'
import json, os, pathlib

mode = os.environ["MODE"]
path = pathlib.Path(os.environ["SETTINGS"])
repo_src = pathlib.Path(os.environ["REPO"]) / "src"
install_root = pathlib.Path(os.environ["INSTALL_ROOT"])
timeout = int(os.environ["HOOK_TIMEOUT"])


def is_ours(command, script_name):
    """A hook command this repo installed, whether it still points at the checkout.

    Reinstall used to match the command string exactly, so changing the path
    from the checkout to the published copy would add a second gate and leave
    the old one in place. Uninstall has the same problem in reverse.
    """
    if not command:
        return False
    candidate = pathlib.Path(command)
    if candidate.name != script_name:
        return False
    repo_copy = repo_src / script_name
    try:
        if candidate.resolve() == repo_copy.resolve():
            return True
    except (OSError, RuntimeError):
        if candidate == repo_copy:
            return True
    try:
        candidate.resolve().relative_to(install_root.resolve())
        return True
    except (ValueError, OSError, RuntimeError):
        return False

# (hook event, script, matcher or None)
WIRING = [
    ("PreToolUse", os.environ["GATE"], os.environ["GATE_MATCHER"]),
    ("PostToolUse", os.environ["NOTICE"], "Bash"),
    # A failed Bash call fires PostToolUseFailure and never PostToolUse, so
    # without this entry the notice never sees a command that exited non-zero.
    ("PostToolUseFailure", os.environ["NOTICE"], "Bash"),
    ("Stop", os.environ["FINISH"], None),
    # The scope check gets its own PreToolUse entry rather than sharing the
    # gate's. Its matcher is the write tools only, and Claude Code applies a
    # matcher per entry -- sharing one would either run the scope check on every
    # Bash command (paying for a call it has no useful state for) or narrow the
    # gate to file writes, which would stop gating Bash entirely.
    ("PreToolUse", os.environ["SCOPE"], os.environ["SCOPE_MATCHER"]),
    # Its own entry for the same reason: Read is gated by nothing else.
    ("PreToolUse", os.environ["READS"], os.environ["READS_MATCHER"]),
    ("UserPromptSubmit", os.environ["CLEAR"], None),
]

data = json.loads(path.read_text())
hooks = data.setdefault("hooks", {})
changed = []

for event, script, matcher in WIRING:
    entries = hooks.setdefault(event, [])
    script_name = pathlib.Path(script).name

    def owns(entry, script_name=script_name):
        return any(is_ours(h.get("command"), script_name) for h in entry.get("hooks", []))

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
            others = [h for h in entry.get("hooks", []) if not is_ours(h.get("command"), script_name)]
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
            entry = {"hooks": [{"type": "command", "command": script, "timeout": timeout}]}
            if matcher:
                entry["matcher"] = matcher
            entries.append(entry)
            changed.append(f"added {name} to {event}")
        else:
            for entry in mine:
                for hook in entry.get("hooks", []):
                    if not is_ours(hook.get("command"), script_name):
                        continue
                    # Move a checkout path onto the published copy, and set the
                    # hook timeout. Claude Code's default is 600s, and a
                    # PreToolUse hook that hits it does not block the call.
                    if hook.get("command") != script:
                        hook["command"] = script
                        changed.append(f"moved {name} on {event} to the installed copy")
                    if hook.get("timeout") != timeout:
                        hook["timeout"] = timeout
                        changed.append(f"set {name} timeout on {event} to {timeout}s")
                only_ours = entry.get("hooks") and all(
                    is_ours(h.get("command"), script_name) for h in entry.get("hooks", [])
                )
                # Already installed, but the matcher may have widened since -- a new
                # gated tool ships as a code change, and without this a reinstall
                # would silently leave the old, narrower list in place. That is how
                # MultiEdit would have stayed ungated for everyone already running it.
                # A shared entry also holds someone else's hook, so its matcher is
                # theirs as well and we leave it alone.
                if only_ours and matcher and entry.get("matcher") != matcher:
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

# Older fingerprints go only after settings point at the new copy. Until that
# write succeeds, set -e never reaches here, so a failed install leaves the
# previous copy in place for the previous settings.
if [[ "$MODE" == "install" ]]; then
  parent="$(dirname "$INSTALL_DIR")"
  shopt -s nullglob
  for old in "$parent"/*; do
    if [[ "$old" != "$INSTALL_DIR" ]]; then
      chmod -R u+w "$old" || true
      rm -rf "$old"
    fi
  done
  shopt -u nullglob
fi

if [[ "$MODE" == "uninstall" ]]; then
  if [[ -d "$INSTALL_ROOT" ]]; then
    chmod -R u+w "$INSTALL_ROOT" || true
    rm -rf "$INSTALL_ROOT"
  fi
fi

echo
echo "Backup: $BACKUP"
if [[ "$MODE" == "install" ]]; then
  echo "Hooks:  $INSTALL_DIR"
fi
echo "Restart Claude Code to apply."
if [[ "$MODE" == "install" ]]; then
  echo
  echo "Verify with:  $REPO/verify.sh"
fi
