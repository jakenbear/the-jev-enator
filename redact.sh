#!/usr/bin/env bash
# Make an audit log safe to hand to someone else.
#
#   ./redact.sh                          your log -> stdout, share-safe
#   ./redact.sh -o alice.jsonl           write to a file instead
#   ./redact.sh --keep-commands -o x     keep command text, scrubbed (see below)
#   ./redact.sh --audit                  say what WOULD be stripped, write nothing
#   ./redact.sh other.jsonl -o out       redact a specific log
#
# WHAT IS IN A RAW LOG. Every record holds the probabilities and the decision,
# which are harmless. Four fields are not:
#
#   cwd           your working directory, so your username and often work email
#   command       the full command text, which can contain a key or a token
#   state_head    300 characters of command text or file content
#   request_head  your actual prompt, which can name a customer or a system
#
# DEFAULT: those four are removed. What is left is statistics -- probabilities,
# latencies, verdicts, token counts. That is enough for every question issue #5
# asks (which questions fire most, is a threshold wrong on someone's stack) and
# it cannot leak, because the fields that could are not there.
#
# The list of kept fields is an allowlist, not a blocklist. A field nobody has
# classified is dropped. That costs a little -- a new field needs a one-line
# change to ship -- and it buys the thing that matters: an unrelated commit
# adding a field cannot silently publish it.
#
# --keep-commands is for the OTHER job: reporting a bad classification, where the
# command is the bug report. It keeps command and state_head, run through a
# pattern scrubber that removes home paths, emails, and known secret shapes.
# READ THE OUTPUT BEFORE SENDING IT. The scrubber is only as good as its pattern
# list, and it cannot know that an internal hostname is sensitive. cwd and
# request_head are dropped even then -- there is no pattern that makes a sentence
# safe.

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SETTINGS="$HOME/.claude/settings.json"

KEEP_COMMANDS=0
AUDIT=0
OUT=""
LOGS=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep-commands) KEEP_COMMANDS=1 ;;
    --audit)         AUDIT=1 ;;
    -o|--out)
      OUT="${2:-}"
      [[ -z "$OUT" ]] && { echo "-o needs a filename" >&2; exit 2; }
      shift
      ;;
    -h|--help)
      sed -n '2,36p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    -*)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
    *)
      [[ -f "$1" ]] || { echo "no such log file: $1" >&2; exit 2; }
      LOGS+=("$1")
      ;;
  esac
  shift
done

# Same resolution order as report.sh: env, settings.json, default. Both spellings
# at each step, since a pre-rename install is still a supported one.
if [[ ${#LOGS[@]} -eq 0 ]]; then
  LOG="${JEV_LOG:-${JEV_GATE_LOG:-}}"
  if [[ -z "$LOG" && -f "$SETTINGS" ]]; then
    LOG="$(python3 -c "
import json,pathlib
try:
    env = json.loads(pathlib.Path('$SETTINGS').read_text()).get('env',{})
    print(env.get('JEV_LOG') or env.get('JEV_GATE_LOG') or '')
except Exception: print('')
" 2>/dev/null)"
  fi
  if [[ -z "$LOG" ]]; then
    LOG="$(PYTHONPATH="$REPO/src" python3 -c 'import jev_client; print(jev_client.default_log_path())' 2>/dev/null)"
  fi
  if [[ ! -f "$LOG" ]]; then
    echo "No audit log at $LOG" >&2
    echo "Name one explicitly: ./redact.sh path/to/log.jsonl" >&2
    exit 1
  fi
  LOGS+=("$LOG")
fi

# Refuse to overwrite. This writes a file someone is about to share, and clobbering
# a previous redaction they already reviewed is the wrong kind of surprise.
if [[ -n "$OUT" && -e "$OUT" ]]; then
  echo "$OUT already exists. Refusing to overwrite it." >&2
  exit 1
fi

KEEP_COMMANDS="$KEEP_COMMANDS" AUDIT="$AUDIT" OUT="$OUT" \
  PYTHONPATH="$REPO/src" python3 - "${LOGS[@]}" <<'PYBODY'
import json, os, sys

import jev_logs

keep = os.environ.get("KEEP_COMMANDS") == "1"
audit_only = os.environ.get("AUDIT") == "1"
out_path = os.environ.get("OUT") or ""
paths = sys.argv[1:]

rows = jev_logs.load_many(paths)
counts = jev_logs.audit(rows)

if audit_only:
    # Printed to stdout because it IS the output in this mode. Everywhere else it
    # goes to stderr, so `./redact.sh > log.jsonl` stays pipeable.
    print(f"\n{len(rows)} records across {len(paths)} log(s)\n")
    if not counts:
        print("  Nothing would be stripped: no sensitive fields present.\n")
    else:
        print("  Not kept as-is:")
        NOTE = {
            "command": "removed; kept scrubbed with --keep-commands",
            "state_head": "removed; kept scrubbed with --keep-commands",
            "error": f"scrubbed and truncated to {jev_logs.ERROR_MAX} chars",
        }
        for name, n in sorted(counts.items(), key=lambda kv: -kv[1]):
            print(f"    {name:14} {n:6} records  {NOTE.get(name, 'removed')}")
        print("\n  Everything else -- probabilities, latencies, verdicts, token")
        print("  counts -- is kept. Run without --audit to write the redacted log.\n")
    raise SystemExit(0)

clean = jev_logs.redact_all(rows, keep_commands=keep)
text = "".join(json.dumps(r) + "\n" for r in clean)

if out_path:
    with open(out_path, "w") as fh:
        fh.write(text)
else:
    sys.stdout.write(text)

# To stderr, so it is visible when redirecting to a file and does not corrupt the
# JSONL when piping. Showing the count is the point: someone sharing a log should
# see what was stripped rather than be told that stripping happened.
where = out_path or "stdout"
print(f"\n  {len(clean)} records -> {where}", file=sys.stderr)
if counts:
    stripped = ", ".join(f"{k} ({v})" for k, v in sorted(counts.items(), key=lambda kv: -kv[1]))
    print(f"  removed: {stripped}", file=sys.stderr)
if keep:
    print("\n  --keep-commands: command text was KEPT and pattern-scrubbed.", file=sys.stderr)
    print("  Read it before sending. The scrubber knows common secret shapes,", file=sys.stderr)
    print("  not your internal hostnames or customer names.", file=sys.stderr)
    if out_path:
        print(f"    grep -o '\"command\":[^,]*' {out_path} | less", file=sys.stderr)
print(file=sys.stderr)
PYBODY
