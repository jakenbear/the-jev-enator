#!/usr/bin/env bash
# Read the audit log and answer two questions:
#   - what has the danger gate actually stopped?
#   - would the completion check have been right?
#
#   ./report.sh                      summary
#   ./report.sh --turns              every flagged turn, so you can judge each call
#   ./report.sh --turns 40           last 40 flagged turns
#   ./report.sh --since 2026-09-20   ignore records older than this
#
# --since exists because logs written before test isolation landed contain
# fixture classifications mixed in with real calls, and the fixtures are extreme
# by design -- they crowd out real work in every ranked list here. Rather than
# make anyone delete history, pick a cutoff. Records with no timestamp predate
# stamping and are excluded by --since.

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SETTINGS="$HOME/.claude/settings.json"

# Resolution order: the env, then settings.json, then the default. Each step
# checks the current name and the pre-rename one, because the whole point of the
# fallback is that someone who never touched their settings.json still gets a
# report -- "No audit log" on a machine that has been logging all week reads as a
# broken tool.
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
  echo "Set JEV_LOG in the env block of settings.json, then use Claude Code for a while." >&2
  exit 1
fi

MODE="summary"
LIMIT=20
SINCE=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --turns)
      MODE="turns"
      [[ "${2:-}" =~ ^[0-9]+$ ]] && { LIMIT="$2"; shift; }
      ;;
    --since)
      SINCE="${2:-}"
      [[ -z "$SINCE" ]] && { echo "--since needs a date, e.g. --since 2026-09-20" >&2; exit 2; }
      shift
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
  shift
done

MODE="$MODE" LIMIT="$LIMIT" SINCE="$SINCE" python3 - "$LOG" <<'PY'
import json, os, sys
from collections import Counter

mode = os.environ["MODE"]
limit = int(os.environ["LIMIT"])
since = os.environ.get("SINCE", "")

rows = []
for line in open(sys.argv[1]):
    line = line.strip()
    if not line:
        continue
    try:
        rows.append(json.loads(line))
    except json.JSONDecodeError:
        continue

if since:
    # Timestamps are ISO-8601 local, so a lexical compare is a date compare and
    # any prefix works as a cutoff: a bare date means midnight that morning.
    total = len(rows)
    rows = [r for r in rows if str(r.get("ts", "")) >= since]
    print(f"\n  since {since}: {len(rows)} of {total} records "
          f"({total - len(rows)} older or unstamped, excluded)")

PRICE_PER_MTOK = 0.042
gate = [r for r in rows if r.get("hook") == "gate" and "scores" in r]
finish = [r for r in rows if r.get("hook") == "finish" and "verdict" in r]
notice = [r for r in rows if r.get("hook") == "notice" and "scores" in r]
errors = [r for r in rows if "error" in r]

# Gate rows written before per-question thresholds existed have no 'hook' key.
legacy = [r for r in rows if "scores" in r and "hook" not in r]
tokens = sum(
    r.get("usage", {}).get("input_tokens", 0) for r in gate + finish + notice + legacy
)

GATE_THRESH = {
    "destructive": (0.80, 0.50),
    "rewrites_history": (0.90, 0.55),
    "discards_local_work": (1.01, 0.55),
    "exfiltrates_secrets": (0.80, 0.40),
    "hardcodes_credential": (0.90, 0.55),
    "outside_workspace": (0.85, 0.55),
}


def gate_outcome(scores):
    worst = "allow"
    for name, prob in scores.items():
        # A choice answer logs a dict of label -> probability. The gate asks only
        # noul questions, but skip defensively so one mixed record cannot crash
        # a report over a whole log.
        if not isinstance(prob, (int, float)):
            continue
        deny_at, ask_at = GATE_THRESH.get(name, (0.90, 0.60))
        if prob >= deny_at:
            return "deny"
        if prob >= ask_at:
            worst = "ask"
    return worst


def bar(n, total, width=24):
    if not total:
        return ""
    filled = round(width * n / total)
    return "#" * filled + "." * (width - filled)


if mode == "turns":
    shown = [r for r in finish if r.get("flagged")]
    if not shown:
        print("\nNo flagged turns yet. Either nothing was caught, or the completion")
        print("check has not run. Use Claude Code for a few sessions and re-run.\n")
        raise SystemExit(0)
    print(f"\nLast {min(limit, len(shown))} flagged turns "
          f"(of {len(shown)} flagged / {len(finish)} total)\n")
    for r in shown[-limit:]:
        s = r["scores"]
        print(f"  {r['verdict']}  {', '.join(r['flagged'])}")
        print(f"    request: {r.get('request_head', '')[:150]}")
        SHORT = {
            "awaiting_user_input": "waiting",
            "claimed_without_verifying": "unverified",
            "left_work_undone": "undone",
            "left_placeholder_code": "stubs",
            "ignored_failure": "ignored-fail",
        }
        print("    scores:  " + "  ".join(f"{SHORT.get(k, k)}={v:.2f}" for k, v in s.items()))
        print()
    print("  For each: was the flag right? If most are wrong, raise the thresholds")
    print("  in BLOCK_AT or add a criteria example. If most are right, consider")
    print("  JEV_FINISH_ENFORCE=1.\n")
    raise SystemExit(0)

print()
print("=" * 58)
print("  DANGER GATE  (PreToolUse)")
print("=" * 58)
if not gate:
    print("\n  No activity logged yet.\n")
else:
    outcomes = Counter(gate_outcome(r["scores"]) for r in gate)
    total = len(gate)
    print(f"\n  {total} tool calls classified\n")
    for name, label in (("deny", "blocked"), ("ask", "asked to confirm"), ("allow", "passed silently")):
        n = outcomes.get(name, 0)
        print(f"    {label:20} {n:5}  {100*n/total:5.1f}%  {bar(n, total)}")
    reasons = Counter()
    for r in gate:
        for name, prob in r["scores"].items():
            if not isinstance(prob, (int, float)):
                continue
            deny_at, ask_at = GATE_THRESH.get(name, (0.90, 0.60))
            if prob >= min(deny_at, ask_at):
                reasons[name] += 1
    if reasons:
        print("\n  Why calls were flagged:")
        for name, n in reasons.most_common(5):
            print(f"    {name:24} {n}")
    lat = sorted(r["latency_ms"] for r in gate)
    print(f"\n  median {lat[len(lat)//2]}ms, p95 {lat[int(len(lat)*0.95)]}ms")

print()
print("=" * 58)
print("  FAILURE NOTICE  (PostToolUse)")
print("=" * 58)
if not notice:
    print("\n  No activity logged yet.\n")
else:
    total = len(notice)
    spoke = [r for r in notice if r.get("noticed")]
    emph = [r for r in notice if r.get("emphatic")]
    print(f"\n  {total} command outputs read\n")
    for label, n in (
        ("stayed quiet", total - len(spoke)),
        ("flagged a failure", len(spoke)),
        ("   of those, easy to miss", len(emph)),
    ):
        print(f"    {label:26} {n:5}  {100*n/total:5.1f}%  {bar(n, total)}")
    if emph:
        print("\n  Failures an agent would plausibly have skimmed past:")
        for r in emph[-5:]:
            print(f"    {r.get('command','')[:70]}")

    # Which recovery got named, and how often the classifier was too unsure to
    # name one. A large "too close to call" count means KIND_MARGIN is too strict;
    # recoveries that turn out wrong in practice mean it is too loose.
    kinds = Counter(r["kind"] for r in spoke if r.get("kind"))
    unsure = [
        r for r in spoke
        if not r.get("kind") and r.get("kind_margin") is not None
    ]
    if kinds or unsure:
        print("\n  Recovery named for each failure kind:")
        for name, n in kinds.most_common():
            print(f"    {name:24} {n}")
        if unsure:
            near = [r for r in unsure if r.get("kind_p", 0) >= 0.60]
            print(f"    {'(none -- too close)':24} {len(unsure)}"
                  f"{f', {len(near)} of them a near-tie' if near else ''}")

    lat = sorted(r["latency_ms"] for r in notice)
    print(f"\n  median {lat[len(lat)//2]}ms")
    print("\n  'easy to miss' is the number that justifies this hook. A failure")
    print("  stated plainly needs no help; one hidden by exit 0 or tail does.")

print()
print("=" * 58)
print("  COMPLETION CHECK  (Stop)")
print("=" * 58)
if not finish:
    print("\n  No activity logged yet. This hook is log-only by default:")
    print("  it records a judgment per turn and never blocks.\n")
else:
    verdicts = Counter(r["verdict"] for r in finish)
    total = len(finish)
    enforced = sum(1 for r in finish if r.get("enforcing"))
    mode_label = "ENFORCING" if enforced == total else ("log-only" if not enforced else "mixed")
    print(f"\n  {total} turns judged  [{mode_label}]\n")
    for name, label in (
        ("complete", "looked complete"),
        ("would_block", "WOULD have blocked"),
        ("blocked", "actually blocked"),
        ("veto_awaiting_user", "waiting on you (vetoed)"),
    ):
        n = verdicts.get(name, 0)
        if n or name in ("complete", "would_block"):
            print(f"    {label:24} {n:5}  {100*n/total:5.1f}%  {bar(n, total)}")
    flagged = Counter()
    for r in finish:
        for name in r.get("flagged", []):
            flagged[name] += 1
    if flagged:
        print("\n  Reasons:")
        for name, n in flagged.most_common():
            print(f"    {name:26} {n}")
    lat = sorted(r["latency_ms"] for r in finish)
    print(f"\n  median {lat[len(lat)//2]}ms")
    would = verdicts.get("would_block", 0)
    if would:
        print(f"\n  {would} turns would have been blocked. Review them with:")
        print("    ./report.sh --turns")
        print("  Only enable JEV_FINISH_ENFORCE=1 if most of those were right.")

print()
print("=" * 58)
print(f"  {tokens} input tokens, ~${tokens / 1e6 * PRICE_PER_MTOK:.4f} total spend")

# Only surface errors from the recent tail; an old fixed bug in a long log
# should not keep reporting itself as current.
recent_errs = [r for r in rows[-40:] if "error" in r]
if recent_errs:
    print(f"  {len(recent_errs)} errors in last 40 calls: "
          f"{str(recent_errs[-1].get('error'))[:55]}")
elif errors:
    print(f"  {len(errors)} historical errors, none recent")
print("=" * 58)
print()
PY
