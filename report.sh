#!/usr/bin/env bash
# Read the audit log and answer two questions:
#   - what has the danger gate actually stopped?
#   - would the completion check have been right?
#
#   ./report.sh                      summary
#   ./report.sh --turns              every flagged turn, so you can judge each call
#   ./report.sh --turns 40           last 40 flagged turns
#   ./report.sh --since 2026-09-20   ignore records older than this
#   ./report.sh --json               machine-readable summary, for scripting
#   ./report.sh team/*.jsonl         merge several logs into one report
#   ./report.sh --by-source team/*.jsonl   one summary per log, side by side
#
# --since exists because logs written before test isolation landed contain
# fixture classifications mixed in with real calls, and the fixtures are extreme
# by design -- they crowd out real work in every ranked list here. Rather than
# make anyone delete history, pick a cutoff. Records with no timestamp predate
# stamping and are excluded by --since.
#
# Naming several logs merges them, deduplicated, tagged by filename. Name the
# files after whose machine they came from: --by-source is the mode that answers
# "is this threshold wrong on someone else's stack", which an average cannot.
# Share logs with ./redact.sh first -- they contain command text and prompts.

set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SETTINGS="$HOME/.claude/settings.json"

MODE="summary"
LIMIT=20
SINCE=""
JSON=0
BY_SOURCE=0
LOGS=()
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
    --json)   JSON=1 ;;
    --by-source) BY_SOURCE=1 ;;
    -h|--help)
      sed -n '2,25p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    -*)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
    *)
      # A bare argument is a log file. This is what makes `scp everyone's log
      # into a folder` a working aggregation story with no server involved.
      if [[ ! -f "$1" ]]; then
        echo "no such log file: $1" >&2
        exit 2
      fi
      LOGS+=("$1")
      ;;
  esac
  shift
done

# No files named: fall back to the one this machine writes. Resolution order is
# the env, then settings.json, then the default -- each step checking the current
# name and the pre-rename one, because the whole point of the fallback is that
# someone who never touched their settings.json still gets a report. "No audit
# log" on a machine that has been logging all week reads as a broken tool.
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
    echo "Set JEV_LOG in the env block of settings.json, then use Claude Code for a while." >&2
    echo "Or name one or more log files: ./report.sh team/*.jsonl" >&2
    exit 1
  fi
  LOGS+=("$LOG")
fi

MODE="$MODE" LIMIT="$LIMIT" SINCE="$SINCE" JSON="$JSON" BY_SOURCE="$BY_SOURCE" \
  PYTHONPATH="$REPO/src" python3 - "${LOGS[@]}" <<'PYBODY'
import json, os, sys

import jev_logs

mode = os.environ["MODE"]
limit = int(os.environ["LIMIT"])
since = os.environ.get("SINCE", "")
as_json = os.environ.get("JSON") == "1"
by_source = os.environ.get("BY_SOURCE") == "1"
paths = sys.argv[1:]

rows = jev_logs.load_many(paths)
total_before = len(rows)
if since:
    rows = jev_logs.since(rows, since)

if as_json:
    # Nothing on stdout but JSON, so this can be piped. The filter and merge
    # facts go in the payload rather than a header line, or a consumer has no
    # way to know a cutoff was applied to the numbers it just read.
    out = {
        "logs": paths,
        "since": since or None,
        "excluded_by_since": total_before - len(rows),
        "summary": jev_logs.summarize(rows),
    }
    if by_source or len(paths) > 1:
        out["by_source"] = jev_logs.by_source(rows)
    print(json.dumps(out, indent=2))
    raise SystemExit(0)

finish = jev_logs.split(rows)["finish"]

if since:
    print(f"\n  since {since}: {len(rows)} of {total_before} records "
          f"({total_before - len(rows)} older or unstamped, excluded)")

if len(paths) > 1:
    sources = jev_logs.summarize(rows)["sources"]
    print(f"\n  merged {len(paths)} logs: "
          + ", ".join(f"{name} {n}" for name, n in sources.items()))


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
        who = f"[{r['source']}] " if len(paths) > 1 and r.get("source") else ""
        print(f"  {who}{r['verdict']}  {', '.join(r['flagged'])}")
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


def render(s, heading=None):
    """Print one summary dict.

    Rendered from the same dict --json emits, so the human and machine reports
    cannot disagree. A machine-readable summary reporting different numbers than
    the text one is worse than not having it at all.
    """
    if heading:
        print()
        print("#" * 58)
        print(f"  {heading}")
        print("#" * 58)

    print()
    print("=" * 58)
    print("  DANGER GATE  (PreToolUse)")
    print("=" * 58)
    g = s["gate"]
    if not g["total"]:
        print("\n  No activity logged yet.\n")
    else:
        total = g["total"]
        print(f"\n  {total} tool calls classified\n")
        for name, label in (("deny", "blocked"), ("ask", "asked to confirm"), ("allow", "passed silently")):
            n = g["outcomes"].get(name, 0)
            print(f"    {label:20} {n:5}  {100*n/total:5.1f}%  {bar(n, total)}")
        if g["reasons"]:
            print("\n  Why calls were flagged:")
            for name, n in list(g["reasons"].items())[:5]:
                print(f"    {name:24} {n}")
        print(f"\n  median {g['latency']['median_ms']}ms, p95 {g['latency']['p95_ms']}ms")

    print()
    print("=" * 58)
    print("  FAILURE NOTICE  (PostToolUse)")
    print("=" * 58)
    nn = s["notice"]
    if not nn["total"]:
        print("\n  No activity logged yet.\n")
    else:
        total = nn["total"]
        print(f"\n  {total} command outputs read\n")
        for label, n in (
            ("stayed quiet", total - nn["noticed"]),
            ("flagged a failure", nn["noticed"]),
            ("   of those, easy to miss", nn["emphatic"]),
        ):
            print(f"    {label:26} {n:5}  {100*n/total:5.1f}%  {bar(n, total)}")

        # Which recovery got named, and how often the classifier was too unsure
        # to name one. A large "too close to call" count means KIND_MARGIN is too
        # strict; recoveries that turn out wrong in practice mean it is too loose.
        if nn["kinds"] or nn["kind_unsure"]:
            print("\n  Recovery named for each failure kind:")
            for name, n in nn["kinds"].items():
                print(f"    {name:24} {n}")
            if nn["kind_unsure"]:
                near = nn["kind_near_tie"]
                print(f"    {'(none -- too close)':24} {nn['kind_unsure']}"
                      f"{f', {near} of them a near-tie' if near else ''}")

        print(f"\n  median {nn['latency']['median_ms']}ms")
        print("\n  'easy to miss' is the number that justifies this hook. A failure")
        print("  stated plainly needs no help; one hidden by exit 0 or tail does.")

    print()
    print("=" * 58)
    print("  COMPLETION CHECK  (Stop)")
    print("=" * 58)
    f = s["finish"]
    if not f["total"]:
        print("\n  No activity logged yet. This hook is log-only by default:")
        print("  it records a judgment per turn and never blocks.\n")
    else:
        total = f["total"]
        enforced = f["enforcing"]
        mode_label = "ENFORCING" if enforced == total else ("log-only" if not enforced else "mixed")
        print(f"\n  {total} turns judged  [{mode_label}]\n")
        for name, label in (
            ("complete", "looked complete"),
            ("would_block", "WOULD have blocked"),
            ("blocked", "actually blocked"),
            ("veto_awaiting_user", "waiting on you (vetoed)"),
        ):
            n = f["verdicts"].get(name, 0)
            if n or name in ("complete", "would_block"):
                print(f"    {label:24} {n:5}  {100*n/total:5.1f}%  {bar(n, total)}")
        if f["flagged"]:
            print("\n  Reasons:")
            for name, n in f["flagged"].items():
                print(f"    {name:26} {n}")
        print(f"\n  median {f['latency']['median_ms']}ms")
        would = f["verdicts"].get("would_block", 0)
        if would:
            print(f"\n  {would} turns would have been blocked. Review them with:")
            print("    ./report.sh --turns")
            print("  Only enable JEV_FINISH_ENFORCE=1 if most of those were right.")

    print()
    print("=" * 58)
    print(f"  {s['tokens']} input tokens, ~${s['spend_usd']:.4f} total spend")
    # Only surface errors from the recent tail; an old fixed bug in a long log
    # should not keep reporting itself as current.
    e = s["errors"]
    if e["recent"]:
        print(f"  {e['recent']} errors in last 40 calls: {str(e['last'])[:55]}")
    elif e["total"]:
        print(f"  {e['total']} historical errors, none recent")
    print("=" * 58)
    print()


if by_source:
    per = jev_logs.by_source(rows)
    if len(per) < 2:
        print("\n  --by-source needs more than one log to compare. Name several:")
        print("    ./report.sh --by-source team/*.jsonl\n")
    for name, s in per.items():
        render(s, heading=f"{name}  ({s['records']} records)")
    # A side-by-side table, because the per-machine blocks above are long enough
    # that the comparison they exist for gets lost in the scrolling.
    print("=" * 58)
    print("  SIDE BY SIDE")
    print("=" * 58)
    print(f"\n  {'source':14} {'calls':>6} {'blocked':>13} {'asked':>6} {'noticed':>8} {'wouldblk':>9}")
    for name, s in per.items():
        gt = s["gate"]["total"] or 1
        deny = s["gate"]["outcomes"].get("deny", 0)
        print(f"  {name[:14]:14} {s['gate']['total']:6} "
              f"{deny:6} {100*deny/gt:5.1f}% "
              f"{s['gate']['outcomes'].get('ask', 0):6} "
              f"{s['notice']['noticed']:8} "
              f"{s['finish']['verdicts'].get('would_block', 0):9}")
    print("\n  A rate that is an outlier here is the one worth reading. Same")
    print("  thresholds, different stack -- that is what a merged average hides.\n")
else:
    render(jev_logs.summarize(rows))
PYBODY
