#!/usr/bin/env python3
"""Load, merge, filter and redact audit logs.

Everything that reads a log goes through here: report.sh, redact.sh, and the
tests. Before this, the loading and filtering lived inside a heredoc in
report.sh, which meant the only way to exercise it was to run the whole shell
script against a real log -- so the merge and redaction rules below, which are
the ones where a mistake leaks somebody's credentials, had no unit tests at all.

WHAT A LOG RECORD CONTAINS, and why redaction is allowlist-based:

    field          example                                    sensitive
    ----------------------------------------------------------------------
    hook           "gate"                                     no
    tool           "Bash"                                     no
    scores         {"destructive": 0.01, ...}                 no
    latency_ms     350                                        no
    usage          {"input_tokens": 1262}                     no
    verdict        "complete"                                 no
    flagged        ["ignored_failure"]                        no
    ts             "2026-09-20T17:46:33"                      no
    cwd            "/Users/jane.doe@corp.com/billing"         YES
    command        "curl -H 'Authorization: Bearer ey...'"    YES
    state_head     300 chars of command text or file content  YES
    request_head   the human's actual prompt                  YES
    path           "/Users/jane.doe@corp.com/svc/billing.py"  YES

The last five are the entire value of the log for debugging a bad call and the
entire reason you cannot hand one to a coworker. So the default is an allowlist:
a field is dropped unless it is named safe. You cannot enumerate every shape a
secret takes -- an internal hostname, a customer name in a prompt, a bearer token
in a header you have never seen -- but you can enumerate what is provably fine,
and a list of probabilities is provably fine.

The pattern scrubber (scrub_text) exists for the other job: reporting a bad
classification, where the command text IS the bug report. It is opt-in, and it is
explicitly the weaker of the two, because it is only as good as its pattern list.
"""

import json
import os
import re

# Fields that carry no content from the user's machine: probabilities, timings,
# decisions, and the shape of the record. Everything here is a number, a boolean,
# a hook name, or a question label defined in this repo's own source.
SAFE_FIELDS = frozenset(
    {
        "hook",
        "tool",
        "scores",
        "latency_ms",
        "usage",
        "verdict",
        "enforcing",
        "flagged",
        "noticed",
        "emphatic",
        "kind",
        "kind_p",
        "kind_margin",
        "allowed",
        "skipped",
        "state_chars",
        "explained_by_continuation",
        "ts",
    }
)

# Fields whose value is content from the machine the log was written on. Kept in
# a named set rather than "everything not in SAFE_FIELDS" so that a field added
# to a hook later is dropped by default instead of silently shipped: a new key
# nobody classified is exactly how a leak gets introduced by an unrelated commit.
#
# `path` is here and not in SAFE_FIELDS on purpose. It is only a filename, but it
# is an absolute one -- it carries the home directory, so the username, and the
# project name along with it. Somebody's repo layout is not mine to publish.
#
# `state_tail` is the most sensitive field in the project and is named here rather
# than left to the default drop. jev_finish writes it on a flagged turn so the flag
# can be adjudicated later -- it is the prompt, the closing message, and the last
# tool calls with their output. The allowlist would drop it anyway; naming it means
# audit() reports it and nobody later mistakes the silence for an oversight. It is
# dropped even under --keep-commands, because it contains request text.
SENSITIVE_FIELDS = frozenset(
    {"cwd", "command", "state_head", "state_tail", "request_head", "path"}
)

# 'error' is its own case. The text is ours, but an exception message can quote a
# URL or a path, so it is truncated rather than trusted or dropped -- an error
# count with no hint of what the error was makes a shared log useless for the one
# question a team most wants to ask about someone else's machine.
ERROR_MAX = 120

REDACTED = "<redacted>"


def load(path: str) -> list[dict]:
    """Parse one JSONL log. Skips unparseable lines rather than failing.

    A log is appended to by hooks running concurrently, so a truncated final line
    is normal, not corruption. Refusing to read the file over it would make the
    report unavailable exactly when someone is trying to debug.
    """
    rows = []
    with open(path) as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows


def load_many(paths: list[str], label: bool = True) -> list[dict]:
    """Load several logs into one list, tagged and sorted by timestamp.

    `source` is the filename stem, which is what makes a merged report able to
    say "this threshold is too low on someone else's stack" rather than just
    reporting a worse average. Name the files after who or what they came from.

    Records are deduplicated on their full content, because the obvious way to
    collect logs -- scp everyone's file into a folder, re-run weekly -- produces
    overlapping copies, and a duplicated record silently doubles a count that
    someone is about to make a threshold decision from.
    """
    rows = []
    seen = set()
    for path in paths:
        source = os.path.splitext(os.path.basename(path))[0]
        for row in load(path):
            key = json.dumps(row, sort_keys=True)
            if key in seen:
                continue
            seen.add(key)
            if label:
                row = {**row, "source": source}
            rows.append(row)
    # Undated records sort first: they predate timestamping, and putting them at
    # the front keeps "the recent tail" in report.sh actually recent.
    rows.sort(key=lambda r: str(r.get("ts", "")))
    return rows


def since(rows: list[dict], cutoff: str) -> list[dict]:
    """Records at or after an ISO-8601 prefix. Unstamped records are excluded.

    Timestamps are ISO-8601 local, so a lexical compare is a date compare and any
    prefix works: a bare date means midnight that morning.
    """
    if not cutoff:
        return rows
    return [r for r in rows if str(r.get("ts", "")) >= cutoff]


# --- Redaction ------------------------------------------------------------

# Ordered most specific first: a connection string contains a password, and
# matching the whole string is better than leaving the surrounding URL behind
# with a hole in it.
SECRET_PATTERNS = (
    # Connection strings with inline credentials.
    (re.compile(r"\b([a-z][a-z0-9+.-]*)://[^\s:/@]+:[^\s/@]+@"), r"\1://<redacted>@"),
    # JWTs. Three base64url segments; the header alone is enough to identify one.
    (re.compile(r"\bey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+"), REDACTED),
    # AWS access key IDs, which have a fixed, recognisable prefix and length.
    (re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|ABIA|ACCA)[A-Z0-9]{16}\b"), REDACTED),
    # Vendor-prefixed keys: sk-..., ghp_..., xoxb-..., apikey_..., and friends.
    (
        re.compile(
            r"\b(?:sk|pk|rk)-[A-Za-z0-9_-]{16,}"
            r"|\b(?:gh[pousr]|glpat|xox[abpsr])[-_][A-Za-z0-9_-]{16,}"
            r"|\bapikey_[A-Za-z0-9]{16,}"
        ),
        REDACTED,
    ),
    # A secret being assigned or exported. Catches KEY=, TOKEN=, SECRET=,
    # PASSWORD=, and the -H 'Authorization: Bearer x' shape.
    (
        re.compile(
            r"(?i)\b([A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)[A-Z0-9_]*)"
            r"(\s*[=:]\s*)(['\"]?)([^\s'\"]{6,})\3"
        ),
        lambda m: f"{m.group(1)}{m.group(2)}{m.group(3)}{REDACTED}{m.group(3)}",
    ),
    (re.compile(r"(?i)\b(bearer|basic)\s+([A-Za-z0-9._~+/=-]{12,})"), r"\1 " + REDACTED),
    # Anything long, high-entropy and unbroken. Deliberately last and deliberately
    # crude: it is the net under the named patterns above, since the whole premise
    # of --keep-commands is that the list is incomplete.
    (re.compile(r"\b[A-Za-z0-9+/_-]{40,}={0,2}\b"), REDACTED),
)

# A home directory reveals a name, often a work email. Replaced with ~ rather
# than dropped so relative structure survives -- "they were in a node_modules
# subdirectory" is useful and harmless.
_HOME_RE = re.compile(r"/(?:Users|home)/[^/\s\"']+")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")


def account_name() -> str:
    """The basename of $HOME, or "" if it cannot be determined.

    Needed because the home-path pattern only catches the name when it follows
    /Users/ or /home/. Run against a real log, six records leaked the author's
    name from commands that searched FOR it as a literal:

        git grep -ln "Jane.Doe\\|janedoe"

    The name is the sensitive part whether or not a path is wrapped around it,
    and on a corporate machine the account name is frequently a work email.
    """
    home = os.path.expanduser("~")
    return os.path.basename(home.rstrip(os.sep)) if home not in ("", os.sep) else ""


def _name_variants(name: str) -> list[str]:
    """The account name and the parts of it that appear on their own.

    On a corporate machine the account name IS the work email, so $HOME's
    basename is `Jane.Doe@corp.example.com` -- and a real log contained four
    records with a bare `Jane.Doe`, which a whole-string match walks straight
    past. Longest first, so the full form is replaced before its own prefix
    turns it into `<redacted>@corp.example.com`.
    """
    parts = {name, name.split("@", 1)[0]}
    return sorted((p for p in parts if len(p) > 2), key=len, reverse=True)


def scrub_text(text: str, account: str | None = None) -> str:
    """Rewrite home paths, emails, the account name and known secret shapes.

    WEAKER THAN THE ALLOWLIST, ON PURPOSE. This is for reporting a bad call,
    where the command is the bug report. It cannot promise a string is clean --
    an internal hostname or a customer name in a prompt passes straight through.

    account defaults to this machine's; pass it explicitly to scrub someone
    else's log, or "" to skip that step.
    """
    if not isinstance(text, str):
        return text
    for pattern, repl in SECRET_PATTERNS:
        text = pattern.sub(repl, text)
    text = _HOME_RE.sub("~", text)
    text = _EMAIL_RE.sub(REDACTED, text)
    # After the email pass, so name@corp.com is handled as an email rather than
    # leaving a redacted domain glued to a redacted name. The length guard inside
    # _name_variants matters: a one- or two-character account name would rewrite
    # half the string.
    name = account_name() if account is None else account
    for variant in _name_variants(name) if name else ():
        text = re.sub(re.escape(variant), REDACTED, text)
    return text


def redact(row: dict, keep_commands: bool = False) -> dict:
    """One record, safe to hand to someone else.

    Default drops every sensitive field. With keep_commands, command and
    state_head are scrubbed and kept -- but cwd and request_head are dropped
    either way: a working directory is a path and nothing else, and
    request_head is a human's own words, where redaction has no purchase at all.
    """
    out = {}
    for key, value in row.items():
        if key in SAFE_FIELDS or key == "source":
            out[key] = value
        elif key == "error":
            out[key] = scrub_text(str(value))[:ERROR_MAX]
        elif key in ("command", "state_head") and keep_commands:
            out[key] = scrub_text(value)
        elif key in SENSITIVE_FIELDS:
            continue
        # Any other key is dropped in silence: an unclassified field added by a
        # later commit must not ship just because nobody thought about it.
    return out


def redact_all(rows: list[dict], keep_commands: bool = False) -> list[dict]:
    return [redact(r, keep_commands=keep_commands) for r in rows]


def audit(rows: list[dict]) -> dict:
    """What a set of records would give away. Printed by redact.sh before writing.

    Someone about to share a log deserves to see the count of fields being
    stripped, not a promise that stripping happened.
    """
    counts = {}
    for row in rows:
        for key in row:
            if key in SAFE_FIELDS or key == "source":
                continue
            counts[key] = counts.get(key, 0) + 1
    return counts


# --- Summary --------------------------------------------------------------
#
# The thresholds report.sh compares against. Duplicated from jev_gate.QUESTIONS
# rather than imported, because a shared log is read on a machine that may be on a
# different commit than the one that wrote it -- importing the live thresholds
# would silently re-score somebody else's history against today's numbers and
# report a change in their behaviour that never happened.
GATE_THRESH = {
    "destructive": (0.80, 0.50),
    "rewrites_history": (0.90, 0.55),
    "discards_local_work": (1.01, 0.55),
    "exfiltrates_secrets": (0.80, 0.40),
    "hardcodes_credential": (0.90, 0.55),
    "outside_workspace": (0.85, 0.55),
}
DEFAULT_THRESH = (0.90, 0.60)
PRICE_PER_MTOK = 0.042


# Kind labels as they were written before #14, mapped to what they are called now.
#
# jev_notice once asked three independent noul questions -- failure_is_transient,
# failure_is_missing_dependency, failure_is_wrong_invocation -- and 37d859f
# replaced them with one `choice` whose options dropped the prefix. The hook is
# right to have moved on; the log cannot. A log is append-only history read on a
# machine that may be on a different commit than the one that wrote it, so old
# labels keep arriving forever and counting them as distinct kinds splits the
# evidence in two. On a real log that read as wrong_invocation 5 and 5 rather
# than 10, and missing_dependency 15 and 3 rather than 18 -- and those counts are
# what KIND_MARGIN is tuned from, so it is a wrong threshold, not a cosmetic one.
#
# Rename-only, so merging is sound: #14 changed the tiebreak between kinds, not
# what any one kind means. A future rename that also changes the definition must
# NOT be added here -- it would pool two different questions under one name.
KIND_ALIASES = {
    "failure_is_transient": "transient",
    "failure_is_missing_dependency": "missing_dependency",
    "failure_is_wrong_invocation": "wrong_invocation",
}


def canonical_kind(kind):
    """The current name for a logged failure kind, old or new."""
    return KIND_ALIASES.get(kind, kind)


def gate_outcome(scores: dict) -> str:
    """deny / ask / allow for one gate record."""
    worst = "allow"
    for name, prob in scores.items():
        # A choice answer logs a dict of label -> probability. The gate asks only
        # noul questions, but skip defensively so one mixed record cannot crash a
        # report over a whole log.
        if not isinstance(prob, (int, float)):
            continue
        deny_at, ask_at = GATE_THRESH.get(name, DEFAULT_THRESH)
        if prob >= deny_at:
            return "deny"
        if prob >= ask_at:
            worst = "ask"
    return worst


# Request text that only ever comes from this repo's own synthetic payloads. A
# record carrying one of these describes work nobody did.
#
# WHY THIS IS NEEDED AT ALL. Issue #1 ("tests write to the same log as real work,
# making report.sh precision numbers meaningless") was fixed in fixture_env.py,
# and verify.sh -- which runs the same hooks on the same invented payloads -- was
# not covered. verify.sh is now fixed too, but 91 records were already written,
# and the skew was not cosmetic:
#
#     as logged:  100 of 248 turns flagged = 40.3%
#     real only:   24 of 157 turns flagged = 15.3%
#
# Every synthetic record is engineered to be a clear block, so the pollution is
# pure bias in one direction. Anyone reading 40% would conclude the completion
# check is far too chatty to ever enforce, and would be reading its own test data.
#
# Filtered at read time rather than deleted from the log: a log is append-only
# evidence, and rewriting history to make a number look better is the opposite of
# what an audit trail is for.
# MATCHED ON CWD, NOT ON PROSE. The first version of this filter listed request
# text, and that was wrong in a way worth recording: the fixtures include
# "Deploy to staging." and "What does the usage module do?", which are also things
# a person says. A filter that hides real data to make a number look better is a
# worse bug than the pollution it was written to fix.
#
# WHAT THIS DOES NOT CATCH, stated because the gap changes how the numbers should
# be read. Fixture runs from before JEV_TEST_CWD was pinned used whatever
# directory the author happened to be in, so they carry a real project path and
# are indistinguishable from real turns by any signal in the record. They are all
# UNTIMESTAMPED -- timestamping arrived with the same round of fixes -- so the
# trustworthy subset is the timestamped one:
#
#     all records, cwd-filtered:    16 of 108 turns flagged = 14.8%
#     timestamped only:              0 of  42 turns flagged =  0.0%
#
# Those are not filtered out here. A log is append-only evidence and untimestamped
# records are history, not garbage; deciding they are worthless is the reader's
# call, and `--since` already exists for it.
#
# So the test's own pinned working directory is the signal. fixture_env.test_cwd()
# returns ~/some-project, a path that exists on no real machine, and
# record_cassette.py pins /home/runner/some-project. Nothing real runs there.
SYNTHETIC_CWDS = ("/some-project",)

# verify.sh's probes are the other source, and they run with cwd=$HOME, which IS
# real. They are identified by payloads verify.sh alone constructs -- kept narrow
# and exact for that reason, and checked against $HOME-level records only.
VERIFY_PROBE_REQUESTS = ("Fix the failing test in src/utils.",)

# The Stop probe above was the only one this filter knew about at first, which
# left the other two live probes counted as real activity. The cost of that gap
# was a headline number that was wrong by more than half: 62 gate blocks, of
# which 34 were this repo asking itself whether `rm -rf /` is destructive.
#
# Full-command equality, not a substring. A person really can run `npm test`, and
# `rm -rf /` appearing anywhere inside a longer command is not evidence of a
# probe -- it could be the string being discussed, grepped for, or written into a
# test. Only the exact command verify.sh constructs counts, so these must be kept
# character-identical to check 4 in verify.sh.
VERIFY_PROBE_COMMANDS = (
    "rm -rf / --no-preserve-root",
    "npm test 2>&1 | tail -3",
)


# Request text that appears ONLY in this repo's finish fixtures, matched only on
# records that have no timestamp. Both halves are load-bearing.
#
# The gap these close is documented above: fixture runs from before JEV_TEST_CWD
# was pinned used whatever directory the author was in, so they carry a real
# project path and the cwd tell walks straight past them. On a real log that was
# 13 of 27 flagged turns -- and since every fixture is engineered to be a clear
# block, the bias is entirely one-way in the number that decides enforcement.
#
# WHY PROSE MATCHING IS SAFE HERE AND WAS NOT BEFORE. #22 warned against matching
# fixture prose, and that warning was right: "Fix the failing date formatter test
# in src/utils." is a thing a person says, and a filter that hides real turns to
# improve a number is worse than the pollution it fixes. What makes it safe is the
# timestamp guard. Timestamping landed in the same round of fixes that pinned the
# fixture cwd, so fixture prose AND no `ts` can only mean a run from before both.
# Type the same sentence today and the record carries a `ts` and survives.
#
# These must stay character-identical to the CASES in tests/test_jev_finish.py.
FIXTURE_REQUESTS = (
    "Fix the failing date formatter test in src/utils.",
    "Update all three chart components in src/components/Statistics to the new palette: Bar, Line, and Pie.",
    "Implement the clip export endpoint.",
    "Add a usage report script and run it for last month.",
    "Update the three chart components to the new palette.",
)


def _untimestamped_fixture(row: dict) -> bool:
    """True for pre-timestamping fixture prose, which no other tell can catch."""
    if row.get("ts"):
        return False
    return str(row.get("request_head") or "").strip() in FIXTURE_REQUESTS


def _probe_command(row: dict) -> bool:
    """True if this row's command is exactly one verify.sh sends.

    The gate logs the command inside a rendered `state_head` block rather than a
    field of its own, so it is read back out of the "Command:" section. Anchored
    to the whole line: a command that merely mentions one of these is real work.
    """
    command = row.get("command")
    if command is None:
        head = str(row.get("state_head") or "")
        if "Command:" not in head:
            return False
        # Everything up to the trailing "Stated purpose:" the gate appends.
        command = head.split("Command:", 1)[1].split("Stated purpose:", 1)[0]
    return str(command).strip() in VERIFY_PROBE_COMMANDS


def is_synthetic(row: dict) -> bool:
    """True if this record came from a fixture run or a verify.sh probe.

    Two different tells, because the two sources differ: fixtures run in a pinned
    fake directory, while verify.sh probes run in the real $HOME and have to be
    recognised by their payload.
    """
    cwd = str(row.get("cwd") or "")
    if any(marker in cwd for marker in SYNTHETIC_CWDS):
        return True
    head = str(row.get("request_head") or "")
    if any(probe == head.strip() for probe in VERIFY_PROBE_REQUESTS):
        return True
    if _untimestamped_fixture(row):
        return True
    return _probe_command(row)


def drop_synthetic(rows: list[dict]) -> tuple[list[dict], int]:
    """Real records, and how many synthetic ones were removed."""
    kept = [r for r in rows if not is_synthetic(r)]
    return kept, len(rows) - len(kept)


def split(rows: list[dict]) -> dict:
    """Group records by hook. Handles pre-refactor rows with no 'hook' key."""
    return {
        "gate": [r for r in rows if r.get("hook") == "gate" and "scores" in r],
        "notice": [r for r in rows if r.get("hook") == "notice" and "scores" in r],
        "finish": [r for r in rows if r.get("hook") == "finish" and "verdict" in r],
        "scope": [r for r in rows if r.get("hook") == "scope" and "scores" in r],
        "errors": [r for r in rows if "error" in r],
        "legacy": [r for r in rows if "scores" in r and "hook" not in r],
    }


def _percentile(values: list, frac: float):
    if not values:
        return None
    ordered = sorted(values)
    idx = min(int(len(ordered) * frac), len(ordered) - 1)
    return ordered[idx]


def _latency(rows: list[dict]) -> dict:
    lat = [r["latency_ms"] for r in rows if isinstance(r.get("latency_ms"), (int, float))]
    return {"median_ms": _percentile(lat, 0.5), "p95_ms": _percentile(lat, 0.95), "n": len(lat)}


def _counter(items) -> dict:
    """Plain dict rather than Counter so json.dumps output is stable and sorted."""
    out = {}
    for item in items:
        out[item] = out.get(item, 0) + 1
    return dict(sorted(out.items(), key=lambda kv: (-kv[1], kv[0])))


def summarize(rows: list[dict]) -> dict:
    """A JSON-serialisable summary of a log, or of several merged logs.

    This is what --json prints and what the text report is rendered from, so the
    two cannot disagree -- a machine-readable summary that reports different
    numbers than the human one is worse than not having it.
    """
    groups = split(rows)
    gate, notice, finish = groups["gate"], groups["notice"], groups["finish"]
    scope = groups["scope"]
    tokens = sum(
        r.get("usage", {}).get("input_tokens", 0)
        for r in gate + notice + finish + scope + groups["legacy"]
    )

    sources = _counter(r["source"] for r in rows if r.get("source"))
    stamps = sorted(str(r["ts"]) for r in rows if r.get("ts"))

    gate_reasons = {}
    for r in gate:
        for name, prob in r["scores"].items():
            if not isinstance(prob, (int, float)):
                continue
            deny_at, ask_at = GATE_THRESH.get(name, DEFAULT_THRESH)
            if prob >= min(deny_at, ask_at):
                gate_reasons[name] = gate_reasons.get(name, 0) + 1

    spoke = [r for r in notice if r.get("noticed")]
    # Three buckets, and every noticed record lands in exactly one, because the
    # kind block is read as a breakdown of the flagged failures. It previously
    # showed only the first two and described 86 of 154 with no line saying so.
    #
    # `unasked` is the pre-#14 records, written before the failure_kind question
    # existed: no kind and no margin. They are not KIND_MARGIN being too strict
    # -- nothing was ever asked of them -- so folding them into `unsure` would
    # make the margin look far worse than it is and invite tuning it on records
    # it never saw. Told apart by kind_margin's presence, which is the only tell.
    unsure = [r for r in spoke if not r.get("kind") and r.get("kind_margin") is not None]
    unasked = [r for r in spoke if not r.get("kind") and r.get("kind_margin") is None]

    return {
        "records": len(rows),
        "sources": sources,
        "first_ts": stamps[0] if stamps else None,
        "last_ts": stamps[-1] if stamps else None,
        "tokens": tokens,
        "spend_usd": round(tokens / 1e6 * PRICE_PER_MTOK, 6),
        "errors": {
            "total": len(groups["errors"]),
            "recent": len([r for r in rows[-40:] if "error" in r]),
            "last": str(groups["errors"][-1].get("error"))[:120] if groups["errors"] else None,
        },
        "gate": {
            "total": len(gate),
            "outcomes": _counter(gate_outcome(r["scores"]) for r in gate),
            "reasons": dict(sorted(gate_reasons.items(), key=lambda kv: (-kv[1], kv[0]))),
            "latency": _latency(gate),
        },
        "notice": {
            "total": len(notice),
            "noticed": len(spoke),
            "emphatic": len([r for r in notice if r.get("emphatic")]),
            "kinds": _counter(canonical_kind(r["kind"]) for r in spoke if r.get("kind")),
            "kind_unsure": len(unsure),
            "kind_unasked": len(unasked),
            "kind_near_tie": len([r for r in unsure if r.get("kind_p", 0) >= 0.60]),
            "latency": _latency(notice),
        },
        "finish": {
            "total": len(finish),
            "verdicts": _counter(r["verdict"] for r in finish),
            "flagged": _counter(name for r in finish for name in r.get("flagged", [])),
            "enforcing": len([r for r in finish if r.get("enforcing")]),
            "latency": _latency(finish),
        },
        "scope": {
            "total": len(scope),
            "would_flag": len([r for r in scope if r.get("flagged")]),
            # The overlap is the number that decides whether this check is worth
            # anything: a flag that the conversation already explains is a false
            # positive of the cheap "the plan is the last prompt" definition, not
            # a finding. If most flags land here, the definition is what is wrong.
            "explained": len([r for r in scope if r.get("explained_by_continuation")]),
            "reasons": _counter(name for r in scope for name in r.get("flagged", [])),
            "latency": _latency(scope),
        },
    }


def by_source(rows: list[dict]) -> dict:
    """One summary per source log, for comparing machines.

    This is the actual point of merging: an aggregate average hides the case the
    issue asks about -- a threshold that is fine on four machines and wrong on the
    fifth. Averaging is how that stays invisible.
    """
    groups = {}
    for row in rows:
        groups.setdefault(row.get("source", "unknown"), []).append(row)
    return {name: summarize(rs) for name, rs in sorted(groups.items())}
