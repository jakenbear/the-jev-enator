#!/usr/bin/env python3
"""Check log loading, merging and redaction.

The redaction cases are the ones that matter. Everything else here is a count
being wrong, which someone notices. A redaction bug is a credential in a file
somebody just emailed to their team, and nothing about the output looks wrong.

So the redaction tests are written as adversarially as I could manage: real
secret shapes, secrets in fields nobody thinks about, and -- most importantly --
a record containing a field that did not exist when this module was written, to
prove an unclassified field is dropped rather than shipped.

No API key, no network, no real log touched.

Usage:
  python3 tests/test_jev_logs.py
"""

import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "src"))

import jev_logs  # noqa: E402

# A real-shaped gate record, with every sensitive field populated.
GATE_ROW = {
    "hook": "gate",
    "tool": "Bash",
    "cwd": "/Users/jane.doe@corp.example.com/billing-service",
    "scores": {"destructive": 0.94, "rewrites_history": 0.02},
    "latency_ms": 350,
    "usage": {"input_tokens": 1262, "output_tokens": 118},
    "state_head": "Working directory: /Users/jane.doe@corp.example.com/billing-service\n\nCommand:\nrm -rf /",
    "ts": "2026-09-20T17:46:33",
}

NOTICE_ROW = {
    "hook": "notice",
    "scores": {"output_shows_failure": 0.96, "failure_kind": {"transient": 0.7, "needs_code_change": 0.1}},
    "latency_ms": 349,
    "usage": {"input_tokens": 3425},
    "noticed": True,
    "emphatic": True,
    "kind": "transient",
    "command": "curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r_wW1gFWFOEjXk' https://api.internal/v1",
    "ts": "2026-09-20T17:46:25",
}

FINISH_ROW = {
    "hook": "finish",
    "verdict": "would_block",
    "enforcing": False,
    "flagged": ["claimed_without_verifying"],
    "cwd": "/Users/jane.doe@corp.example.com/billing-service",
    "scores": {"claimed_without_verifying": 0.91},
    "latency_ms": 392,
    "usage": {"input_tokens": 1779},
    "request_head": "deploy the new pricing to prod for Acme Corp",
    "ts": "2026-09-20T17:45:43",
}


SCOPE_ROW = {
    "hook": "scope",
    "tool": "Edit",
    "cwd": "/Users/jane.doe@corp.example.com/billing-service",
    "path": "/Users/jane.doe@corp.example.com/billing-service/src/auth/session.ts",
    "scores": {
        "outside_stated_scope": 0.95,
        "unrequested_refactor": 0.10,
        "unrequested_dependency_change": 0.03,
        "continuation_ok": 0.05,
    },
    "flagged": ["outside_stated_scope"],
    "explained_by_continuation": False,
    "verdict": "would_flag",
    "latency_ms": 341,
    "usage": {"input_tokens": 980},
    "state_head": "## What the user asked for\nFix the date formatter in src/utils/date.ts",
    "ts": "2026-09-20T17:47:10",
}


def write_log(rows, name="alice.jsonl", directory=None):
    directory = directory or Path(tempfile.mkdtemp(prefix="jev-logs-test-"))
    path = Path(directory) / name
    with open(path, "a") as fh:
        for row in rows:
            fh.write(json.dumps(row) + "\n")
    return path


# --- cases -----------------------------------------------------------------


def case_load_skips_garbage():
    """A truncated final line is normal, not corruption."""
    tmp = Path(tempfile.mkdtemp(prefix="jev-logs-test-"))
    try:
        path = tmp / "partial.jsonl"
        path.write_text(
            json.dumps(GATE_ROW) + "\n"
            + "\n"
            + '{"hook": "gate", "scores": {"destru\n'  # a half-written line
            + json.dumps(NOTICE_ROW) + "\n"
        )
        rows = jev_logs.load(str(path))
        return [
            (len(rows) == 2, f"two valid records read past a truncated line (got {len(rows)})"),
        ]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def case_merge_tags_and_dedupes():
    """Merging labels each record and drops exact duplicates.

    The obvious collection workflow -- scp everyone's log into a folder, re-run
    weekly -- produces overlapping copies. A duplicated record silently doubles a
    count someone is about to set a threshold from.
    """
    tmp = Path(tempfile.mkdtemp(prefix="jev-logs-test-"))
    try:
        a = write_log([GATE_ROW, NOTICE_ROW], "alice.jsonl", tmp)
        b = write_log([GATE_ROW, FINISH_ROW], "bob.jsonl", tmp)  # GATE_ROW is a dup
        rows = jev_logs.load_many([str(a), str(b)])
        sources = {r["source"] for r in rows}
        return [
            (len(rows) == 3, f"duplicate record dropped across logs (got {len(rows)}, want 3)"),
            (sources == {"alice", "bob"}, f"each record tagged with its source log ({sources})"),
            (
                [r["ts"] for r in rows] == sorted(r["ts"] for r in rows),
                "merged records are in timestamp order",
            ),
        ]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def case_by_source_separates_machines():
    """Per-source summaries, because an average hides the case worth finding.

    A threshold that is fine on four machines and wrong on the fifth is exactly
    what averaging makes invisible, and it is the question issue #5 asks.
    """
    tmp = Path(tempfile.mkdtemp(prefix="jev-logs-test-"))
    try:
        quiet = dict(GATE_ROW, scores={"destructive": 0.01})
        a = write_log([quiet, dict(quiet, ts="2026-09-20T18:00:00")], "alice.jsonl", tmp)
        b = write_log([GATE_ROW], "bob.jsonl", tmp)  # destructive 0.94 -> deny
        per = jev_logs.by_source(jev_logs.load_many([str(a), str(b)]))
        return [
            (set(per) == {"alice", "bob"}, f"one summary per source ({sorted(per)})"),
            (
                per["alice"]["gate"]["outcomes"].get("deny", 0) == 0,
                "alice has no denies",
            ),
            (
                per["bob"]["gate"]["outcomes"].get("deny", 0) == 1,
                "bob's deny is attributed to bob, not averaged away",
            ),
        ]
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def case_since_excludes_unstamped():
    """Records with no timestamp predate stamping and cannot be dated."""
    rows = [GATE_ROW, dict(GATE_ROW, ts="2026-09-19T10:00:00"), {"hook": "gate", "scores": {}}]
    kept = jev_logs.since(rows, "2026-09-20")
    return [
        (len(kept) == 1, f"only the on-or-after record kept (got {len(kept)})"),
        (all(r.get("ts") for r in kept), "unstamped record excluded rather than assumed recent"),
    ]


def case_redact_drops_sensitive_fields():
    """The default output must carry no machine content at all."""
    out = [jev_logs.redact(r) for r in (GATE_ROW, NOTICE_ROW, FINISH_ROW)]
    blob = json.dumps(out)
    return [
        (all("cwd" not in r for r in out), "cwd dropped"),
        (all("state_head" not in r for r in out), "state_head dropped"),
        (all("command" not in r for r in out), "command dropped"),
        (all("request_head" not in r for r in out), "request_head dropped"),
        ("jane.doe" not in blob, "the username appears nowhere in the output"),
        ("corp.example.com" not in blob, "the work domain appears nowhere"),
        ("Acme Corp" not in blob, "a customer name from a prompt appears nowhere"),
        ("eyJhbGciOiJIUzI1NiJ9" not in blob, "the JWT appears nowhere"),
        (out[0]["scores"] == GATE_ROW["scores"], "probabilities survive intact"),
        (out[0]["latency_ms"] == 350, "latency survives"),
        (out[2]["flagged"] == ["claimed_without_verifying"], "question labels survive"),
    ]


def case_unknown_field_is_dropped():
    """A field added by a later commit must not ship because nobody classified it.

    This is the case that makes the allowlist worth the inconvenience. A hook
    gains a `prompt_text` field in six months, nobody updates this module, and an
    opt-out design would have published it.
    """
    row = dict(GATE_ROW, prompt_text="the user's private prompt", hostname="jane-laptop.corp")
    out = jev_logs.redact(row)
    return [
        ("prompt_text" not in out, "an unclassified new field is dropped"),
        ("hostname" not in out, "a second unclassified field is dropped"),
        ("hook" in out, "known-safe fields still pass through"),
    ]


def case_keep_commands_scrubs_secrets():
    """--keep-commands must still remove the secret shapes it knows."""
    cases = [
        ("export TYPESAFE_API_KEY=apikey_2991bf260ed80df47859b7ee2497", "apikey_2991bf"),
        ("curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.dBjftJeZ4CVPmB92K27uhbUJU1p1r', x", "eyJhbGciOi"),
        ("aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
        ("psql postgres://admin:hunter2@db.internal:5432/billing", "hunter2"),
        ("git clone https://ghp_16C7e42F292c6912E7710c838347Ae178B4a@github.com/x", "ghp_16C7e42F"),
        ("export OPENAI_KEY=sk-proj-abcdefghijklmnopqrstuvwxyz012345", "sk-proj-abcdef"),
        ("echo $DATABASE_PASSWORD=correcthorsebattery", "correcthorsebattery"),
    ]
    results = []
    for text, secret in cases:
        scrubbed = jev_logs.scrub_text(text)
        results.append((secret not in scrubbed, f"scrubbed: {text[:44]}..."))
    # Home paths and emails, which identify a person rather than grant access.
    scrubbed = jev_logs.scrub_text("cd /Users/jane.doe@corp.example.com/billing && mail bob@corp.example.com")
    results.append(("jane.doe" not in scrubbed, "home directory path replaced"))
    results.append(("bob@corp.example.com" not in scrubbed, "email address replaced"))
    results.append(("billing" in scrubbed, "harmless relative structure survives scrubbing"))
    return results


def case_bare_account_name_is_scrubbed():
    """The account name leaks even with no path around it.

    Found by running --keep-commands against a real log: six records contained
    the author's name because the command searched FOR it as a literal --

        git grep -ln "Jane.Doe|janedoe"

    The home-path pattern only matches /Users/<name>, so a bare name walked
    straight through. On a corporate machine the account name is often the work
    email, so this is the identity, not a cosmetic path detail -- and it also
    means $HOME's basename is the full address, which is why the bare local part
    below is its own assertion: matching only the whole account name left every
    one of those four real records leaking after the first fix.
    """
    account = "Jane.Doe@corp.example.com"
    cases = [
        'git grep -ln "Jane.Doe@corp.example.com|janedoe"',
        "grep -rn 'Jane.Doe@corp.example.com' README.md",
        "echo owner is Jane.Doe@corp.example.com",
        # The shape that actually leaked: the local part with no domain and no path.
        'git grep -ln "Jane.Doe\\|janedoe" | head -20',
        "cd ~/svc && grep -rn 'Jane.Doe' README.md",
    ]
    results = []
    for text in cases:
        out = jev_logs.scrub_text(text, account=account)
        leaked = account in out or "Jane.Doe" in out
        results.append((not leaked, f"name removed from: {text[:42]}..."))
    # The full address must not be left as <redacted>@corp.example.com, which
    # would publish the employer and the address format for free.
    full = jev_logs.scrub_text("owner Jane.Doe@corp.example.com", account=account)
    results.append(
        ("corp.example.com" not in full, "the domain goes with the name, not left behind"),
    )
    # A short account name must not turn the whole string into markers.
    short = jev_logs.scrub_text("cd /tmp && ls -la", account="jd")
    results.append(("ls -la" in short, "a 2-char account name is not substituted"))
    # Explicitly opting out has to work, for scrubbing someone else's log.
    optout = jev_logs.scrub_text("hello Jane.Doe@corp.example.com", account="")
    results.append(
        (jev_logs.REDACTED in optout, "account='' still scrubs the email pattern"),
    )
    return results


def case_keep_commands_still_drops_prompts():
    """cwd and request_head go even with --keep-commands.

    A working directory is a path and nothing else, and request_head is a human's
    own words -- there is no pattern that makes a sentence safe.
    """
    out = jev_logs.redact(FINISH_ROW, keep_commands=True)
    notice = jev_logs.redact(NOTICE_ROW, keep_commands=True)
    return [
        ("request_head" not in out, "request_head dropped even with --keep-commands"),
        ("cwd" not in out, "cwd dropped even with --keep-commands"),
        ("command" in notice, "command is kept with --keep-commands"),
        (
            "eyJhbGciOiJIUzI1NiJ9" not in json.dumps(notice),
            "the kept command has its JWT scrubbed",
        ),
    ]


def case_error_is_truncated_not_trusted():
    """An exception message is ours, but it can quote a path or URL."""
    row = {
        "hook": "gate",
        "error": "urlopen error at /Users/jane.doe@corp.example.com/x: " + "detail " * 60,
    }
    out = jev_logs.redact(row)
    return [
        (len(out["error"]) <= jev_logs.ERROR_MAX, f"error truncated to {jev_logs.ERROR_MAX}"),
        ("jane.doe" not in out["error"], "a path quoted inside an error is scrubbed"),
        (bool(out["error"]), "some error text survives, so the log stays useful"),
    ]


def case_audit_counts_what_would_leak():
    """redact.sh prints this before writing, so the count is shown not promised."""
    counts = jev_logs.audit([GATE_ROW, NOTICE_ROW, FINISH_ROW])
    return [
        (counts.get("cwd") == 2, f"counts both cwd fields (got {counts.get('cwd')})"),
        (counts.get("command") == 1, "counts the command field"),
        (counts.get("request_head") == 1, "counts the prompt field"),
        ("scores" not in counts, "safe fields are not counted as leaks"),
    ]


def case_summary_matches_hand_count():
    """The numbers --json prints must be the numbers in the records."""
    rows = [
        dict(GATE_ROW, scores={"destructive": 0.94}),            # deny
        dict(GATE_ROW, scores={"destructive": 0.60}),            # ask
        dict(GATE_ROW, scores={"destructive": 0.01}),            # allow
        NOTICE_ROW,
        FINISH_ROW,
        {"hook": "gate", "error": "boom", "ts": "2026-09-20T01:00:00"},
    ]
    s = jev_logs.summarize(rows)
    return [
        (s["records"] == 6, f"record count (got {s['records']})"),
        (s["gate"]["total"] == 3, f"gate records (got {s['gate']['total']})"),
        (s["gate"]["outcomes"] == {"allow": 1, "ask": 1, "deny": 1}, f"outcomes {s['gate']['outcomes']}"),
        (s["notice"]["emphatic"] == 1, "emphatic count"),
        (s["finish"]["verdicts"] == {"would_block": 1}, "finish verdicts"),
        (s["errors"]["total"] == 1, "error counted"),
        (
            s["tokens"] == 1262 * 3 + 3425 + 1779,
            f"input tokens summed across hooks (got {s['tokens']})",
        ),
    ]


def case_choice_score_does_not_crash():
    """A choice answer logs a dict; one mixed record must not kill a whole report."""
    rows = [dict(GATE_ROW, scores={"destructive": 0.01, "failure_kind": {"transient": 0.9}})]
    s = jev_logs.summarize(rows)
    return [
        (s["gate"]["outcomes"] == {"allow": 1}, "a dict-valued score is skipped, not compared"),
    ]


def case_json_is_serialisable():
    """--json has to actually serialise, including for an empty log."""
    results = []
    for label, rows in (("populated", [GATE_ROW, NOTICE_ROW, FINISH_ROW]), ("empty", [])):
        try:
            text = json.dumps(jev_logs.summarize(rows))
            results.append((len(text) > 2, f"{label} summary serialises to JSON"))
        except (TypeError, ValueError) as exc:
            results.append((False, f"{label} summary failed to serialise: {exc}"))
    s = jev_logs.summarize([])
    results.append((s["gate"]["latency"]["median_ms"] is None, "empty log reports no median, not a crash"))
    return results


def case_scope_path_is_redacted():
    """The scope hook's `path` field is an absolute path, so it is sensitive.

    It is tempting to call a filename harmless. It is not: an absolute path
    carries the home directory, so the username, and the project name with it.
    Somebody's repo layout is not mine to publish.
    """
    out = jev_logs.redact(SCOPE_ROW)
    kept = jev_logs.redact(SCOPE_ROW, keep_commands=True)
    return [
        ("path" not in out, "path dropped by default"),
        ("path" not in kept, "path dropped even with --keep-commands"),
        ("jane.doe" not in json.dumps(out), "the username does not survive via path"),
        (out["flagged"] == ["outside_stated_scope"], "which question fired still survives"),
        (out["scores"] == SCOPE_ROW["scores"], "the probabilities survive intact"),
        (
            out.get("explained_by_continuation") is False,
            "explained_by_continuation survives -- it is the false-positive signal",
        ),
        (jev_logs.audit([SCOPE_ROW]).get("path") == 1, "audit counts path as something stripped"),
    ]


def case_scope_summary():
    """would_flag, explained, and the overlap between them.

    The overlap is the number that decides whether the check is worth anything,
    so a summary that reported it wrong would be worse than not reporting it.
    """
    explained = dict(
        SCOPE_ROW,
        explained_by_continuation=True,
        scores={**SCOPE_ROW["scores"], "continuation_ok": 0.91},
    )
    quiet = dict(SCOPE_ROW, flagged=[], verdict="in_scope", explained_by_continuation=False)
    dep = dict(
        SCOPE_ROW,
        flagged=["outside_stated_scope", "unrequested_dependency_change"],
        explained_by_continuation=False,
    )
    s = jev_logs.summarize([SCOPE_ROW, explained, quiet, quiet, dep])
    return [
        (s["scope"]["total"] == 5, f"all scope records counted (got {s['scope']['total']})"),
        (s["scope"]["would_flag"] == 3, f"flagged writes counted (got {s['scope']['would_flag']})"),
        (s["scope"]["explained"] == 1, f"explained-by-continuation counted (got {s['scope']['explained']})"),
        (
            s["scope"]["reasons"] == {"outside_stated_scope": 3, "unrequested_dependency_change": 1},
            f"per-question counts ({s['scope']['reasons']})",
        ),
        (s["tokens"] >= 980 * 5, "scope tokens are included in the spend total"),
        (s["scope"]["latency"]["median_ms"] == 341, "scope latency reported separately"),
    ]


def case_scope_does_not_pollute_other_hooks():
    """A scope record must not be counted as a gate call.

    Both are PreToolUse and both log `scores`, so the only thing separating them
    is the `hook` field. Counting scope writes as gate calls would inflate the
    'passed silently' rate that enforcement decisions are made from.
    """
    s = jev_logs.summarize([SCOPE_ROW, GATE_ROW, NOTICE_ROW])
    return [
        (s["gate"]["total"] == 1, f"gate total excludes the scope record (got {s['gate']['total']})"),
        (s["scope"]["total"] == 1, "the scope record is counted once, as scope"),
        (s["notice"]["total"] == 1, "notice is unaffected"),
    ]


def case_synthetic_records_are_excluded():
    """Fixture and verify.sh records must not be counted as real traffic.

    This is issue #1's other half. That issue was about the test suites logging
    into the real audit log; it was fixed for tests/, and verify.sh -- which runs
    the same hooks on the same invented payloads -- was not covered, so it kept
    writing. 89 such records were already in a real log, and because every
    synthetic payload is engineered to be a clear block, the bias was one-way:

        as logged:  100 of 248 turns flagged = 40.3%
        real only:   24 of 157 turns flagged = 15.3%

    A reader seeing 40% concludes the completion check is far too chatty to
    enforce, from its own test data.
    """
    fixture_run = {**FINISH_ROW, "cwd": "/Users/jane.doe@corp.example.com/some-project"}
    ci_run = {**FINISH_ROW, "cwd": "/home/runner/some-project"}
    probe = {**FINISH_ROW, "request_head": "Fix the failing test in src/utils."}
    # The fixtures also say "Deploy to staging." and "What does the usage module
    # do?", which are things a person genuinely says. Matching those as prose
    # would delete real evidence to make a number look better -- a worse bug than
    # the one being fixed -- so only a cwd tell or an exact probe match counts.
    real_but_similar = {
        **FINISH_ROW,
        "request_head": "Deploy to staging.",
        "cwd": "/Users/jane.doe@corp.example.com/billing-service",
    }

    # The Stop probe was the only one this filter knew about at first, so the gate
    # and notice probes below were still counted as real traffic -- and they are
    # the loudest records in the log, because both are built to be caught. 34 of
    # a reported 62 gate blocks were this one command.
    gate_probe = {
        "hook": "gate",
        "cwd": "/Users/jane.doe@corp.example.com",
        "state_head": (
            "Working directory: /Users/jane.doe@corp.example.com\n\nTool: Bash\n\n"
            "Command:\nrm -rf / --no-preserve-root\n\nStated purpose: cleanup"
        ),
        "scores": {"destructive": 0.98},
    }
    notice_probe = {
        "hook": "notice",
        "command": "npm test 2>&1 | tail -3",
        "scores": {"output_shows_failure": 0.97},
        "noticed": True,
    }
    # Full-command equality, not substring. Someone really does run `npm test`,
    # and a command that merely CONTAINS the probe text -- grepping for it,
    # writing it into a test, discussing it -- is real work being done on this
    # repo. Both of these must survive.
    real_npm_test = {
        "hook": "notice",
        "command": "npm test",
        "scores": {"output_shows_failure": 0.9},
        "noticed": True,
    }
    real_mentions_probe = {
        "hook": "gate",
        "cwd": "/Users/jane.doe@corp.example.com/the-jev-enator",
        "state_head": (
            "Working directory: /Users/jane.doe@corp.example.com/the-jev-enator\n\n"
            "Tool: Bash\n\nCommand:\ngrep -rn 'rm -rf / --no-preserve-root' verify.sh"
            "\n\nStated purpose: find the probe"
        ),
        "scores": {"destructive": 0.04},
    }

    rows = [FINISH_ROW, fixture_run, ci_run, probe, real_but_similar,
            gate_probe, notice_probe, real_npm_test, real_mentions_probe]
    kept, dropped = jev_logs.drop_synthetic(rows)
    kept_heads = [r.get("request_head") for r in kept if r.get("request_head")]

    return [
        (dropped == 5, f"five synthetic records dropped (got {dropped})"),
        (jev_logs.is_synthetic(fixture_run), "a pinned fixture cwd is synthetic"),
        (jev_logs.is_synthetic(ci_run), "the CI runner's pinned cwd is synthetic too"),
        (jev_logs.is_synthetic(probe), "a verify.sh Stop probe is synthetic"),
        (jev_logs.is_synthetic(gate_probe), "the verify.sh gate probe is synthetic"),
        (jev_logs.is_synthetic(notice_probe), "the verify.sh notice probe is synthetic"),
        (
            not jev_logs.is_synthetic(real_but_similar),
            "a real turn whose text resembles a fixture is KEPT",
        ),
        (
            not jev_logs.is_synthetic(real_npm_test),
            "a real `npm test` is KEPT (probe match is the whole command)",
        ),
        (
            not jev_logs.is_synthetic(real_mentions_probe),
            "a real command that only MENTIONS the probe is KEPT",
        ),
        (
            "Deploy to staging." in kept_heads and FINISH_ROW["request_head"] in kept_heads,
            f"both real records survive ({kept_heads})",
        ),
        (
            jev_logs.summarize(kept)["finish"]["total"] == 2,
            "the summary counts only the real turns",
        ),
    ]


CASES = [
    ("load skips unparseable lines", case_load_skips_garbage),
    ("fixture and probe records are excluded", case_synthetic_records_are_excluded),
    ("merging tags sources and drops duplicates", case_merge_tags_and_dedupes),
    ("per-source summaries keep machines distinct", case_by_source_separates_machines),
    ("--since excludes unstamped records", case_since_excludes_unstamped),
    ("redaction drops every sensitive field", case_redact_drops_sensitive_fields),
    ("an unclassified field is dropped", case_unknown_field_is_dropped),
    ("--keep-commands scrubs known secret shapes", case_keep_commands_scrubs_secrets),
    ("a bare account name is scrubbed", case_bare_account_name_is_scrubbed),
    ("--keep-commands still drops cwd and prompts", case_keep_commands_still_drops_prompts),
    ("errors are scrubbed and truncated", case_error_is_truncated_not_trusted),
    ("audit counts what would have leaked", case_audit_counts_what_would_leak),
    ("summary matches a hand count", case_summary_matches_hand_count),
    ("a choice score does not crash a report", case_choice_score_does_not_crash),
    ("summaries serialise, including empty ones", case_json_is_serialisable),
    ("the scope hook's path is redacted", case_scope_path_is_redacted),
    ("scope summary counts flags and the overlap", case_scope_summary),
    ("scope records are not counted as gate calls", case_scope_does_not_pollute_other_hooks),
]


def main() -> int:
    failures = 0
    for label, fn in CASES:
        print(f"\n{label}")
        try:
            results = fn()
        except Exception as exc:  # noqa: BLE001 -- a crashing case is a failing case
            print(f"  FAIL  case raised {type(exc).__name__}: {exc}")
            failures += 1
            continue
        for ok, detail in results:
            if not ok:
                failures += 1
            print(f"  {'PASS' if ok else 'FAIL'}  {detail}")

    print()
    if failures:
        print(f"{failures} assertion(s) failed")
    else:
        print("all assertions passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
