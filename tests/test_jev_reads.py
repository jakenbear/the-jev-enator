#!/usr/bin/env python3
"""Check jev_reads.py: the chunker and verdict offline, then real rankings.

Two halves, because they answer different questions.

The first half needs no key. It pins the chunker and the verdict rule, which is
where a quiet bug does the most damage: a chunk boundary one line off puts a
function's signature under its neighbour's label, and Jev then ranks the wrong
region with full confidence.

The second half fires Read payloads at the hook with a transcript behind them
and reads the log, like the scope suite -- this hook prints nothing, ever. The
cases that matter are the ones that must NOT narrow: an overview, a reformat, a
review. Narrowing those would hide most of the file from an agent that needs all
of it, and it would not know.

Run:
  python3 tests/test_jev_reads.py                                 offline half only
  JEV_REPLAY=tests/cassette.json python3 tests/test_jev_reads.py  both, replayed
  source .env && python3 tests/test_jev_reads.py                  both, live
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOK = os.path.join(REPO, "src", "jev_reads.py")

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(REPO, "src"))
from fixture_env import fixture_log, hook_env, replay_miss, replaying, report  # noqa: E402

import jev_reads  # noqa: E402

# ---------------------------------------------------------------------------
# Fixture files. Deterministic, because the file text is in the scored state and
# the cassette key is a hash of it.

FUNCS = [
    ("load_config", "Read billing.toml and return the merged settings dict.", "toml.load(path)"),
    ("load_customers", "Fetch active customers from the accounts table.", "db.query('SELECT * FROM customers WHERE active')"),
    ("compute_tax", "Sales tax by province. QC is GST plus QST.", "RATES = {'ON': 0.13, 'QC': 0.13, 'BC': 0.12}"),
    ("apply_discount", "Apply a coupon code to a line-item subtotal.", "coupon.percent_off * subtotal / 100"),
    ("build_line_items", "Turn a cart into priced line items.", "LineItem(sku, qty, price)"),
    ("render_invoice_pdf", "Render an invoice to PDF with the company letterhead.", "pdf.draw_text(x, y, total)"),
    ("send_invoice_email", "Email the PDF to the billing contact.", "smtp.send(to=contact, attachment=pdf)"),
    ("retry_webhook", "Retry a failed Stripe webhook with exponential backoff.", "time.sleep(2 ** attempt)"),
    ("reconcile_payments", "Match Stripe payouts against open invoices.", "payout.amount == invoice.total"),
    ("refund_charge", "Issue a full or partial refund through Stripe.", "stripe.Refund.create(charge=cid)"),
    ("export_csv", "Export a month of invoices as CSV for accounting.", "csv.writer(fh).writerow(row)"),
    ("archive_old_invoices", "Move invoices older than seven years to cold storage.", "s3.copy(key, bucket='archive')"),
]


def billing_module() -> str:
    out = ['"""Billing: invoices, tax, payments."""', "", "import csv", "import time", "", ""]
    for name, doc, core in FUNCS:
        if name == "retry_webhook":
            out.append("@with_logging")
        out.append(f"# {doc}")
        out.append(f"def {name}(*args, **kwargs):")
        out.append(f'    """{doc}"""')
        out.append(f"    result = {core}")
        for k in range(19):
            out.append(f"    step_{k} = _{name}_step({k}, result)  # {name} stage {k}")
        out.append("    return result")
        out.append("")
        out.append("")
    return "\n".join(out) + "\n"


SECTIONS = [
    ("Install", "Requires Python 3.9 or later. Run ./install.sh, then restart Claude Code."),
    ("Configuration", "Set TYPESAFE_API_KEY in .env. JEV_LOG sets where the audit log goes."),
    ("The danger gate", "Scores each Bash command before it runs and asks on destructive ones."),
    ("The failure notice", "Reads command output and tells the agent when a test failed."),
    ("The completion check", "Runs on Stop and logs whether the work was actually finished."),
    ("Troubleshooting", "If nothing is logged, run ./verify.sh and read the first FAIL."),
    ("License", "MIT."),
]


def readme() -> str:
    out = ["# Example project", "", "A tool that does things.", ""]
    for title, body in SECTIONS:
        out.append(f"## {title}")
        out.append("")
        for k in range(45):
            out.append(f"{body} (paragraph {k} of the {title.lower()} section)")
        out.append("")
    return "\n".join(out) + "\n"


def line_of(text: str, needle: str) -> int:
    for i, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return i
    raise AssertionError(f"{needle!r} not in fixture")


# ---------------------------------------------------------------------------
# Offline half


def case_chunks_attach_comments_and_decorators():
    text = billing_module()
    lines = text.splitlines()
    chunks = jev_reads.chunk_file(lines, "billing.py")
    starts = {s for s, _ in chunks}
    comment = line_of(text, "# Sales tax by province")
    deco = line_of(text, "@with_logging")
    return [
        (len(lines) >= jev_reads.MIN_LINES, f"fixture is big enough to be judged ({len(lines)} lines)"),
        (comment in starts, "a function's chunk starts at its leading comment"),
        (deco in starts, "a decorated function's chunk starts at the decorator"),
        (deco + 2 not in starts, "the def under a decorator does not start a second chunk"),
        (chunks[0][0] == 1 and chunks[-1][1] == len(lines), "chunks cover the file end to end"),
        (all(a[1] + 1 == b[0] for a, b in zip(chunks, chunks[1:])), "no gaps, no overlaps"),
    ]


def case_markdown_uses_headings_python_does_not():
    md = readme().splitlines()
    md_chunks = jev_reads.chunk_file(md, "README.md")
    py = ["# a comment", "x = 1"] * 200
    py_chunks = jev_reads.chunk_file(py, "notes.py")
    install = line_of(readme(), "## Install")
    return [
        (install in {s for s, _ in md_chunks}, "a markdown section starts a chunk"),
        (len(py_chunks) < 40, f"python comments are not headings ({len(py_chunks)} chunks for 400 lines)"),
    ]


def case_chunk_limits():
    many = []
    for k in range(80):
        many += [f"def f{k}():", "    return 1", ""]
    many += ["x = 0"] * 100
    chunks = jev_reads.chunk_file(many, "m.py")
    giant = ["class Big:"] + ["    def m(self): pass"] * 700
    giant_chunks = jev_reads.chunk_file(giant + ["def a(): pass", "def b(): pass"], "g.py")
    return [
        (len(chunks) <= jev_reads.MAX_CHUNKS, f"at most {jev_reads.MAX_CHUNKS} options (got {len(chunks)})"),
        (
            max(e - s + 1 for s, e in giant_chunks) <= jev_reads.MAX_CHUNK_LINES,
            "a 700-line class is split into windows, not one option the size of the file",
        ),
    ]


def case_decide():
    lines = ["x" * 39] * 400  # 40 chars per line with the newline
    chunks = [(1, 20), (21, 380), (381, 400)]
    narrow = jev_reads.decide({"1": 0.8, "2": 0.1, "whole_file": 0.1}, chunks, lines)
    close = jev_reads.decide({"1": 0.45, "3": 0.35, "whole_file": 0.2}, chunks, lines)
    low = jev_reads.decide({"1": 0.35, "2": 0.05, "whole_file": 0.3}, chunks, lines)
    whole = jev_reads.decide({"1": 0.2, "whole_file": 0.7}, chunks, lines)
    big = jev_reads.decide({"2": 0.9, "whole_file": 0.1}, chunks, lines)
    junk = jev_reads.decide({"99": 0.9}, chunks, lines)
    return [
        (narrow["verdict"] == "would_narrow", f"clear winner narrows ({narrow['verdict']})"),
        (narrow.get("region") == [1, 20], "region is the winning chunk's lines"),
        (narrow.get("saved_tokens") == (400 - 20) * 40 // 4, f"saved tokens counted ({narrow.get('saved_tokens')})"),
        (close["verdict"] == "too_close", f"a 0.10 margin is too close ({close['verdict']})"),
        (low["verdict"] == "too_close", f"a winner under REGION_AT does not narrow ({low['verdict']})"),
        (whole["verdict"] == "whole_file", "whole_file wins as itself"),
        (big["verdict"] == "region_too_big", "a region that is most of the file is not a narrowing"),
        (junk["verdict"] == "no_answer", "an unknown label is not a crash"),
    ]


def run_hook(payload, log_path, env_extra=None):
    proc = subprocess.run(
        [sys.executable, HOOK],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        env=hook_env(log_path, **(env_extra or {})),
    )
    record = None
    if os.path.exists(log_path):
        rows = [json.loads(l) for l in open(log_path).read().splitlines() if l.strip()]
        record = rows[-1] if rows else None
    return proc, record


def case_skips_without_calling_jev():
    tmp = tempfile.mkdtemp()
    try:
        small = os.path.join(tmp, "small.py")
        big = os.path.join(tmp, "big.py")
        with open(small, "w") as fh:
            fh.write("def a():\n    pass\n" * 20)
        with open(big, "w") as fh:
            fh.write(billing_module())
        results = []
        for label, tool_input in (
            ("a small file", {"file_path": small}),
            ("a read with an offset", {"file_path": big, "offset": 100, "limit": 50}),
            ("an image", {"file_path": os.path.join(tmp, "shot.png")}),
            ("a missing file", {"file_path": os.path.join(tmp, "nope.py")}),
        ):
            log = os.path.join(tmp, f"log-{len(results)}.jsonl")
            proc, record = run_hook(
                {"tool_name": "Read", "tool_input": tool_input, "transcript_path": "/nonexistent"},
                log,
                {"TYPESAFE_API_KEY": "sk-not-used"},
            )
            results.append((record is None and not proc.stdout.strip() and proc.returncode == 0,
                            f"{label} is skipped with no call and no output"))
        return results
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


OFFLINE = [
    ("chunks: comments and decorators", case_chunks_attach_comments_and_decorators),
    ("chunks: markdown vs code", case_markdown_uses_headings_python_does_not),
    ("chunks: limits", case_chunk_limits),
    ("verdict rule", case_decide),
    ("skips before any call", case_skips_without_calling_jev),
]

# ---------------------------------------------------------------------------
# Scored half.
#
# (label, file name, file text, request, accepted verdicts, line the region must contain)


def user(text):
    return {"type": "user", "message": {"role": "user", "content": text}}


BILLING = billing_module()
README = readme()

SCORED = [
    (
        "narrow: the one function the bug is in",
        "billing.py",
        BILLING,
        "Quebec invoices are charging 13% tax. compute_tax should use 14.975% for QC.",
        {"would_narrow"},
        line_of(BILLING, "def compute_tax"),
    ),
    (
        "narrow: the webhook retry",
        "billing.py",
        BILLING,
        "The Stripe webhook retries hammer the endpoint -- the backoff never grows. Fix it.",
        {"would_narrow"},
        line_of(BILLING, "def retry_webhook"),
    ),
    (
        "narrow: one markdown section",
        "README.md",
        README,
        "The README install section still says Python 3.9. It needs 3.10 now -- update it.",
        {"would_narrow"},
        line_of(README, "## Install"),
    ),
    (
        "whole: an overview",
        "billing.py",
        BILLING,
        "What does billing.py do? Give me a quick tour before I start changing it.",
        {"whole_file", "too_close"},
        None,
    ),
    (
        "whole: a change to every function",
        "billing.py",
        BILLING,
        "Add type hints to every function in billing.py.",
        {"whole_file", "too_close"},
        None,
    ),
    (
        "whole: a review",
        "README.md",
        README,
        "Proofread the README and fix any typos or unclear sentences.",
        {"whole_file", "too_close"},
        None,
    ),
]


def scored_cases() -> int:
    tmp = tempfile.mkdtemp()
    # The last three path components are in the state, so the directory under the
    # random temp root is fixed: the cassette key must not change run to run.
    project = os.path.join(tmp, "proj", "src")
    os.makedirs(project)
    log_path = fixture_log("reads")
    failures = 0
    try:
        for label, name, text, request, accepted, must_contain in SCORED:
            path = os.path.join(project, name)
            with open(path, "w") as fh:
                fh.write(text)
            transcript = os.path.join(tmp, "t.jsonl")
            with open(transcript, "w") as fh:
                fh.write(json.dumps(user(request)) + "\n")
            case_log = log_path + ".case"
            proc, record = run_hook(
                {"hook_event_name": "PreToolUse", "tool_name": "Read",
                 "tool_input": {"file_path": path}, "transcript_path": transcript},
                case_log,
            )
            if os.path.exists(case_log):
                with open(case_log) as src, open(log_path, "a") as out:
                    out.write(src.read())
                os.unlink(case_log)

            if replay_miss(proc):
                print(f"FAIL  {label}\n      replay miss -- re-record the cassette")
                failures += 1
                continue
            if record is None or "verdict" not in record:
                print(f"FAIL  {label}\n      no verdict logged: {record!r:.160} {proc.stderr.strip()[:160]}")
                failures += 1
                continue
            region = record.get("region") or [0, 0]
            ok = record["verdict"] in accepted and (
                must_contain is None or region[0] <= must_contain <= region[1]
            )
            if proc.stdout.strip():
                ok = False
                print(f"      emitted output in shadow mode: {proc.stdout.strip()[:120]}")
            failures += not ok
            print(f"{'PASS' if ok else 'FAIL'}  {label}")
            print(
                f"      {record['verdict']}  winner={record.get('winner')} p={record.get('top')} "
                f"margin={record.get('margin')} region={record.get('region')} saved={record.get('saved_tokens')}"
            )
            if not ok:
                print(f"      expected {sorted(accepted)}" + (f" containing line {must_contain}" if must_contain else ""))

        # JEV_READS_OFF must stop it before any call.
        label, name, text, request, *_ = SCORED[0]
        case_log = log_path + ".off"
        proc, record = run_hook(
            {"tool_name": "Read", "tool_input": {"file_path": os.path.join(project, name)},
             "transcript_path": transcript},
            case_log,
            {"JEV_READS_OFF": "1"},
        )
        if record is not None or proc.stdout.strip():
            print("FAIL  JEV_READS_OFF=1 did not stop the hook")
            failures += 1
        else:
            print("PASS  JEV_READS_OFF=1 stops it before any call is made")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    report(log_path)
    return failures


def main() -> int:
    failures = 0
    for label, fn in OFFLINE:
        print(f"\n{label}")
        try:
            results = fn()
        except Exception as exc:  # noqa: BLE001 -- a crashing case is a failing case
            print(f"  FAIL  case raised {type(exc).__name__}: {exc}")
            failures += 1
            continue
        for ok, detail in results:
            failures += not ok
            print(f"  {'PASS' if ok else 'FAIL'}  {detail}")

    print()
    if replaying() or os.environ.get("TYPESAFE_API_KEY"):
        failures += scored_cases()
    else:
        print("scored cases skipped: no key and no JEV_REPLAY")

    print()
    print(f"{failures} failure(s)" if failures else "all reads checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
