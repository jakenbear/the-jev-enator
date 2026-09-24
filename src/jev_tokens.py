#!/usr/bin/env python3
"""Where do the tokens in a Claude Code session actually go?

Reads the transcripts under ~/.claude/projects and reports, from what was
recorded rather than estimated from outside:

  - totals per API call, split into fresh input, cache writes, cache reads and
    output, deduplicated by message id (one message is often several rows, each
    repeating the same usage block)
  - how large the context was when each call was made, and how often it was large
  - which tool results were biggest, and what they cost in total

The last one is the number that matters, and it is not the size of the result. A
tool result enters the context once and is then re-read on every later call until
the session compacts or ends. A 20k-token log dump early in a 200-call session
costs 4M tokens of reads, not 20k. That is "carried" below.

No Jev, no API, no network. Carried tokens are estimated at 4 characters per
token, which is rough for code and good enough to rank things.

Usage:
  ./tokens.sh                       every transcript
  ./tokens.sh --since 2026-09-01    only rows from this date on
  ./tokens.sh --project the-jev     only projects whose directory contains this
  ./tokens.sh --top 20              longer "biggest results" list
"""

import argparse
import glob
import json
import os
import sys
from collections import defaultdict
from dataclasses import dataclass, field

CHARS_PER_TOKEN = 4

# The context sizes the ideas in the README turn on. 60k is where a /clear
# suggestion starts to be worth making; below it there is little to save.
CONTEXT_BANDS = (60_000, 100_000, 150_000)

# A result this large is the kind a big-output guard would have stopped.
BIG_RESULT_CHARS = 10_000


def est_tokens(chars: int) -> int:
    return chars // CHARS_PER_TOKEN


@dataclass
class Result:
    """One tool result or hook injection that entered the context."""

    kind: str  # tool name, or "hook:<name>"
    label: str  # command, path, or hook name -- for the reader
    chars: int
    later_calls: int = 0  # API calls that re-read it before a compaction
    hit_cut: bool = False  # output too large to show in full; agent saw a preview

    @property
    def carried(self) -> int:
        return est_tokens(self.chars) * self.later_calls


@dataclass
class Stats:
    sessions: int = 0
    calls: int = 0
    fresh: int = 0
    cache_write: int = 0
    cache_read: int = 0
    output: int = 0
    contexts: list = field(default_factory=list)
    compactions: list = field(default_factory=list)  # (trigger, preTokens)
    results: list = field(default_factory=list)


def block_text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text"
        )
    return ""


def describe_call(name: str, args: dict) -> str:
    for key in ("command", "file_path", "notebook_path", "pattern", "url", "prompt", "description"):
        if isinstance(args.get(key), str) and args[key]:
            return " ".join(args[key].split())[:90]
    return ""


# Hook output the model actually reads. SessionStart and UserPromptSubmit stdout
# goes into context; for other events only an explicit additionalContext does.
CONTEXT_HOOK_EVENTS = ("SessionStart", "UserPromptSubmit")


def attachment_text(attachment: dict) -> str:
    """An attachment's content as text: a string, or a list of strings or blocks."""
    content = attachment.get("content")
    if isinstance(content, list):
        return "\n".join(c if isinstance(c, str) else block_text([c]) for c in content)
    return content if isinstance(content, str) else ""


def hook_injection(attachment: dict) -> tuple[str, str] | None:
    kind = attachment.get("type")
    text = attachment_text(attachment)
    if not text.strip():
        return None
    if kind == "hook_additional_context" or (
        kind == "hook_success" and attachment.get("hookEvent") in CONTEXT_HOOK_EVENTS
    ):
        name = attachment.get("hookName") or attachment.get("hookEvent") or "additional context"
        # Name the injection by its first line, so two SessionStart hooks show up
        # separately rather than as one lump.
        first = text.strip().splitlines()[0][:50]
        return f"hook:{name}", first
    return None


def scan_file(path: str, since: str | None, stats: Stats) -> None:
    """Add one transcript's numbers to stats.

    Two passes over the rows: the first records every API call and every result
    in order, the second counts, for each result, the calls made after it and
    before the next compaction -- which is how many times it was re-read.
    """
    timeline = []  # ("call", None) | ("result", Result) | ("compact", None)
    seen_ids = set()
    tool_uses = {}  # tool_use id -> (name, label)
    persisted = set()  # tool_use ids whose output hit the size cut

    try:
        fh = open(path, errors="replace")
    except OSError:
        return
    with fh:
        for line in fh:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(row, dict):
                continue
            if since and (row.get("timestamp") or "")[:10] < since:
                continue
            kind = row.get("type")
            message = row.get("message") if isinstance(row.get("message"), dict) else {}

            if kind == "system" and row.get("subtype") == "compact_boundary":
                meta = row.get("compactMetadata") or {}
                stats.compactions.append((meta.get("trigger", "?"), meta.get("preTokens") or 0))
                timeline.append(("compact", None))
                continue

            if kind == "assistant":
                for block in message.get("content") or []:
                    if isinstance(block, dict) and block.get("type") == "tool_use":
                        name = block.get("name", "?")
                        tool_uses[block.get("id")] = (name, describe_call(name, block.get("input") or {}))
                usage = message.get("usage")
                mid = message.get("id")
                if not usage or mid in seen_ids:
                    continue
                seen_ids.add(mid)
                fresh = usage.get("input_tokens") or 0
                write = usage.get("cache_creation_input_tokens") or 0
                read = usage.get("cache_read_input_tokens") or 0
                stats.calls += 1
                stats.fresh += fresh
                stats.cache_write += write
                stats.cache_read += read
                stats.output += usage.get("output_tokens") or 0
                stats.contexts.append(fresh + write + read)
                timeline.append(("call", None))
                continue

            if kind == "user":
                tur = row.get("toolUseResult")
                content = message.get("content")
                if isinstance(content, list):
                    for block in content:
                        if not isinstance(block, dict) or block.get("type") != "tool_result":
                            continue
                        tid = block.get("tool_use_id")
                        if isinstance(tur, dict) and tur.get("persistedOutputPath"):
                            persisted.add(tid)
                        name, label = tool_uses.get(tid, ("?", ""))
                        text = block_text(block.get("content"))
                        timeline.append(
                            ("result", Result(name, label, len(text), hit_cut=tid in persisted))
                        )
                continue

            if kind == "attachment":
                found = hook_injection(row.get("attachment") or {})
                if found:
                    name, label = found
                    text = attachment_text(row.get("attachment") or {})
                    timeline.append(("result", Result(name, label, len(text))))

    if not seen_ids:
        return
    stats.sessions += 1

    # Walk backwards so each result sees the count of calls after it.
    calls_after = 0
    for kind, item in reversed(timeline):
        if kind == "call":
            calls_after += 1
        elif kind == "compact":
            calls_after = 0
        else:
            item.later_calls = calls_after
            stats.results.append(item)


def transcripts(project: str | None) -> list[str]:
    root = os.path.expanduser("~/.claude/projects")
    # Main sessions, plus subagent transcripts nested under a session directory.
    paths = glob.glob(os.path.join(root, "*", "*.jsonl")) + glob.glob(
        os.path.join(root, "*", "*", "subagents", "*.jsonl")
    )
    if project:
        paths = [p for p in paths if project in os.path.relpath(p, root).split(os.sep)[0]]
    return sorted(paths)


def pct(part: float, whole: float) -> str:
    return f"{100 * part / whole:5.1f}%" if whole else "    -"


def fmt(n: int) -> str:
    for unit, size in (("B", 1_000_000_000), ("M", 1_000_000), ("k", 1_000)):
        if abs(n) >= size:
            return f"{n / size:.1f}{unit}"
    return str(n)


def quantile(values: list, q: float) -> int:
    if not values:
        return 0
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(q * len(ordered)))]


def report(stats: Stats, top: int) -> str:
    out = []
    say = out.append
    total_in = stats.fresh + stats.cache_write + stats.cache_read

    say(f"{stats.sessions} transcripts, {stats.calls} API calls\n")
    say("Tokens")
    say(f"  input, fresh            {fmt(stats.fresh):>8}  {pct(stats.fresh, total_in)}")
    say(f"  input, cache write      {fmt(stats.cache_write):>8}  {pct(stats.cache_write, total_in)}")
    say(f"  input, cache read       {fmt(stats.cache_read):>8}  {pct(stats.cache_read, total_in)}")
    say(f"  output                  {fmt(stats.output):>8}")
    say("  Cache reads bill at about a tenth of fresh input, so they dominate the")
    say("  count far more than the bill. They still count against rate limits.\n")

    ctx = stats.contexts
    say("Context size per call")
    say(f"  median {fmt(quantile(ctx, 0.5))}   p90 {fmt(quantile(ctx, 0.9))}   max {fmt(max(ctx, default=0))}")
    for band in CONTEXT_BANDS:
        over = [c for c in ctx if c > band]
        say(
            f"  over {fmt(band):>4}: {len(over):6} calls {pct(len(over), len(ctx))}   "
            f"reading {fmt(sum(over)):>7} tokens {pct(sum(over), total_in)} of all input"
        )
    auto = [p for t, p in stats.compactions if t == "auto"]
    manual = [p for t, p in stats.compactions if t != "auto"]
    say(
        f"  compactions: {len(auto)} auto, {len(manual)} manual"
        + (f"; auto fired at a median {fmt(quantile(auto, 0.5))}" if auto else "")
    )
    say("")

    by_kind = defaultdict(lambda: [0, 0, 0])  # count, chars, carried
    for r in stats.results:
        entry = by_kind[r.kind]
        entry[0] += 1
        entry[1] += r.chars
        entry[2] += r.carried
    carried_total = sum(r.carried for r in stats.results)

    say("What entered the context, ranked by carried cost (re-read on every later call)")
    say(f"  {'source':34} {'count':>6} {'size':>8} {'carried':>9}  share of input")
    ranked = sorted(by_kind.items(), key=lambda kv: kv[1][2], reverse=True)
    for kind, (count, chars, carried) in ranked[:12]:
        say(f"  {kind[:34]:34} {count:6} {fmt(est_tokens(chars)):>8} {fmt(carried):>9}  {pct(carried, total_in)}")
    say("")

    big = [r for r in stats.results if r.chars >= BIG_RESULT_CHARS and not r.kind.startswith("hook:")]
    cut = [r for r in stats.results if r.hit_cut]
    say(f"Tool results over {fmt(BIG_RESULT_CHARS)} chars: {len(big)}")
    say(f"  carried {fmt(sum(r.carried for r in big))} tokens, {pct(sum(r.carried for r in big), total_in)} of all input")
    say(f"  {len(cut)} were too large to show in full (the agent saw a 2KB preview)\n")

    say(f"Top {top} single items by carried cost")
    for r in sorted(stats.results, key=lambda r: r.carried, reverse=True)[:top]:
        say(
            f"  {fmt(r.carried):>7}  {fmt(est_tokens(r.chars)):>6} x {r.later_calls:<4} "
            f"{r.kind[:22]:22} {r.label[:60]}"
        )
    say("")
    say(f"Carried totals are estimates at {CHARS_PER_TOKEN} chars/token; the Tokens block is exact.")
    return "\n".join(out)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--since", help="only rows on or after YYYY-MM-DD")
    parser.add_argument("--project", help="only project directories containing this text")
    parser.add_argument("--top", type=int, default=10)
    args = parser.parse_args(argv)

    paths = transcripts(args.project)
    if not paths:
        print("No transcripts found under ~/.claude/projects.", file=sys.stderr)
        return 1
    stats = Stats()
    for path in paths:
        scan_file(path, args.since, stats)
    if not stats.calls:
        print("Transcripts found, but none had usage in range.", file=sys.stderr)
        return 1
    print(report(stats, args.top))
    return 0


if __name__ == "__main__":
    sys.exit(main())
