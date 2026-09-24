#!/usr/bin/env python3
"""Jev-backed relevance ranking for whole-file Reads. SHADOW MODE: log only.

WHY THIS EXISTS

./tokens.sh on one developer's transcripts found the single biggest cost item was
not a log dump or a runaway command. It was whole-file Reads: a 10k-token file
read once and then re-read, as part of the context, on every one of the next
100-200 API calls. One such read carried 1.4M tokens. The agent usually needed a
function or two.

WHAT IT DOES

Before a Read of a large file with no offset/limit, it splits the file into
chunks at top-level definitions (or headings, or fixed windows), and asks Jev one
`choice` question: given what the user asked for, which chunk should be read?
The distribution over chunks IS the ranking -- N chunks, one call, the same trick
tests/spike_grep_rank.py measured at #45 -> #1 on a real search.

`whole_file` is one of the options, and it is what keeps the others honest. An
overview, a review, or a rewrite needs the whole file, and without an escape
hatch the probability mass would be forced onto some chunk anyway -- the same
reason jev_notice has needs_code_change.

A winner is only named when it clears REGION_AT and beats second place by
REGION_MARGIN. A near-tie is a real answer here too: narrowing a read to the
wrong function is worse than reading the whole file, because the agent does not
know what it did not see.

SHADOW MODE, AND WHY

It emits nothing. It logs what it would have suggested and how many tokens that
would have saved. Narrowing a read fails UNSAFE -- a missed function is invisible
to the agent -- so whether it is right often enough has to be read off the log,
with `./jev reads`, before anything acts on it. Same path the completion check
took.

Env:
  TYPESAFE_API_KEY   required, else the hook no-ops
  JEV_LOG            path for the JSONL audit log (required to be useful)
  JEV_DISABLE        set to 1 to bypass every hook in this repo
  JEV_READS_OFF      set to 1 to turn off just this hook

Also: `jev_reads.py --report` prints the shadow log, for `./jev reads`.
"""

import json
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# ORDER MATTERS -- see the same comment in jev_gate.py.
from jev_pyversion import require_python

require_python()

from jev_client import JevError, api_key, ask_jev, disabled, env_var, log, read_payload, top_two  # noqa: E402
from jev_finish import load_transcript  # noqa: E402
from jev_scope import recent_requests  # noqa: E402

# Below this, a whole-file read is cheap enough that ranking it costs more in
# latency than it could save in tokens.
MIN_LINES = 300

# A choice question's criteria map grows with every option. The grep spike ran
# 20 per call; the same budget here.
MAX_CHUNKS = 20

# A chunk longer than this is split into windows, so a 600-line class is not one
# option the size of the file.
MAX_CHUNK_LINES = 150

# Characters of each chunk shown to Jev: its first line (the signature) and what
# follows. The signature carries most of the signal; the body disambiguates.
SNIPPET_CHARS = 320

# Name a region only if it wins, and wins clearly. Set from the fixtures, where
# clear winners scored well above these and honest ties well below.
REGION_AT = 0.40
REGION_MARGIN = 0.20

# A region that is most of the file is not worth narrowing to.
MAX_REGION_SHARE = 0.5

SKIP_SUFFIXES = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".pdf", ".ipynb", ".svg", ".ico",
    ".lock", ".min.js", ".map",
}

# A line that starts a top-level unit, across the languages this is likely to
# meet. Column 0 only: indented matches are methods, handled by the window split.
BOUNDARY = re.compile(
    r"^(?:export\s+(?:default\s+)?)?(?:async\s+)?"
    r"(?:def|class|function|interface|type|enum|const|let|var|fn|func|impl|struct|trait|mod|pub|describe|test|it)\b"
    r"|^@\w"  # a decorator starts the definition it decorates
)

# In markdown the units are sections. Only there: in Python a column-0 `#` is a
# comment, and treating comments as boundaries splits every function from its
# own explanation.
HEADING = re.compile(r"^#{1,3}\s")
MARKDOWN = (".md", ".mdx", ".markdown", ".rst")

# Lines directly above a definition that belong to it: its comment and its
# decorators. A chunk that starts at `def` and leaves its comment in the chunk
# before hands Jev the explanation under the wrong label.
LEADING = ("@", "#", "//", "/*", "*", "--", ";")

WHOLE_FILE = "whole_file"


def chunk_starts(lines: list[str], markdown: bool) -> list[int]:
    starts = []
    for i, line in enumerate(lines):
        if markdown:
            if HEADING.match(line):
                starts.append(i + 1)
            continue
        if not BOUNDARY.match(line):
            continue
        j = i
        while j > 0 and lines[j - 1].strip() and lines[j - 1].lstrip().startswith(LEADING):
            j -= 1
        # A def under a decorator that already started a chunk is that chunk.
        if starts and j + 1 <= starts[-1]:
            continue
        starts.append(j + 1)
    return starts


def chunk_file(lines: list[str], path: str = "") -> list[tuple[int, int]]:
    """Split a file into (start, end) line ranges, 1-based and inclusive."""
    n = len(lines)
    starts = chunk_starts(lines, path.lower().endswith(MARKDOWN))

    if len(starts) < 3:
        # No usable structure: prose, config, data. Fixed windows.
        size = max(60, -(-n // MAX_CHUNKS))
        starts = list(range(1, n + 1, size))
    elif starts[0] != 1:
        starts.insert(0, 1)  # the imports and module docstring

    chunks = [(s, (starts[k + 1] - 1) if k + 1 < len(starts) else n) for k, s in enumerate(starts)]

    split = []
    for s, e in chunks:
        while e - s + 1 > MAX_CHUNK_LINES:
            split.append((s, s + 99))
            s += 100
        split.append((s, e))

    # Too many options: merge the adjacent pair that is smallest together, which
    # folds runs of one-line constants and small helpers before anything big.
    while len(split) > MAX_CHUNKS:
        k = min(range(len(split) - 1), key=lambda i: split[i + 1][1] - split[i][0])
        split[k : k + 2] = [(split[k][0], split[k + 1][1])]
    return split


def short_path(path: str) -> str:
    """The last three path components: enough to name the file, stable across machines."""
    return "/".join(Path(path).parts[-3:])


def snippet(lines: list[str], start: int, end: int) -> str:
    body = "\n".join(lines[start - 1 : end])
    return body[:SNIPPET_CHARS]


def build_state(requests: list[str], path: str, lines: list[str], chunks: list[tuple[int, int]]) -> str:
    parts = [
        "## What the user asked for, oldest message first\n"
        + "\n\n".join(f"[{i}] {text[:1500]}" for i, text in enumerate(requests, 1)),
        f"## The assistant is about to read the whole of {short_path(path)} ({len(lines)} lines)",
        "## The file, in chunks",
    ]
    for i, (s, e) in enumerate(chunks, 1):
        parts.append(f"[{i}] lines {s}-{e}:\n{snippet(lines, s, e)}")
    return "\n\n".join(parts)


def questions(lines: list[str], chunks: list[tuple[int, int]]) -> dict:
    criteria = {
        str(i): f"Lines {s}-{e}, starting: {lines[s - 1].strip()[:80] or '(blank)'}"
        for i, (s, e) in enumerate(chunks, 1)
    }
    criteria[WHOLE_FILE] = (
        "The request needs the whole file, or no single chunk: an overview or "
        "explanation of the file, a review, a rewrite or reformat, a search for "
        "something whose location is unknown, or a request unrelated to this file."
    )
    return {
        "region": {
            "type": "choice",
            "instructions": (
                "The assistant is about to read this entire file to act on the "
                "user's request. Which single chunk contains what it actually needs "
                "to read to do that? Choose whole_file if it genuinely needs all of it."
            ),
            "criteria": criteria,
        }
    }


def decide(dist: dict, chunks: list[tuple[int, int]], lines: list[str]) -> dict:
    """Turn the distribution into a verdict. Pure, so it can be tested offline."""
    label, top, second = top_two(dist)
    verdict = {"top": round(top, 3), "margin": round(top - second, 3), "winner": label}
    if not label:
        return {**verdict, "verdict": "no_answer"}
    if label == WHOLE_FILE:
        return {**verdict, "verdict": "whole_file"}
    if top < REGION_AT or top - second < REGION_MARGIN:
        return {**verdict, "verdict": "too_close"}
    try:
        s, e = chunks[int(label) - 1]
    except (ValueError, IndexError):
        return {**verdict, "verdict": "no_answer"}
    total = sum(len(l) + 1 for l in lines)
    region = sum(len(l) + 1 for l in lines[s - 1 : e])
    if total and region / total > MAX_REGION_SHARE:
        return {**verdict, "verdict": "region_too_big", "region": [s, e]}
    return {
        **verdict,
        "verdict": "would_narrow",
        "region": [s, e],
        # Tokens this one read would have kept out of the context. The carried
        # saving is this times however many calls followed; tokens.sh has those.
        "saved_tokens": (total - region) // 4,
    }


def read_lines(path: str) -> list[str] | None:
    if any(path.lower().endswith(suf) for suf in SKIP_SUFFIXES):
        return None
    try:
        with open(path, "rb") as fh:
            raw = fh.read(4_000_000)
    except OSError:
        return None
    if b"\0" in raw[:8192]:
        return None
    return raw.decode("utf-8", errors="replace").splitlines()


def emit() -> None:
    """Emit nothing. Shadow mode: the read goes ahead exactly as asked."""
    sys.exit(0)


def report(limit: int = 25) -> int:
    """Print the shadow log: what it would have done, and what it would have saved."""
    path = env_var("JEV_LOG")
    if not path or not os.path.exists(os.path.expanduser(path)):
        print("No audit log yet. The Reads hook logs to JEV_LOG once installed.")
        return 1
    rows = []
    with open(os.path.expanduser(path)) as fh:
        for line in fh:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if row.get("hook") == "reads" and row.get("verdict"):
                rows.append(row)
    if not rows:
        print("No Reads decisions logged yet. They appear after large-file Reads.")
        return 0

    counts = {}
    for r in rows:
        counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
    narrow = [r for r in rows if r["verdict"] == "would_narrow"]
    print(f"{len(rows)} large-file Reads judged\n")
    for verdict, count in sorted(counts.items(), key=lambda kv: -kv[1]):
        print(f"  {verdict:16} {count:5}  {100 * count / len(rows):5.1f}%")
    saved = sum(r.get("saved_tokens", 0) for r in narrow)
    print(f"\n  would have kept ~{saved:,} tokens out of context, before re-reads")
    print("  (tokens.sh shows how many later calls re-read each one)\n")
    print(f"Last {min(limit, len(narrow))} suggestions -- was each region the one that mattered?")
    for r in narrow[-limit:]:
        s, e = r.get("region", [0, 0])
        print(f"  p={r.get('top', 0):.2f}  {r.get('file', '?'):42} lines {s}-{e} of {r.get('lines', '?')}")
        print(f"          asked: {r.get('request_head', '')[:90]}")
    return 0


def main() -> None:
    # install.sh asks for the matcher rather than keeping its own copy, same as
    # jev_gate.py and jev_scope.py.
    if "--matcher" in sys.argv[1:]:
        print("Read")
        sys.exit(0)

    if "--report" in sys.argv[1:]:
        sys.exit(report())

    if disabled() or os.environ.get("JEV_READS_OFF") == "1":
        emit()

    key = api_key()
    if not key:
        emit()

    payload = read_payload()
    if payload is None or payload.get("tool_name") != "Read":
        emit()

    tool_input = payload.get("tool_input") or {}
    path = tool_input.get("file_path") or ""
    if not path or tool_input.get("offset") or tool_input.get("limit") or tool_input.get("pages"):
        emit()

    lines = read_lines(path)
    if lines is None or len(lines) < MIN_LINES:
        emit()

    transcript = payload.get("transcript_path")
    requests = recent_requests(load_transcript(transcript)) if transcript else []
    if not requests:
        log({"hook": "reads", "skipped": "no_request_in_transcript"})
        emit()

    chunks = chunk_file(lines, path)
    state = build_state(requests, path, lines, chunks)
    try:
        scores, elapsed_ms, usage = ask_jev(state, questions(lines, chunks), key)
    except JevError as exc:
        log({"hook": "reads", "error": str(exc)})
        emit()

    dist = scores.get("region")
    result = decide(dist if isinstance(dist, dict) else {}, chunks, lines)
    log(
        {
            "hook": "reads",
            **result,
            "file": short_path(path),
            "path": path,
            "lines": len(lines),
            "chunks": len(chunks),
            "scores": scores,
            "latency_ms": elapsed_ms,
            "usage": usage,
            "request_head": " ".join(requests[-1].split())[:220],
            # Enough to find this read in its transcript later and check whether
            # the agent's edits landed inside the suggested region.
            "session_id": payload.get("session_id"),
            "tool_use_id": payload.get("tool_use_id"),
        }
    )
    emit()


if __name__ == "__main__":
    main()
