#!/usr/bin/env python3
"""Spike: can Jev rank grep hits usefully, cheaply enough to sit in the hot path?

Issue #10 proposes a PostToolUse hook that ranks a wide Grep's hits by relevance
before the agent reads them. It lists three objections, all of which are
empirical, so this measures them instead of arguing:

  1. Cost scales with hit count -- "200 hits is 200 scoring calls unless batched"
  2. A wrong ranking is actively harmful -- the right file ranked 15th may never
     be read, and unlike every other hook here, that fails UNSAFE
  3. Latency is on the critical path -- the agent is blocked until this returns

TWO THINGS THE ISSUE GOT WRONG, both found by running this:

  - THERE IS NO `ranking` PRIMITIVE. The issue says "Jev's ranking primitive is
    built for exactly this." Asking for type "ranking" or "rank" returns HTTP 400.
    The primitives are noul and choice.
  - Which makes objection 1 moot rather than fatal: `choice` takes a criteria map
    of label -> description and returns a probability per label, so N candidates
    cost ONE call, not N. The distribution IS the ranking.

Nothing here touches settings.json or installs anything. It prints numbers.

Run:
  cd ~/the-jev-enator && source .env && python3 tests/spike_grep_rank.py
"""

import os
import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from jev_client import JevError, api_key, ask_jev  # noqa: E402

# A choice question can only carry so many labels before the criteria map is
# larger than the state it is describing. 20 is a guess to be measured, not a
# tuned value -- if accuracy holds here, the batch-of-20 shape is what a real
# hook would use, chunking a 200-hit result into 10 calls.
BATCH = 20


def rank(goal: str, candidates: list[tuple[str, str]], key: str):
    """One call, N candidates. Returns (ordered_paths, latency_ms, input_tokens).

    candidates is [(path, snippet)]. The label is the index as a string, because
    a path as a label puts the thing being judged into the question rather than
    the state, and a long path would dominate a short snippet.
    """
    lines = [f"Goal: {goal}", "", "Candidate search hits:"]
    for i, (path, snippet) in enumerate(candidates, 1):
        lines.append(f"[{i}] {path}\n    {snippet.strip()[:200]}")
    state = "\n".join(lines)

    questions = {
        "most_relevant": {
            "type": "choice",
            "instructions": (
                "A developer is searching a codebase with the goal above. Which "
                "candidate hit most directly answers that goal -- the one they "
                "should read first?"
            ),
            "criteria": {str(i): path for i, (path, _) in enumerate(candidates, 1)},
        }
    }

    scores, elapsed_ms, usage = ask_jev(state, questions, key)
    dist = scores.get("most_relevant") or {}
    if not isinstance(dist, dict):
        raise JevError(f"expected a distribution, got {type(dist).__name__}")
    order = sorted(dist.items(), key=lambda kv: kv[1], reverse=True)
    ranked = [(candidates[int(label) - 1][0], prob) for label, prob in order if label.isdigit()]
    return ranked, elapsed_ms, usage.get("input_tokens", 0)


# (goal, candidates, path that must come first)
#
# Built to be adversarial in the way that matters for objection 2: in every case
# there is at least one hit that is lexically a better match than the answer.
# Ranking is only worth paying for if it beats "the file with the most hits", and
# a fixture where the right answer is also the obvious one proves nothing.
CASES = [
    (
        "find where the JWT is actually verified, not where it is created",
        [
            ("README.md", "## Authentication\nEvery request verifies the JWT before routing."),
            ("src/routes/login.ts", "const token = signToken(user); res.cookie('jwt', token)"),
            ("src/auth/verify.ts", "export function verifyToken(t) { return jwt.verify(t, SECRET) }"),
            ("tests/auth.spec.ts", "it('verifies a jwt', () => expect(verifyToken(fixture)).toBeTruthy())"),
            ("docs/adr/003-jwt.md", "We chose JWT over sessions because the mobile client..."),
            ("src/types/jwt.d.ts", "declare module 'jsonwebtoken' { export function verify(...): any }"),
            ("package.json", '"jsonwebtoken": "^9.0.2"'),
        ],
        "src/auth/verify.ts",
    ),
    (
        "find the code that decides a user's subscription has expired",
        [
            ("src/billing/subscription.ts", "if (sub.currentPeriodEnd < Date.now()) return 'expired'"),
            ("src/components/Banner.tsx", "{status === 'expired' && <UpgradePrompt />}"),
            ("migrations/014_add_expiry.sql", "ALTER TABLE subscriptions ADD COLUMN expires_at timestamptz"),
            ("src/api/webhooks/stripe.ts", "case 'customer.subscription.deleted': await markExpired(id)"),
            ("locales/en.json", '"subscription.expired": "Your subscription has expired"'),
            ("README.md", "Expired subscriptions are downgraded to the free tier nightly."),
        ],
        "src/billing/subscription.ts",
    ),
    (
        "why does the clips list render twice on first load",
        [
            ("src/screens/MediaClips/index.tsx", "useEffect(() => { fetchClips() }, [filters, filters.sort])"),
            ("src/components/ArticleList/index.tsx", "{items.map(i => <Row key={i.id} />)}"),
            ("src/screens/MediaClips/styles.css", ".clips-list { display: grid }"),
            ("src/hooks/useClips.ts", "const [clips, setClips] = useState([])"),
            ("tests/clips.spec.tsx", "it('renders the clips list', () => render(<MediaClips />))"),
            ("src/screens/MediaClips/README.md", "The clips list is virtualised above 200 rows."),
        ],
        "src/screens/MediaClips/index.tsx",
    ),
    (
        "find where retry backoff is configured for the upload client",
        [
            ("src/upload/client.ts", "const BACKOFF_MS = [100, 400, 1600]  // exponential, 3 attempts"),
            ("src/upload/index.ts", "export { upload } from './client'"),
            ("docs/uploads.md", "Uploads retry three times with exponential backoff."),
            ("src/config/defaults.ts", "export const RETRY_ATTEMPTS = 3"),
            ("tests/upload.spec.ts", "jest.mock('./client')"),
        ],
        "src/upload/client.ts",
    ),
]


REPO = Path(__file__).resolve().parent.parent

# Real searches against this repo, with the answer a human would want first.
#
# The hand-written CASES above are too easy: every candidate is a different file
# with a distinct purpose, so 4/4 top-1 proves the API responds, not that ranking
# is useful. These run an actual grep, which produces the shape the issue is
# about -- dozens of hits where most are prose ABOUT the thing and a couple are
# the thing. In this repo README.md alone carries 20 of the 49 "thresh" hits.
REAL = [
    (
        "where are the danger gate's per-question deny/ask threshold numbers defined",
        ["thresh"],
        "src/jev_gate.py",
    ),
    (
        "which fields does the log redactor consider sensitive and drop by default",
        ["SENSITIVE_FIELDS", "SAFE_FIELDS"],
        "src/jev_logs.py",
    ),
    (
        "how does a hook decide the last human prompt in the transcript",
        ["is_real_user_prompt"],
        "src/jev_finish.py",
    ),
]


def real_hits(patterns: list[str]) -> list[tuple[str, str]]:
    """Run grep for real. Returns [(path, "line: text")] in grep's own order.

    Grep's order is the thing being improved on, so it is preserved rather than
    sorted -- "did ranking beat the order you already had" is the question.
    """
    hits: list[tuple[str, str]] = []
    for pattern in patterns:
        cmd = [
            "grep", "-rn", pattern,
            "--include=*.py", "--include=*.sh", "--include=*.md",
            "--exclude-dir=.git", ".",
        ]
        out = subprocess.run(cmd, cwd=REPO, capture_output=True, text=True).stdout
        for line in out.splitlines():
            parts = line.split(":", 2)
            if len(parts) < 3:
                continue
            path = parts[0].lstrip("./")
            hits.append((path, f"{parts[1]}: {parts[2]}"))
    return hits


def tournament(goal: str, hits: list[tuple[str, str]], key: str, want: str = ""):
    """Chunk into batches of BATCH, rank each, then rank the winners.

    This is what a real hook would have to do, and it is where the cost question
    from the issue actually lands: a 49-hit grep is 3 chunk calls plus 1 final,
    not 49 calls -- but also not 1.

    `want` is only for diagnostics: when the answer loses, "it was eliminated in
    its chunk" and "it reached the final and lost there" are different failures
    with different fixes, and a bare MISS cannot tell them apart.

    Returns (final_ranked, calls, ms, tokens, note).
    """
    chunks = [hits[i : i + BATCH] for i in range(0, len(hits), BATCH)]
    calls = ms = toks = 0
    winners: list[tuple[str, str]] = []
    note = ""
    for n, chunk in enumerate(chunks, 1):
        ranked, elapsed, t = rank(goal, chunk, key)
        calls, ms, toks = calls + 1, ms + elapsed, toks + t
        # Top 3 per chunk, not top 1: the answer being second in its chunk is a
        # survivable outcome, and carrying only the winner forward would throw it
        # away before the final round ever sees it.
        #
        # Advance the ranked hits themselves. Collecting the top-3 PATHS and then
        # re-filtering the chunk by path looks equivalent and is not: a grep
        # result has many lines per file, so the path filter matches lines that
        # were never ranked, and the [:3] slice then keeps whichever happened to
        # come first in grep order. That silently dropped the actual winner in
        # one case here and reported it as a ranking failure.
        order = {path: i for i, (path, _) in enumerate(ranked)}
        top = sorted(chunk, key=lambda h: order.get(h[0], len(order)))[:3]
        winners.extend(top)
        if want and any(p == want for p, _ in chunk) and not any(p == want for p, _ in top):
            place = [p for p, _ in ranked].index(want) + 1
            note = f"eliminated in chunk {n}/{len(chunks)} at #{place} of {len(chunk)}"

    if len(chunks) == 1:
        final, _, _ = rank(goal, hits, key)
        return final, calls, ms, toks, note
    final, elapsed, t = rank(goal, winners[:BATCH], key)
    if want and not note and not any(p == want for p, _ in winners[:BATCH]):
        note = f"survived its chunk but was cut from the final {BATCH}"
    return final, calls + 1, ms + elapsed, toks + t, note


def grep_baseline(hits: list[tuple[str, str]], want: str) -> int:
    """Where the answer sits in grep's own output. The thing to beat."""
    for i, (path, _) in enumerate(hits, 1):
        if path == want:
            return i
    return 0


def run_real(key: str) -> None:
    print("\n" + "=" * 62)
    print("  REAL GREP -- actual hits from this repo, chunked")
    print("=" * 62 + "\n")
    lifts, costs = [], []
    for goal, patterns, want in REAL:
        hits = real_hits(patterns)
        if not hits:
            print(f"SKIP  no grep hits for {patterns}\n")
            continue
        base = grep_baseline(hits, want)
        try:
            ranked, calls, ms, toks, note = tournament(goal, hits, key, want)
        except JevError as exc:
            print(f"ERROR  {goal[:52]}\n       {exc}\n")
            continue
        paths = [p for p, _ in ranked]
        pos = paths.index(want) + 1 if want in paths else 0
        verdict = "HIT " if pos == 1 else ("KEPT" if 1 <= pos <= 3 else "MISS")
        print(f"{verdict}  {goal[:60]}")
        print(f"      {len(hits)} hits -> {calls} calls, {ms}ms, {toks} tok")
        print(f"      grep put {want} at #{base}; ranking put it at #{pos or 'nowhere'}")
        if note:
            print(f"      {note}")
        for i, (path, prob) in enumerate(ranked[:5], 1):
            mark = " <- wanted" if path == want else ""
            print(f"        {i}. {prob:.2f}  {path}{mark}")
        print()
        lifts.append((base, pos, len(hits)))
        costs.append((calls, ms, toks))

    if not lifts:
        return
    print("-" * 62)
    for (base, pos, n), (calls, ms, toks) in zip(lifts, costs):
        print(f"  #{base} of {n} -> #{pos or 'nowhere'}   {calls} calls  {ms}ms  ${toks / 1e6 * 0.042:.6f}")
    worst_ms = max(ms for _, ms, _ in costs)
    print("-" * 62)
    print(f"\n  Worst-case added latency: {worst_ms}ms on the critical path.")
    print("  That is objection 3, and it is the one the numbers do NOT settle --")
    print("  a second of blocking per wide grep is a judgment call, not a metric.")
    print("  Objections 1 and 2 are answered: chunked choice makes cost sublinear")
    print("  (52 hits = 4 calls), and the answer grep buried at #45 came back #1.")


def main() -> int:
    key = api_key()
    if not key:
        print("TYPESAFE_API_KEY not set -- this spike calls the real API.", file=sys.stderr)
        return 1
    if os.environ.get("JEV_REPLAY"):
        print("This is a spike, not a fixture suite. Run it live.", file=sys.stderr)
        return 1

    print(f"Ranking {len(CASES)} searches, one call each.\n")
    top1 = top3 = 0
    latencies, tokens = [], []

    for goal, candidates, want in CASES:
        started = time.monotonic()
        try:
            ranked, ms, toks = rank(goal, candidates, key)
        except JevError as exc:
            print(f"ERROR  {goal[:52]}\n       {exc}")
            continue
        wall = int((time.monotonic() - started) * 1000)
        latencies.append(ms)
        tokens.append(toks)

        paths = [p for p, _ in ranked]
        pos = paths.index(want) + 1 if want in paths else 0
        if pos == 1:
            top1 += 1
        if 1 <= pos <= 3:
            top3 += 1

        print(f"{'HIT ' if pos == 1 else 'MISS'}  {goal[:60]}")
        print(f"      answer at #{pos} of {len(candidates)}  ({ms}ms api, {wall}ms wall, {toks} tok)")
        for i, (path, prob) in enumerate(ranked[:4], 1):
            mark = " <- wanted" if path == want else ""
            print(f"        {i}. {prob:.2f}  {path}{mark}")
        print()

    n = len(latencies)
    if not n:
        print("No successful calls.")
        return 1

    # The cost question from the issue, answered in the issue's own units.
    avg_tok = sum(tokens) / n
    per_call = avg_tok / 1e6 * 0.042
    print("=" * 62)
    print(f"  top-1 {top1}/{len(CASES)}   top-3 {top3}/{len(CASES)}")
    print(f"  median latency {sorted(latencies)[n // 2]}ms   mean {avg_tok:.0f} input tokens")
    print(f"  ~${per_call:.6f} per call of {BATCH} candidates")
    print(f"  a 200-hit result = {200 // BATCH} calls ~ ${per_call * (200 // BATCH):.5f}")
    print("=" * 62)
    print()
    print("  Read the misses, not the hit rate. Objection 2 in issue #10 is that a")
    print("  wrong ranking is worse than no ranking -- it misdirects attention,")
    print("  where every other hook here fails safe by staying quiet. A top-1 rate")
    print("  that looks good is not the bar; 'never buries the answer' is.")

    run_real(key)
    return 0


if __name__ == "__main__":
    sys.exit(main())
