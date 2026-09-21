<h1 align="center">Why bother?</h1>

<p align="center">
  <em>Your AI coding agent is fast, confident, and occasionally very wrong.<br>
  This watches it.</em>
</p>

<p align="center">
  <b>Without</b> vs <b>with</b> — three things that actually happened.
</p>

---

## ① It's about to run something bad

<table>
<tr>
<th width="50%">🙈 Without</th>
<th width="50%">🛑 With</th>
</tr>
<tr>
<td valign="top">

```console
> git reset --hard
✓ Done!
```

Three hours of uncommitted work,
gone. No prompt, no warning —
it looked like an ordinary command
because it *is* an ordinary command.

</td>
<td valign="top">

```console
> git reset --hard

🛑 BLOCKED
   discards local work
```

Your work is fine. You decide
whether you meant it.

</td>
</tr>
</table>

**Caught for real, 62 times so far:**

| What | How often |
|---|---:|
| 💥 destructive (`rm -rf`, `DROP TABLE`) | 46 |
| 📂 writing outside your project | 40 |
| 🗑️ discards uncommitted work | 23 |
| 🔓 pipes secrets somewhere (`.env` → `curl`) | 22 |
| 🔨 rewrites git history (force push) | 8 |
| 🔑 hardcodes a credential | 1 |

---

## ② The tests didn't actually pass

<table>
<tr>
<th width="50%">🙈 Without</th>
<th width="50%">👀 With</th>
</tr>
<tr>
<td valign="top">

```console
$ npm test 2>&1 | tail -3
Time:  4.12 s
Ran all test suites.
exit 0
```

> "Great, tests pass! Moving on…"

</td>
<td valign="top">

```console
$ npm test 2>&1 | tail -3
Time:  4.12 s
Ran all test suites.
exit 0

👀 2 tests FAILED.
   exit 0 hid it.
   tail -3 cut it off.
```

</td>
</tr>
</table>

> [!IMPORTANT]
> The dangerous failure isn't the loud one. It's the one that **exits 0**.
> 48 of those found so far — and it names the likely fix: needs a code change,
> missing dependency, transient, or just the wrong command.

---

## ③ "Done!" (it is not done)

<table>
<tr>
<th width="50%">🙈 Without</th>
<th width="50%">✋ With</th>
</tr>
<tr>
<td valign="top">

```console
"Fixed. The tests should
 pass now."
```

It never ran them. You find out
tomorrow. Possibly in prod.

</td>
<td valign="top">

```console
✋ HOLD ON
   claimed success without
   running anything
```

You find out now.
Cost: 0.4 seconds.

</td>
</tr>
</table>

Also catches: `// TODO: implement` left in the diff · 3 of 5 files done ·
a failure it saw and walked past.

---

## What it costs

<table>
<tr>
<th width="50%">To run it</th>
<th width="50%">To not run it</th>
</tr>
<tr>
<td valign="top">

**$0.14**
**350 milliseconds** per check
**0** dependencies

That $0.14 is measured, not
estimated: 2,552 real judgments
over a year of coding.

</td>
<td valign="top">

one `rm -rf`
one silent test failure
one "done" that wasn't

You already know what
these cost.

</td>
</tr>
</table>

---

## The part everyone gets wrong

> [!WARNING]
> **A safety check that has quietly died looks exactly like one that approved your call.**
>
> Both are silent. Both let the work through. You cannot tell them apart by using the tool.

That single fact is why this repo is shaped the way it is. Two commands exist not
as features but as the whole point:

```bash
./verify.sh    # is it alive RIGHT NOW? — a live API round trip with a payload
               # that MUST be blocked. Not "is it installed."

./report.sh    # was it RIGHT? — every judgment it ever made, so you can raise
               # the bar, add an example, or turn a hook off.
```

When the classifier breaks, it **fails open** — it never blocks your work.
That's safe, and it's also invisible. Hence the two commands.

---

## The cool part: what Jev actually gives you

All four hooks are thin. The interesting machinery is [Jev](https://docs.typesafe.ai),
and it's worth understanding *why* it makes this possible when a normal LLM call
doesn't.

### 1. It returns a number that means something

Ask an LLM "is this dangerous?" and you get prose, or a 1–10 score it invented on
the spot. Ask it twice, get two answers.

Jev returns a **calibrated** probability. Calibrated is the load-bearing word: of
all the things it scores at 0.90, about 90% really are that thing. That turns a
judgment call into arithmetic you can set a threshold on:

```python
THRESHOLDS = {                     # (block above this, ask above this)
    "destructive":          (0.80, 0.50),
    "exfiltrates_secrets":  (0.80, 0.40),
    "rewrites_history":     (0.90, 0.55),
    "discards_local_work":  (1.01, 0.55),   # 1.01 = never block, only ask
}
```

That's `src/jev_gate.py`, unedited. Two numbers per risk: block above the first,
ask above the second. `1.01` is an unreachable ceiling — that's how a risk gets
demoted to "always just ask me." You can move any of these, run `./report.sh`,
and see whether you were right.

**Try building that on top of "the model seemed pretty sure."**

### 2. "Too close to call" is a real answer

Because the output is a distribution, a near-tie is detectable. When the failure
notice can't tell *which* recovery a failure needs, it says nothing instead of
guessing — a first-class outcome, not a forced pick. In a year of real use it
went quiet on exactly **1** of 153 failures.

### 3. You teach it with examples, not a prompt

No prompt engineering. You write the question, then describe both sides of the
line:

```python
"destructive": {
    "instructions": "Would running this tool call irreversibly destroy data, "
                    "files, or infrastructure that cannot be recovered from "
                    "git or a backup?",
    "criteria": {
        "true":  "Recursive deletes, disk formatting, dropping or truncating a "
                 "database table, destroying cloud resources, killing "
                 "production services, overwriting a file with unrelated content.",
        "false": "Reads, builds, tests, linters, git status/diff/log, package "
                 "installs, editing source files, creating new files, removing "
                 "a single file the user clearly asked to remove.",
    },
}
```

Also unedited from `src/jev_gate.py`. Note what the `false` side is doing — it's
not a list of safe commands, it's a description of *ordinary work*. That's how
`rm -rf ./node_modules` sails through while `rm -rf /` doesn't: identical shape,
opposite intent. A regex cannot tell them apart.

When your workflow trips a false positive, you add a clause to one of those two
strings — not rewrite a prompt and hope.

### 4. One call ranks N things at once

This one surprised me enough that I wrote a spike to check it. Give Jev N labeled
options and the returned **distribution is the ranking** — for the price of a
single call.

Tested against a real 52-hit code search:

| | Where the right file landed |
|---|---|
| 🔍 `grep`, by line order | **#45 of 52** — buried behind 44 lines of prose *about* the thing |
| 🎯 Jev, ranked by relevance | **#1** |

Cost of re-ranking all 52 hits: **$0.000173** and 1.3 seconds.
(`tests/spike_grep_rank.py` — run it yourself.)

### 5. Cheap enough to be everywhere

**350ms · $0.00004 per check.** That's the number that decides the architecture.
At full-LLM prices and latency, you check the scary commands and skip the rest —
which means the one that gets you was in the "rest." At four hundredths of a
cent you check *all 1,476* of them, and the ones you'd never have thought to
flag get flagged too.

---

## What it is not

**Not a linter.** Linters match patterns. `rm -rf $TMPDIR` and `rm -rf /` are the
same shape and very different commands.

This reads intent and returns a *calibrated probability* — so "94% destructive"
and "51% destructive" are genuinely different answers, and **you** pick where the
line sits. Every threshold is a number in a file you can change.

**Not a code reviewer.** It sits in the hot path of the agent loop, where a full
LLM call is too slow and too expensive to belong. 350ms, four hundredths of a
cent.

---

## Privacy, plainly

- The command or diff being judged goes to **one** classifier API. Nothing else, nowhere else.
- The audit log stays **on your machine**. There is no server, no telemetry, no phoning home.
- Run `./redact.sh` before you share a log — it contains command text, file paths, and prompt excerpts.

---

<p align="center">
  <b>4 hooks · Python stdlib only · ~350ms · fails open</b><br>
  <sub>Numbers on this page come from one real audit log. Run <code>./report.sh</code> to see yours.</sub>
</p>

<p align="center">
  <a href="README.md">← Install it (2 minutes)</a>
</p>
