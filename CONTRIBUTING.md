# 🤝 Contributing

The most useful contribution isn't code. It's a case where a hook got it wrong.

These hooks are calibrated against a few hundred classifications from one
developer's machine, on one stack. Every false positive you hit on a different
stack is information nobody here has.

## 📦 Setup

```bash
git clone git@github.com:jakenbear/the-jev-enator.git ~/the-jev-enator
cd ~/the-jev-enator
cp .env.example .env          # paste your TYPESAFE_API_KEY
./install.sh
./verify.sh                   # should print 8 OKs
```

Python 3.10+, standard library only. No build step, no dependencies, no
virtualenv. Get a key at [typesafe.ai](https://typesafe.ai) — the full test suite
costs well under a cent to run.

Restart Claude Code after installing; `settings.json` is only read at startup.

## 🧪 Running the tests

```bash
source .env
python3 tests/test_jev_gate.py     # 23 cases: 14 safe, 9 dangerous
python3 tests/test_jev_notice.py   # 19 cases: 6 quiet, 13 failures
python3 tests/test_jev_finish.py   # 12 cases: 7 legitimate, 5 early stops
```

These hit the live API, so they cost a fraction of a cent and take about a minute.
Run all three before opening a PR — the thresholds interact, and it's easy to fix
one case by breaking another.

Each suite logs its classifications to its own temp file and prints the path when
it finishes — your real `~/jev-gate.jsonl` is untouched. If you add a suite, use
`tests/fixture_env.py`; pass `env=hook_env(log_path)` to every `subprocess.run`.
Fixtures are extreme by design, and letting them into the real log destroys the
score distribution `report.sh` exists to show you.

Expect **occasional** flakiness. A couple of fixtures sit within 0.02 of their
threshold, so a rerun can flip them. If a case fails, rerun before debugging. If
it fails twice, it's real.

## 🐛 Reporting a bad call

This is the highest-value issue you can file. Include:

1. The command or output that was misjudged
2. What the hook did, and what it should have done
3. The log line — `grep <something> ~/jev-gate.jsonl | tail -1`

That last one matters most: it has the actual probabilities, so the fix is
usually obvious from the scores alone.

Redact freely. The log records command text and paths, so scrub anything
internal before pasting.

## 🎛️ Changing a threshold or a question

Two rules, both learned the hard way:

**Add a fixture first.** If you're changing behaviour, there should be a case
that fails before your change and passes after. A threshold moved without a
fixture is untested by construction.

**Don't move a threshold to fix one case.** Check what else sits near it first.
`exit_status_misleads` is the live example: the obvious fix for one fixture at
0.44 was to drop the bar to 0.40, which would also make every ordinary test
failure "emphatic" and drain the word of meaning. The fixture's expectation was
wrong, not the threshold. Correcting a fixture is a legitimate fix — say so in
the commit message and explain why.

When a question scores near 0.5 on cases you think are obvious, the question is
usually asking for something not in the state. See
[Adding another hook](README.md#-adding-another-hook) — moving the question earlier
in the loop beats rewording it.

## 🪝 Adding a hook

`src/jev_client.py` holds everything reusable. A new hook is roughly:

1. Define `QUESTIONS` and thresholds as module constants, with a comment saying
   why each number is what it is
2. Build a state string from the hook payload
3. Call `ask_jev`, and on `JevError` **log and allow** — the fail-open contract is
   not optional
4. Emit the event's decision JSON
5. Add it to `WIRING` in `install.sh`
6. Write fixtures, including the ones that must stay quiet

Ship anything that depends on intent as log-only, and let the log decide whether
it earns enforcement. `report.sh` exists for exactly this.

## 🎨 Style

Match what's there. Comments explain *why* a number or a branch exists, not what
the line does — the thresholds are the interesting part of this codebase and an
undocumented constant is a magic number.

No new dependencies. Standard library is a feature here: these run on every tool
call, in whatever Python is on `PATH`.

## 🚀 PRs

Small and single-purpose. State what you ran, and paste the suite output —
including any fixture you corrected and why.

If a change touches the danger gate, say explicitly whether it can make the gate
*less* likely to block something. That's the one direction where a mistake is
expensive.
