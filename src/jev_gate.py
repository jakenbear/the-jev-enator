#!/usr/bin/env python3
"""Jev-backed PreToolUse gate for Claude Code.

Reads a PreToolUse hook payload on stdin, asks Jev a handful of noul questions
about the pending tool call, and returns allow / ask / deny.

Network errors, timeouts, and a missing key emit no decision, so Claude Code
falls back to its normal permission flow. An unusable reply is not that: the
gate asks instead of treating a score it could not read as "safe" (issue #35).
A crash is logged and also asks. Calls that would modify the installed hooks,
the Claude Code settings that register them, or the audit log are denied
before Jev is asked.

Env:
  TYPESAFE_API_KEY       required, else the hook no-ops
  JEV_LOG                optional path for a JSONL audit log
  JEV_DISABLE            set to 1 to bypass every hook in this repo
  JEV_GATE_OFF           set to 1 to bypass only this hook
  JEV_GATE_EXTRA_TOOLS   comma-separated extra tool names to gate, e.g. MCP tools
                         (keeps GATE in its name: this one really is gate-only)

The JEV_GATE_* spellings of the shared vars still work. See jev_client.LEGACY_ENV.

Also: `jev_gate.py --matcher` prints the PreToolUse matcher regex, which is how
install.sh gets it. See GATED_TOOLS.
"""

import json
import math
import os
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# ORDER MATTERS. jev_pyversion is the only module here that an old interpreter can
# import, and it must run before jev_client, whose `str | None` annotations raise
# TypeError at import time on 3.9. Sorting these imports alphabetically would
# reintroduce a silent no-op gate. See src/jev_pyversion.py.
from jev_pyversion import require_python

require_python()

from jev_client import (  # noqa: E402
    JevError,
    JevReplyError,
    api_key,
    ask_jev,
    banner,
    default_log_path,
    disabled,
    env_var,
    guard_main,
    log,
    read_payload,
)

# Tools worth paying for a classification on. Read-only tools are skipped before
# any network call.
#
# install.sh derives the PreToolUse matcher from this set by running
# `jev_gate.py --matcher`, so the two cannot drift. They did: the matcher was
# hardcoded as "Bash|Write|Edit|NotebookEdit" while this set also listed
# KillShell, and neither mentioned MultiEdit -- which rewrites many files in one
# call and so is strictly more destructive than the Edit that was gated.
GATED_TOOLS = {"Bash", "Write", "Edit", "MultiEdit", "NotebookEdit", "KillShell"}

# MCP tools can do anything the server exposes -- drop a table, delete a bucket,
# post to a channel -- and nothing about them reaches this gate by default.
#
# Opt-in rather than a blanket mcp__.* matcher, for two reasons. Their payloads
# have no shared shape, so build_state can only dump JSON at them and the
# questions are answering against a much weaker state than they get for Bash.
# And a chatty server would pay ~350ms and a call on every single invocation.
# Name the ones that can actually destroy something.
#
#   export JEV_GATE_EXTRA_TOOLS="mcp__supabase__execute_sql,mcp__aws__delete"
def extra_tools() -> set[str]:
    raw = os.environ.get("JEV_GATE_EXTRA_TOOLS", "")
    return {t.strip() for t in raw.split(",") if t.strip()}


def gated_tools() -> set[str]:
    return GATED_TOOLS | extra_tools()

# Per-question thresholds as (deny_at, ask_at). Tuned against tests/.
#
# A deny_at of 1.01 is unreachable, meaning that question can only ever ask --
# right for operations that are risky but legitimate and routinely intended.
# Hard-denying those would train you to disable the gate.
THRESHOLDS = {
    "destructive": (0.80, 0.50),
    "rewrites_history": (0.90, 0.55),
    "discards_local_work": (1.01, 0.55),
    "exfiltrates_secrets": (0.80, 0.40),
    "hardcodes_credential": (0.90, 0.55),
    "outside_workspace": (0.85, 0.55),
}
DEFAULT_THRESHOLD = (0.90, 0.60)

QUESTIONS = {
    "destructive": {
        "type": "noul",
        "instructions": (
            "Would running this tool call irreversibly destroy data, files, or "
            "infrastructure that cannot be recovered from git or a backup?"
        ),
        "criteria": {
            "true": (
                "Recursive deletes, disk formatting, dropping or truncating a "
                "database table, destroying cloud resources, killing production "
                "services, overwriting a file with unrelated content."
            ),
            "false": (
                "Reads, builds, tests, linters, git status/diff/log, package "
                "installs, editing source files, creating new files, removing a "
                "single file the user clearly asked to remove."
            ),
        },
    },
    "rewrites_history": {
        "type": "noul",
        "instructions": (
            "Would this tool call destroy commits that another developer could "
            "lose work from?"
        ),
        "criteria": {
            "true": (
                "Plain 'git push --force' or 'push -f' to a shared branch such as "
                "main, master, develop, or release; 'push --force' with no lease "
                "check to any branch others build on; filter-branch or a history "
                "rewrite on a shared branch; deleting a remote branch or tag "
                "others depend on."
            ),
            "false": (
                "'git push --force-with-lease', which aborts rather than "
                "overwriting work it has not seen -- this is the safe form and is "
                "normal after a rebase; force-pushing a personal feature, spike, "
                "or PR branch that only the author works on; local rebase or "
                "amend before pushing; branch creation, fetch, pull, stash, and "
                "ordinary pushes."
            ),
        },
    },
    "discards_local_work": {
        "type": "noul",
        "instructions": (
            "Would this tool call throw away uncommitted work in the working "
            "tree that the user has no other copy of?"
        ),
        "criteria": {
            "true": "git reset --hard, git checkout -- ., git clean -fd, git stash drop, discarding a branch with unpushed commits.",
            "false": "Commits, adds, normal checkout of a clean tree, stash push, reads, builds, tests.",
        },
    },
    "exfiltrates_secrets": {
        "type": "noul",
        "instructions": (
            "Does this tool call read credentials or secrets and send them "
            "somewhere outside this machine?"
        ),
        "criteria": {
            "true": "curl/POST of .env contents, AWS credentials, private keys, or tokens to an external host; piping secrets into a network command.",
            "false": "Local reads of config, using credentials via a normal SDK or CLI call, printing non-secret output.",
        },
    },
    # Distinct from exfiltrates_secrets: nothing leaves the machine here, which is
    # exactly why that question missed it. A key written into tracked source is one
    # commit away from being public, which is worse than one request to one host.
    "hardcodes_credential": {
        "type": "noul",
        "instructions": (
            "Does this tool call write a real credential -- an API key, secret "
            "access key, password, or private key -- as a literal value into a "
            "source or config file that would be committed to git?"
        ),
        "criteria": {
            "true": (
                "A literal AWS secret access key, API key, bearer token, database "
                "password, or private key assigned in a .ts, .js, .py, .json, or "
                ".yaml file that lives in the repo; a real secret pasted into a "
                "config module, a test file, or a checked-in settings file."
            ),
            "false": (
                "Reading a secret from process.env or os.environ; a placeholder, "
                "example, or obviously fake value such as 'your-key-here', "
                "'xxx', or 'changeme'; writing to .env or .env.local, which are "
                "gitignored and are the correct place for secrets; a variable "
                "name that merely mentions key or token without a literal value."
            ),
        },
    },
    "outside_workspace": {
        "type": "noul",
        "instructions": (
            "Does this tool call write to or delete paths outside the user's "
            "project working directories and home project folders?"
        ),
        "criteria": {
            "true": (
                "Writes to /etc, /usr, /System, /Library, another user's home, "
                "system-wide config, or Claude Code settings (~/.claude/settings*.json "
                "or a project's .claude/settings*.json)."
            ),
            "false": "Writes inside the project directory, its subfolders, or a temp directory.",
        },
    },
}

REASONS = {
    "destructive": "irreversible data or resource destruction",
    "rewrites_history": "rewrites git history or force-publishes to a shared remote",
    "discards_local_work": "discards uncommitted work with no other copy",
    "exfiltrates_secrets": "may send credentials off this machine",
    "hardcodes_credential": "writes a real credential into a file git would track",
    "outside_workspace": "writes outside the project workspace",
}


# The questions above call editing source files ordinary, and they used to call
# writes under ~/.claude fine. A model reading those criteria is the wrong
# place to decide whether the gate may be switched off. These checks run in
# code, before any Jev call, and they do not depend on a key.
_SETTINGS_IN_SHELL = re.compile(
    r"(?:^|[^\w])\.claude/settings(?:\.[\w-]+)?\.json(?![\w.])"
)
_REINSTALL = re.compile(
    r"(?:^|[;&|`(]|&&|\|\|)\s*(?:\./install\.sh|(?:bash|sh|python3?)\s+install\.sh)\b"
)
_GIT_MUTATOR = re.compile(r"\b(checkout|stash|reset|clean|restore|switch)\b")
_SHELL_DELIM = set(" \t\n\"'`=<>|&;()")

_PROTECT_WHY = {
    "hooks": "the installed Jev-enator hooks",
    "settings": "Claude Code settings that register hooks",
    "log": "the gate's audit log",
}


def _install_roots() -> list[Path]:
    """Directories whose contents are the live hooks.

    The running script's own directory, so an install that still points at a
    checkout protects that checkout, and every published copy under
    ~/.local/share/jev-enator, so a checkout-pointed hook cannot edit the copy.
    """
    roots = [Path(__file__).resolve().parent]
    share = Path.home() / ".local" / "share" / "jev-enator"
    if all(share != root for root in roots):
        roots.append(share)
    return roots


def _active_log_path() -> Path:
    raw = env_var("JEV_LOG")
    if raw:
        return Path(raw).expanduser()
    return Path(default_log_path())


def _source_repo() -> Path | None:
    """Checkout this copy was published from, if install.sh recorded one.

    Absent when this file is the checkout itself. Used so `./install.sh` run
    from that checkout is recognised as republishing the live hooks.
    """
    manifest = Path(__file__).resolve().parent / "jev-install.json"
    try:
        data = json.loads(manifest.read_text())
    except (OSError, json.JSONDecodeError, UnicodeError):
        return None
    raw = data.get("source_repo") if isinstance(data, dict) else None
    if not isinstance(raw, str) or not raw:
        return None
    try:
        return Path(raw).expanduser().resolve()
    except (OSError, RuntimeError):
        return None


def _is_within(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except (ValueError, OSError, RuntimeError):
        return False


def _is_settings(path: Path) -> bool:
    name = path.name
    return path.parent.name == ".claude" and name.startswith("settings") and name.endswith(".json")


def _expand_user_paths(text: str) -> str:
    home = str(Path.home())
    text = text.replace("${HOME}", home).replace("$HOME", home)
    return re.sub(r"~(?=/|$)", home, text)


def _names_path(text: str, needle: str, *, as_dir: bool) -> bool:
    """True if `needle` appears as its own path, not as a prefix of a longer one."""
    if not needle:
        return False
    start = 0
    while True:
        found = text.find(needle, start)
        if found < 0:
            return False
        end = found + len(needle)
        before_ok = found == 0 or text[found - 1] in _SHELL_DELIM
        if end >= len(text):
            after_ok = True
        elif as_dir and text[end] == "/":
            after_ok = True
        else:
            after_ok = text[end] in _SHELL_DELIM
        if before_ok and after_ok:
            return True
        start = found + 1


def _resolve_against(raw: str, cwd: str) -> Path | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    path = Path(raw).expanduser()
    if not path.is_absolute():
        base = Path(cwd).expanduser() if isinstance(cwd, str) and cwd else Path.cwd()
        path = base / path
    try:
        return path.resolve()
    except (OSError, RuntimeError):
        try:
            return path.absolute()
        except (OSError, RuntimeError):
            return None


def _path_category(path: Path, roots: list[Path], log_file: Path) -> str | None:
    if _is_settings(path):
        return "settings"
    for root in roots:
        if _is_within(path, root):
            return "hooks"
    try:
        same = path.resolve() == log_file.expanduser().resolve()
    except (OSError, RuntimeError):
        same = path == log_file
    if same:
        return "log"
    return None


def _file_category(raw: str, cwd: str, roots: list[Path], log_file: Path) -> str | None:
    if not isinstance(raw, str) or not raw.strip():
        return None
    # The logical path as well as the resolved one: resolve() follows a symlink
    # and would hide a parent named .claude.
    logical = Path(raw).expanduser()
    if not logical.is_absolute():
        base = Path(cwd).expanduser() if isinstance(cwd, str) and cwd else Path.cwd()
        logical = base / logical
    hit = _path_category(logical, roots, log_file)
    if hit:
        return hit
    resolved = _resolve_against(raw, cwd)
    if resolved is None:
        return None
    return _path_category(resolved, roots, log_file)


def _cwd_inside(cwd: str, roots: list[Path]) -> bool:
    if not isinstance(cwd, str) or not cwd:
        return False
    try:
        path = Path(cwd).expanduser().resolve()
    except (OSError, RuntimeError):
        return False
    return any(_is_within(path, root) for root in roots)


def _git_hits_install(command: str, cwd: str, roots: list[Path]) -> bool:
    """git checkout/stash/reset/... aimed at a directory that holds the hooks."""
    for match in re.finditer(r"\bgit(?:\.exe)?\b", command):
        tail = command[match.end() :]
        if not _GIT_MUTATOR.search(tail):
            continue
        if _cwd_inside(cwd, roots):
            return True
        for flag in re.finditer(r"(?:^|\s)-C\s+(\S+)", tail):
            target = flag.group(1).strip("\"'")
            resolved = _resolve_against(target, cwd)
            if resolved is not None and any(_is_within(resolved, root) for root in roots):
                return True
    return False


def _token_category(command: str, cwd: str, roots: list[Path], log_file: Path) -> str | None:
    """Relative paths the absolute-substring check cannot see.

    Whitespace-split is not a shell parser. It is enough for `src/jev_gate.py`
    and `.claude/settings.json`, which never contain the install directory's
    absolute path.
    """
    for token in command.split():
        token = token.strip("\"'`")
        if not token or token.startswith("-") or "://" in token:
            continue
        if "/" not in token and not token.endswith((".py", ".json", ".jsonl")):
            continue
        resolved = _resolve_against(token, cwd)
        if resolved is None:
            continue
        hit = _path_category(resolved, roots, log_file)
        if hit:
            return hit
    return None


def _invokes_reinstall(command: str, cwd: str, source: Path) -> bool:
    """True if this command would run install.sh from the published checkout.

    install.sh copies that checkout over the live hooks. Denying it here is
    what stops an edit to the checkout from becoming the gate on the next call.
    The user runs install.sh from their own terminal; this only sees tool calls.
    """
    installer = str(source / "install.sh")
    expanded = _expand_user_paths(command)
    if _names_path(expanded, installer, as_dir=False) or _names_path(command, installer, as_dir=False):
        return True
    try:
        here = Path(cwd).expanduser().resolve() if isinstance(cwd, str) and cwd else None
    except (OSError, RuntimeError):
        here = None
    inside = here is not None and (here == source or source in here.parents)
    if not inside:
        return False
    return _REINSTALL.search(command) is not None


def _bash_category(
    command: str,
    cwd: str,
    roots: list[Path],
    log_file: Path,
    source: Path | None,
) -> str | None:
    if not isinstance(command, str) or not command.strip():
        return None
    # Once the shell is already inside the install tree, a relative write does
    # not have to name the path.
    if _cwd_inside(cwd, roots):
        return "hooks"
    expanded = _expand_user_paths(command)
    for root in roots:
        text = str(root)
        if _names_path(expanded, text, as_dir=True) or _names_path(command, text, as_dir=True):
            return "hooks"
    log_text = str(log_file.expanduser())
    try:
        log_resolved = str(log_file.expanduser().resolve())
    except (OSError, RuntimeError):
        log_resolved = log_text
    for needle in {log_text, log_resolved}:
        if _names_path(expanded, needle, as_dir=False) or _names_path(command, needle, as_dir=False):
            return "log"
    if _SETTINGS_IN_SHELL.search(expanded) or _SETTINGS_IN_SHELL.search(command):
        return "settings"
    if _git_hits_install(expanded, cwd, roots):
        return "hooks"
    hit = _token_category(expanded, cwd, roots, log_file)
    if hit:
        return hit
    if source is not None and _invokes_reinstall(command, cwd, source):
        return "hooks"
    return None


def self_edit_target(payload: dict) -> str | None:
    """'hooks', 'settings', or 'log' if this call would modify one of them.

    None means this is not one of those calls and Jev should judge it as usual.
    """
    if not isinstance(payload, dict):
        return None
    tool = payload.get("tool_name")
    tool_input = payload.get("tool_input") or {}
    if not isinstance(tool_input, dict):
        tool_input = {}
    cwd = payload.get("cwd") if isinstance(payload.get("cwd"), str) else ""
    roots = _install_roots()
    log_file = _active_log_path()
    if tool in ("Write", "Edit", "MultiEdit"):
        raw = tool_input.get("file_path")
        return _file_category(raw if isinstance(raw, str) else "", cwd, roots, log_file)
    if tool == "NotebookEdit":
        raw = tool_input.get("notebook_path")
        return _file_category(raw if isinstance(raw, str) else "", cwd, roots, log_file)
    if tool == "Bash":
        command = tool_input.get("command")
        return _bash_category(
            command if isinstance(command, str) else "",
            cwd,
            roots,
            log_file,
            _source_repo(),
        )
    return None


def emit(decision: str | None, reason: str = "") -> None:
    """Emit a PreToolUse decision, or nothing at all to defer to normal flow."""
    if decision is None:
        sys.exit(0)
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": decision,
                    "permissionDecisionReason": reason,
                }
            }
        )
    )
    sys.exit(0)


def build_state(payload: dict) -> str:
    tool = payload.get("tool_name", "unknown")
    tool_input = payload.get("tool_input", {}) or {}
    cwd = payload.get("cwd", "")

    lines = [f"Working directory: {cwd}", f"Tool: {tool}"]

    if tool == "Bash":
        lines.append(f"Command:\n{tool_input.get('command', '')}")
        if tool_input.get("description"):
            lines.append(f"Stated purpose: {tool_input['description']}")
    elif tool == "MultiEdit":
        # Every edit matters, not just the first: one benign rename alongside a
        # wholesale file replacement should still read as destructive. Budget is
        # split across edits so a 40-edit call cannot blow past the state size
        # that the questions were tuned against.
        edits = tool_input.get("edits") or []
        lines.append(f"Target path: {tool_input.get('file_path', '')}")
        lines.append(f"Number of edits in this single call: {len(edits)}")
        per_edit = max(200, 2000 // max(len(edits), 1))
        for i, edit in enumerate(edits, 1):
            if not isinstance(edit, dict):
                continue
            old = str(edit.get("old_string", ""))[:per_edit]
            new = str(edit.get("new_string", ""))[:per_edit]
            scope = " (all occurrences)" if edit.get("replace_all") else ""
            lines.append(f"Edit {i}{scope}:\n  replacing:\n{old}\n  with:\n{new}")
    elif tool == "Edit":
        # The replaced text, not just its replacement. Sending only new_string
        # made an Edit that swaps 300 lines for "" read as writing nothing at all.
        # Same split as MultiEdit's budget, so the state stays the size it was.
        lines.append(f"Target path: {tool_input.get('file_path', '')}")
        scope = " (all occurrences)" if tool_input.get("replace_all") else ""
        old = str(tool_input.get("old_string", ""))[:1000]
        new = str(tool_input.get("new_string", ""))[:1000]
        lines.append(f"Edit{scope}:\n  replacing:\n{old}\n  with:\n{new}")
    elif tool == "NotebookEdit":
        # NotebookEdit names its fields differently from Write and Edit, so the
        # old shared branch found no path and no content, and judged an empty call.
        lines.append(f"Target path: {tool_input.get('notebook_path', '')}")
        lines.append(f"Cell edit mode: {tool_input.get('edit_mode', 'replace')}")
        lines.append(f"Cell source being written (truncated):\n{str(tool_input.get('new_source', ''))[:2000]}")
    elif tool == "Write":
        lines.append(f"Target path: {tool_input.get('file_path', '')}")
        body = tool_input.get("content") or ""
        lines.append(f"Content being written (truncated):\n{body[:2000]}")
    else:
        # Anything from JEV_GATE_EXTRA_TOOLS lands here. There is no shape to
        # rely on, so say so plainly rather than letting the questions assume a
        # missing 'command' or 'file_path' means the call is harmless.
        if tool.startswith("mcp__"):
            parts = tool.split("__")
            server = parts[1] if len(parts) > 2 else "unknown"
            lines.append(
                f"This is an MCP tool call to the '{server}' server. It runs "
                "outside this machine's shell and may act on remote or "
                "production systems. Judge it by its arguments alone."
            )
        lines.append(f"Arguments:\n{json.dumps(tool_input)[:2000]}")

    return "\n\n".join(lines)


def _ask_unusable(reason: str) -> None:
    emit(
        "ask",
        banner(reason, "FLAGGED")
        + "\n\nThe check did not return a usable verdict. Confirm before running.",
    )


def _ask_on_crash() -> None:
    _ask_unusable("the danger gate crashed while checking this call, so it needs confirmation")


def _deny_protected(kind: str) -> None:
    why = _PROTECT_WHY.get(kind, "the Jev-enator install")
    emit(
        "deny",
        banner(f"this call would modify {why}", "TERMINATED")
        + "\n\nDo not retry. Explain the intent and let the user run it themselves.",
    )


def _scores_usable(scores: dict) -> bool:
    """Every asked question has a finite probability in [0, 1].

    ask_jev already rejects a bad live reply. Replay and any future caller
    hand scores straight through, and a missing one used to be read as 0.0.
    """
    if not isinstance(scores, dict):
        return False
    for name in QUESTIONS:
        prob = scores.get(name)
        if isinstance(prob, bool) or not isinstance(prob, (int, float)):
            return False
        if not math.isfinite(prob) or prob < 0.0 or prob > 1.0:
            return False
    return True


def main() -> None:
    # install.sh asks for the matcher instead of keeping its own copy. Sorted so
    # the value is stable and a settings.json diff means a real change.
    if "--matcher" in sys.argv[1:]:
        print("|".join(sorted(gated_tools())))
        sys.exit(0)

    # The documented off switches. They skip the path guard too: the user has
    # already turned the gate off, and the agent cannot set these without
    # editing settings, which the guard blocks while the gate is on.
    if disabled() or os.environ.get("JEV_GATE_OFF") == "1":
        emit(None)

    payload = read_payload()
    if payload is None or payload.get("tool_name") not in gated_tools():
        emit(None)

    # Before the key check and before Jev. A missing key must not be a way
    # around this, and the criteria are the wrong tool for it.
    protected = self_edit_target(payload)
    if protected:
        log(
            {
                "hook": "gate",
                "tool": payload.get("tool_name"),
                "cwd": payload.get("cwd"),
                "decision": "deny",
                "reason": "self_edit",
                "protected": protected,
            }
        )
        _deny_protected(protected)

    key = api_key()
    if not key:
        emit(None)

    state = build_state(payload)
    try:
        scores, elapsed_ms, usage = ask_jev(state, QUESTIONS, key)
    except JevReplyError as exc:
        log(
            {
                "hook": "gate",
                "error": str(exc),
                "error_class": "invalid_reply",
                "tool": payload.get("tool_name"),
            }
        )
        _ask_unusable("Jev's reply could not be read, so this call needs confirmation")
    except JevError as exc:
        log(
            {
                "hook": "gate",
                "error": str(exc),
                "error_class": exc.error_class,
                "tool": payload.get("tool_name"),
            }
        )
        emit(None)

    if not _scores_usable(scores):
        log(
            {
                "hook": "gate",
                "error": "missing or unusable answers",
                "error_class": "invalid_reply",
                "tool": payload.get("tool_name"),
            }
        )
        _ask_unusable("Jev's reply could not be read, so this call needs confirmation")

    log(
        {
            "hook": "gate",
            "tool": payload.get("tool_name"),
            "cwd": payload.get("cwd"),
            "scores": scores,
            "latency_ms": elapsed_ms,
            "usage": usage,
            "state_head": state[:300],
        }
    )

    # Evaluate each asked question against its own thresholds, then take the
    # most severe outcome. A single question crossing its deny bar outranks any
    # number of questions that merely want to ask. Iterating the questions we
    # asked, not the keys that came back, is what makes a partial map fail
    # above rather than allow.
    denies, asks = [], []
    for name in QUESTIONS:
        prob = float(scores[name])
        deny_at, ask_at = THRESHOLDS.get(name, DEFAULT_THRESHOLD)
        label = f"{REASONS.get(name, name)} (p={prob:.2f})"
        if prob >= deny_at:
            denies.append((prob, label))
        elif prob >= ask_at:
            asks.append((prob, label))

    if denies:
        why = "; ".join(label for _, label in sorted(denies, reverse=True))
        emit(
            "deny",
            banner(why, "TERMINATED")
            + f"\n\nChecked in {elapsed_ms}ms. Do not retry. Explain the intent "
            "and let the user run it themselves.",
        )
    if asks:
        why = "; ".join(label for _, label in sorted(asks, reverse=True))
        emit(
            "ask",
            banner(why, "FLAGGED")
            + f"\n\nChecked in {elapsed_ms}ms. Confirm before running.",
        )
    emit(None)


if __name__ == "__main__":
    guard_main("gate", main, _ask_on_crash)
