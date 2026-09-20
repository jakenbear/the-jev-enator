#!/usr/bin/env python3
"""Refuse to run on a Python too old to parse the rest of this repo.

WHY THIS FILE EXISTS, and why it is so plain:

Every other module here uses PEP 604 annotations (`str | None`). On Python 3.9
that is not a syntax error -- it parses fine -- it is a TypeError raised when the
`def` line executes at import time. So importing jev_client on 3.9 dies before a
single line of hook logic runs.

A hook that dies on import is indistinguishable, from Claude Code's side, from a
hook that looked at the tool call and approved it: no stdout, no decision, normal
permission flow. That is the worst failure this repo can have. Someone installs
it, sees no errors, and is protected by nothing.

So this module is deliberately written in the oldest, dullest Python that will
still run: no annotations, no f-strings, no walrus, nothing from the last decade.
It has to survive being imported by the interpreter it is about to reject.

The hooks import and call this BEFORE importing jev_client. See the ordering
comment at each call site -- moving that import up is not a cleanup, it re-breaks
the thing this file exists to catch.
"""

import os
import sys

MIN_VERSION = (3, 10)

# Duplicated from jev_client.BRAND rather than imported, because importing
# jev_client is exactly what we cannot do yet. Kept short so the two are unlikely
# to drift in a way that matters; a test asserts they match.
_BRAND = "[ ⊙ ─ ] THE JEV-ENATOR"


def version_string(info=None):
    """'3.9.6' for a version_info-shaped tuple. No f-string: 3.5 must parse this."""
    if info is None:
        info = sys.version_info
    return "%d.%d.%d" % (info[0], info[1], info[2])


def problem():
    """Return a human-facing explanation, or None if this interpreter is fine."""
    if sys.version_info >= MIN_VERSION:
        return None
    return (
        "%s · MISCONFIGURED\n"
        "Python %s cannot run these hooks; %d.%d or newer is required.\n"
        "\n"
        "  interpreter: %s\n"
        "\n"
        "This matters more than a normal dependency error. Claude Code resolves\n"
        "the hook through '#!/usr/bin/env python3', so it uses whatever python3 is\n"
        "first on ITS PATH -- which is not necessarily the one you install with.\n"
        "Until this is fixed the hooks cannot run, and a hook that cannot run\n"
        "looks exactly like a hook that approved your tool call.\n"
        "\n"
        "Fix it by making a newer python3 first on PATH, for example:\n"
        "  brew install python@3.12        # macOS\n"
        "  sudo apt install python3.12     # Debian/Ubuntu\n"
        "\n"
        "Then re-run ./install.sh and ./verify.sh."
    ) % (_BRAND, version_string(), MIN_VERSION[0], MIN_VERSION[1], sys.executable)


def require_python():
    """Exit loudly if this interpreter is too old. Never returns on failure.

    Exits 1, deliberately not 2. For a PreToolUse hook Claude Code reads exit 2 as
    "deny this call", so exiting 2 here would block every single tool call in the
    session and the fastest way out would be to uninstall. Exit 1 surfaces the
    message to the user and lets the session continue, which is noisy every call --
    correct for a safety tool that is not currently protecting anything.

    JEV_DISABLE=1 silences it, on the same principle as everywhere else: the
    documented way to turn this repo off must keep working even when it is broken.
    The old JEV_GATE_DISABLE is honoured too -- the fallback is spelled out here
    instead of calling jev_client.env_var() because importing jev_client is the
    thing this module exists to avoid. A test asserts the two lists match.
    """
    why = problem()
    if why is None:
        return
    if os.environ.get("JEV_DISABLE") == "1" or os.environ.get("JEV_GATE_DISABLE") == "1":
        sys.exit(0)
    sys.stderr.write(why + "\n")
    sys.exit(1)


if __name__ == "__main__":
    # `python3 src/jev_pyversion.py` is the one-liner for "is this interpreter
    # usable", used by install.sh and verify.sh so the check lives in one place.
    why = problem()
    if why is None:
        sys.stdout.write("ok %s\n" % version_string())
        sys.exit(0)
    sys.stderr.write(why + "\n")
    sys.exit(1)
