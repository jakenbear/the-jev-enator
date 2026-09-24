#!/usr/bin/env bash
# Where the tokens in your Claude Code sessions go. See src/jev_tokens.py.
set -euo pipefail
exec python3 "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/src/jev_tokens.py" "$@"
