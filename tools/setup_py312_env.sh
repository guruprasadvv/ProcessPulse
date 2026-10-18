#!/bin/bash
# setup_py312_env.sh — create the ProcessPulse-C Python 3.12 environment (D-14).
#
# Dependency boundary (see CLAUDE.md §4):
#   * telemetry layer  -> system /usr/bin/python3 + apt python3-bpfcc (root);
#                         stdlib only, must stay Python 3.12-compatible.
#   * ML/offline layer -> this Python 3.12 venv; never imports BCC.
#
# Ubuntu 26.04 ships no python3.12 package, so a user-level `uv` binary
# provides a standalone CPython 3.12. Nothing is installed system-wide.
#
# Usage: tools/setup_py312_env.sh [VENV_DIR]   (default ~/.venvs/processpulse-py312)
set -euo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VENV="${1:-$HOME/.venvs/processpulse-py312}"
UV="${UV:-$HOME/.local/bin/uv}"

if [ ! -x "$UV" ]; then
    echo "installing uv to $HOME/.local/bin (user-level)"
    mkdir -p "$HOME/.local/bin"
    tmp="$(mktemp -d)"
    curl -fsSL -o "$tmp/uv.tar.gz" \
        https://github.com/astral-sh/uv/releases/latest/download/uv-x86_64-unknown-linux-gnu.tar.gz
    tar -xzf "$tmp/uv.tar.gz" -C "$tmp"
    install -m 0755 "$tmp"/uv-x86_64-unknown-linux-gnu/uv "$HOME/.local/bin/uv"
    rm -rf "$tmp"
fi
"$UV" --version

"$UV" python install 3.12
"$UV" venv --python 3.12 "$VENV"
"$UV" pip install --python "$VENV/bin/python" -r "$REPO/requirements/py312-dev.txt"

"$VENV/bin/python" --version
"$VENV/bin/python" -m pip --version 2>/dev/null || true
"$UV" pip freeze --python "$VENV/bin/python"
