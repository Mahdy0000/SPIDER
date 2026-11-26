#!/usr/bin/env bash
# SPIDER one-command installer for Linux / WSL2 / macOS.
#   curl -fsSL https://raw.githubusercontent.com/Mahdy0000/SPIDER/main/install.sh | bash
# Does: checks Python 3.9+, installs Ollama if missing (official script), installs SPIDER into its own venv,
# then runs `spider start` (pulls the model, builds the local RAG index, opens the interactive loop).
set -euo pipefail
REPO="git+https://github.com/Mahdy0000/SPIDER.git"
VENV="$HOME/.spider/venv"

echo "== SPIDER install =="
command -v python3 >/dev/null || { echo "python3 not found. Install Python 3.9+ (e.g. sudo apt install python3 python3-venv python3-pip git) and re-run."; exit 1; }
command -v git >/dev/null || { echo "git not found. e.g. sudo apt install git"; exit 1; }
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 9) else 1)' || { echo "Python 3.9+ required."; exit 1; }
if ! command -v ollama >/dev/null; then
  echo "Installing Ollama (official installer from ollama.com) ..."
  curl -fsSL https://ollama.com/install.sh | sh
fi
mkdir -p "$HOME/.spider"
[ -x "$VENV/bin/python" ] || python3 -m venv "$VENV"
"$VENV/bin/python" -m pip install --upgrade --quiet pip
echo "Installing SPIDER (no third-party dependencies) ..."
"$VENV/bin/python" -m pip install --upgrade "$REPO"
echo
echo "Installed. Next time, start with:  $VENV/bin/spider start"
# when piped from curl, stdin is the script: reattach the terminal for the interactive loop
exec "$VENV/bin/python" -m spider start < /dev/tty
