#!/bin/bash
set -e
cd "$(dirname "$0")"
source "$(dirname "$0")/macos_setup.sh"
if ! ensure_supported_python; then exit 1; fi

if [ ! -d .venv ]; then
  echo "Creating the app's isolated Python environment..."
  "$PYTHON" -m venv .venv
fi
source .venv/bin/activate

# A previously-created virtual environment may point at an incompatible Python.
VENV_ARCH="$(python -c 'import platform; print(platform.machine())' 2>/dev/null || true)"
HOST_ARCH="$(/usr/bin/uname -m)"
if [[ "$HOST_ARCH" == "arm64" && "$VENV_ARCH" != "arm64" && "$VENV_ARCH" != "aarch64" ]] || \
   [[ "$HOST_ARCH" == "x86_64" && "$VENV_ARCH" != "x86_64" && "$VENV_ARCH" != "amd64" ]]; then
  echo "The existing .venv uses architecture '$VENV_ARCH', but this Mac runs '$HOST_ARCH'."
  echo "Recreating only the app's isolated .venv..."
  deactivate || true
  rm -rf .venv
  "$PYTHON" -m venv .venv
  source .venv/bin/activate
fi

if ! python -m pip install --upgrade pip; then
  echo "Could not update pip. Check your network connection and rerun START-MAC.command."
  read -r -p "Press Return to close..." _ || true
  exit 1
fi
if ! python -m pip install -r requirements.txt; then
  echo "Dependency installation failed. The app has not been launched. Check the error above, then rerun START-MAC.command."
  read -r -p "Press Return to close..." _ || true
  exit 1
fi

echo "Launching mDNS Observatory..."
python mdns_snooper.py
