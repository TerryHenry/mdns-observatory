#!/bin/bash
set -e
cd "$(dirname "$0")"
source "$(dirname "$0")/macos_setup.sh"
if ! ensure_supported_python; then exit 1; fi

if [ ! -d .venv ]; then "$PYTHON" -m venv .venv; fi
source .venv/bin/activate
VENV_ARCH="$(python -c 'import platform; print(platform.machine())' 2>/dev/null || true)"
HOST_ARCH="$(/usr/bin/uname -m)"
if [[ "$HOST_ARCH" == "arm64" && "$VENV_ARCH" != "arm64" && "$VENV_ARCH" != "aarch64" ]] || \
   [[ "$HOST_ARCH" == "x86_64" && "$VENV_ARCH" != "x86_64" && "$VENV_ARCH" != "amd64" ]]; then
  echo "The existing .venv architecture ($VENV_ARCH) does not match this Mac ($HOST_ARCH); recreating it."
  deactivate || true
  rm -rf .venv
  "$PYTHON" -m venv .venv
  source .venv/bin/activate
fi

python -m pip install --upgrade pip
python -m pip install -r requirements.txt pyinstaller
if ! pyinstaller --noconfirm --clean --windowed --name "mDNS Observatory" \
  --icon "resources/mDNS-Observatory.icns" \
  --add-data "resources/mDNS-Observatory.icns:resources" \
  --add-data "resources/mDNS-Observatory-1024.png:resources" \
  --add-data "service_catalog.json:." \
  --add-data "community_service_catalog.json:." \
  --add-data "THIRD_PARTY_NOTICES.md:." \
  --add-data "LICENSE:." \
  --collect-all scapy \
  --hidden-import scapy.arch.libpcap \
  mdns_snooper.py; then
  echo "PyInstaller failed. No app bundle was created; review the error above."
  read -r -p "Press Return to close..." _ || true
  exit 1
fi
cat <<'EOF2'

Build finished. Verify the app opens, the custom icon appears in Finder/Dock, and the dashboard charts populate after importing a capture or starting live monitoring.
The bundle is not code-signed or notarized.
EOF2
APP_PATH="$PWD/dist/mDNS Observatory.app"
if [ -d "$APP_PATH" ]; then
  echo "App created at: $APP_PATH"
  open "$APP_PATH"
else
  echo "Build command finished, but expected app bundle was not found at: $APP_PATH"
  echo "Check the PyInstaller output above."
fi
read -r -p "Press Return to close..." _ || true
