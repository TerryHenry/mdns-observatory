#!/bin/bash
# Shared macOS architecture and Python bootstrap for mDNS Observatory.
# Never silently use an Intel Homebrew installation on Apple silicon (or vice versa).

mdns_setup_pause() { read -r -p "Press Return to close..." _ || true; }
mdns_setup_fail() {
  echo
  echo "SETUP STOPPED: $*"
  mdns_setup_pause
  return 1
}
mdns_python_arch() { "$1" -c 'import platform; print(platform.machine())' 2>/dev/null; }
mdns_arch_matches() {
  local pyarch="$1" machine="$2"
  if [[ "$machine" == "arm64" ]]; then
    [[ "$pyarch" == "arm64" || "$pyarch" == "aarch64" ]]
  else
    [[ "$pyarch" == "x86_64" || "$pyarch" == "amd64" ]]
  fi
}

ensure_supported_python() {
  local machine brew_prefix brew_bin other_brew candidate version pyarch answer tmp_installer
  local -a candidates
  machine="$(/usr/bin/uname -m)"
  case "$machine" in
    arm64)  brew_prefix="/opt/homebrew"; other_brew="/usr/local/bin/brew" ;;
    x86_64) brew_prefix="/usr/local"; other_brew="/opt/homebrew/bin/brew" ;;
    *) mdns_setup_fail "Unsupported Mac architecture '$machine'. Supported: arm64 (Apple silicon) and x86_64 (Intel)." || return 1; return 1 ;;
  esac
  brew_bin="$brew_prefix/bin/brew"
  echo "Detected Mac architecture: $machine"
  echo "Native Homebrew prefix for this Mac: $brew_prefix"

  # Use a compatible Python already installed before asking for build tools or Homebrew.
  candidates=(
    "$brew_prefix/opt/python@3.13/bin/python3.13"
    "$brew_prefix/bin/python3.13"
    "/Library/Frameworks/Python.framework/Versions/3.13/bin/python3.13"
    "$brew_prefix/opt/python@3.12/bin/python3.12"
    "$brew_prefix/bin/python3.12"
    "/Library/Frameworks/Python.framework/Versions/3.12/bin/python3.12"
  )
  for candidate in "${candidates[@]}" python3.13 python3.12; do
    if [[ "$candidate" != */* ]]; then
      command -v "$candidate" >/dev/null 2>&1 || continue
      candidate="$(command -v "$candidate")"
    fi
    [[ -x "$candidate" ]] || continue
    version="$("$candidate" -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")' 2>/dev/null || true)"
    pyarch="$(mdns_python_arch "$candidate" || true)"
    if [[ "$version" == "3.12" || "$version" == "3.13" ]]; then
      if mdns_arch_matches "$pyarch" "$machine"; then
        PYTHON="$candidate"; export PYTHON
        echo "Using native Python: $($PYTHON --version) ($PYTHON; $pyarch)"
        return 0
      fi
    fi
    echo "Skipping incompatible Python: $candidate (version=${version:-unknown}, architecture=${pyarch:-unknown})"
  done

  # Python must be installed with the architecture-matched Homebrew. First ensure Apple's tools exist.
  if ! /usr/bin/xcode-select -p >/dev/null 2>&1; then
    echo "Apple Command Line Tools are not installed or not selected."
    echo "Requesting Apple's installer now. Complete the installation dialog, then rerun this installer."
    /usr/bin/xcode-select --install >/dev/null 2>&1 || true
    mdns_setup_fail "Complete the Command Line Tools installation, then run this script again. No app changes were made." || return 1
    return 1
  fi

  if [[ ! -x "$brew_bin" ]]; then
    if [[ -x "$other_brew" ]]; then
      echo "Found Homebrew at $other_brew, but it belongs to the other architecture and will not be used."
    fi
    echo "Native Homebrew is not installed at $brew_bin."
    read -r -p "Install native Homebrew for $machine now? [y/N] " answer || answer="n"
    case "$answer" in
      y|Y|yes|YES)
        echo "Downloading the official Homebrew installer. It may request your macOS password."
        tmp_installer="$(/usr/bin/mktemp -t mdns-homebrew-install)"
        if ! /usr/bin/curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh -o "$tmp_installer"; then
          /bin/rm -f "$tmp_installer"
          mdns_setup_fail "Could not download the official Homebrew installer. Check your network and rerun." || return 1
          return 1
        fi
        if ! /bin/bash "$tmp_installer"; then
          /bin/rm -f "$tmp_installer"
          mdns_setup_fail "Homebrew installation failed. Review the output above and rerun this installer." || return 1
          return 1
        fi
        /bin/rm -f "$tmp_installer"
        ;;
      *)
        mdns_setup_fail "Native Homebrew is needed to install Python automatically. Install it from https://brew.sh/ and rerun this script." || return 1
        return 1
        ;;
    esac
  fi

  if [[ ! -x "$brew_bin" ]]; then
    mdns_setup_fail "Native Homebrew was not found at $brew_bin after installation. Open a new Terminal and rerun." || return 1
    return 1
  fi

  echo "Installing supported Python 3.13 with native Homebrew: $brew_bin"
  if ! "$brew_bin" install python@3.13; then
    mdns_setup_fail "Could not install Python 3.13 with native Homebrew. Review the error above and rerun." || return 1
    return 1
  fi
  candidate="$brew_prefix/opt/python@3.13/bin/python3.13"
  if [[ ! -x "$candidate" ]]; then
    mdns_setup_fail "Homebrew finished but Python was not found at $candidate." || return 1
    return 1
  fi
  pyarch="$(mdns_python_arch "$candidate" || true)"
  if ! mdns_arch_matches "$pyarch" "$machine"; then
    mdns_setup_fail "Installed Python architecture '$pyarch' does not match this Mac ('$machine')." || return 1
    return 1
  fi
  PYTHON="$candidate"; export PYTHON
  echo "Installed native Python: $($PYTHON --version) ($PYTHON; $pyarch)"
  return 0
}
