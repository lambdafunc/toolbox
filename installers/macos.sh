#!/usr/bin/env sh
set -eu

# macOS package installs.
install_core_packages() {
  if ! command -v brew >/dev/null 2>&1; then
    die "Homebrew is required on macOS. Install it from https://brew.sh"
  fi

  log_info "Installing core packages with Homebrew"
  brew install git curl

  if ! xcode-select -p >/dev/null 2>&1; then
    log_warn "Xcode Command Line Tools not detected; some builds may fail"
  fi
}
