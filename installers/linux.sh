#!/usr/bin/env sh
set -eu

# Linux package installs (Debian/Ubuntu class).
install_core_packages() {
  if command -v apt-get >/dev/null 2>&1; then
    log_info "Installing core packages with apt"
    sudo apt-get update
    sudo apt-get install -y git curl build-essential
  else
    die "apt-get not found; unsupported Linux package manager"
  fi
}
