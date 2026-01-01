#!/usr/bin/env sh
set -eu

# Detect OS and architecture once and export for other scripts.
UNAME_S=$(uname -s)
UNAME_M=$(uname -m)

case "$UNAME_S" in
  Linux) OS=linux ;;
  Darwin) OS=macos ;;
  *) OS=unknown ;;
esac

case "$UNAME_M" in
  x86_64|amd64) ARCH=amd64 ;;
  arm64|aarch64) ARCH=arm64 ;;
  *) ARCH=unknown ;;
esac

export OS ARCH
