#!/usr/bin/env sh
set -eu

# Example Go build helper: builds a package into $HOME/bin for this arch.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
. "$SCRIPT_DIR/../lib/detect.sh"
. "$SCRIPT_DIR/../lib/common.sh"

pkg=${1:-}
name=${2:-}

if [ -z "$pkg" ] || [ -z "$name" ]; then
  die "Usage: $0 <go-package> <output-name>"
fi

ensure_bin_dir

GOOS=$OS GOARCH=$ARCH go build -o "$HOME/bin/$name" "$pkg"
log_info "Built $HOME/bin/$name for $OS/$ARCH"
