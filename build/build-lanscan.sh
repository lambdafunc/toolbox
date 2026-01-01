#!/usr/bin/env sh
set -eu

# Build lan_scan for all supported OS/arch targets into ../bin.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
ROOT_DIR=$(CDPATH= cd -- "$SCRIPT_DIR/.." && pwd)
. "$ROOT_DIR/lib/common.sh"

if ! command -v go >/dev/null 2>&1; then
  die "Go is required to build lan_scan binaries"
fi

src="$ROOT_DIR/lan-scan/lanscan.go"
out_dir="$ROOT_DIR/bin"

mkdir -p "$out_dir"

build_one() {
  goos=$1
  goarch=$2
  name_os=$3
  name="lan_scan-${name_os}-${goarch}"
  GOOS=$goos GOARCH=$goarch go build -o "$out_dir/$name" "$src"
  log_info "Built $out_dir/$name"
}

build_one linux amd64 linux
build_one linux arm64 linux
build_one darwin amd64 macos
build_one darwin arm64 macos
