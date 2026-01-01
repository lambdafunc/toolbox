#!/usr/bin/env sh
set -eu

# Entry point: keep this minimal and delegate to helpers.
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

. "$SCRIPT_DIR/lib/detect.sh"
. "$SCRIPT_DIR/lib/common.sh"

ensure_bin_dir

case "$OS" in
  linux) . "$SCRIPT_DIR/installers/linux.sh" ;;
  macos) . "$SCRIPT_DIR/installers/macos.sh" ;;
  *) die "Unsupported OS: $OS" ;;
esac

install_core_packages

symlink_dotfiles "$SCRIPT_DIR/dotfiles" "$HOME"

install_platform_binary "lan_scan" "$SCRIPT_DIR/bin"

log_info "Done. Ensure $HOME/.local/bin and $HOME/bin are on your PATH."
