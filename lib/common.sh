#!/usr/bin/env sh
set -eu

log_info() {
  printf '%s\n' "[info] $*"
}

log_warn() {
  printf '%s\n' "[warn] $*" 1>&2
}

die() {
  printf '%s\n' "[error] $*" 1>&2
  exit 1
}

ensure_bin_dir() {
  if [ ! -d "$HOME/bin" ]; then
    log_info "Creating $HOME/bin"
    mkdir -p "$HOME/bin"
  fi
}

ensure_local_bin_dir() {
  if [ ! -d "$HOME/.local/bin" ]; then
    log_info "Creating $HOME/.local/bin"
    mkdir -p "$HOME/.local/bin"
  fi
}

install_platform_binary() {
  name=$1
  src_dir=$2

  src="$src_dir/${name}-${OS}-${ARCH}"
  dest="$HOME/.local/bin/$name"

  if [ ! -f "$src" ]; then
    die "Missing binary: $src (run build/build-lanscan.sh on the dev machine)"
  fi

  ensure_local_bin_dir
  symlink_file "$src" "$dest"
}

symlink_file() {
  src=$1
  dest=$2

  if [ -L "$dest" ]; then
    # Replace mismatched symlink targets.
    current=$(readlink "$dest" || true)
    if [ "$current" = "$src" ]; then
      return 0
    fi
    rm -f "$dest"
  elif [ -e "$dest" ]; then
    log_warn "Skipping $dest (exists and is not a symlink)"
    return 0
  fi

  ln -s "$src" "$dest"
  log_info "Linked $dest -> $src"
}

symlink_dotfiles() {
  dotdir=$1
  homedir=$2

  for file in "$dotdir"/*; do
    [ -e "$file" ] || continue
    base=$(basename "$file")
    symlink_file "$file" "$homedir/.${base}"
  done
}
