# toolbox

Portable, platform-independent developer toolbox for Linux and macOS.

## Quick start

```sh
./install.sh
```

## Layout

- `install.sh` entrypoint
- `lib/` shared helpers
- `installers/` platform-specific package logic
- `build/` per-arch build helpers
- `dotfiles/` symlinked into `$HOME`
- `bin/` local tools installed into `$HOME/bin`

## Notes

- Requires `sudo` on Linux for apt.
- Homebrew must already be installed on macOS.
- `lan_scan` is installed from `bin/lan_scan-<os>-<arch>` into `~/.local/bin/lan_scan`.
- To refresh binaries on the dev machine, run `build/build-lanscan.sh`.
- Dotfiles are symlinked, never copied.
