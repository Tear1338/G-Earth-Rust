#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_SRC="${1:-$SCRIPT_DIR/gearth-desktop}"
ICON_SRC="${2:-$SCRIPT_DIR/g_earth_icon.png}"
PREFIX="${XDG_DATA_HOME:-$HOME/.local/share}"
BIN_DIR="${HOME}/.local/bin"

if [[ ! -f "$BIN_SRC" ]]; then
  echo "error: gearth-desktop binary not found at $BIN_SRC" >&2
  exit 1
fi

install -Dm755 "$BIN_SRC" "$BIN_DIR/gearth-desktop"
if [[ -f "$ICON_SRC" ]]; then
  install -Dm644 "$ICON_SRC" "$PREFIX/icons/hicolor/64x64/apps/gearth-rust.png"
fi
install -Dm644 "$SCRIPT_DIR/gearth-rust.desktop" "$PREFIX/applications/gearth-rust.desktop"
echo "Installed G-Earth Rust to $BIN_DIR/gearth-desktop"
