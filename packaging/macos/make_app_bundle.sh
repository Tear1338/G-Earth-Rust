#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="${1:?usage: make_app_bundle.sh <gearth-desktop> <icon.png> <output-dir>}"
ICON="${2:?usage: make_app_bundle.sh <gearth-desktop> <icon.png> <output-dir>}"
OUT_DIR="${3:?usage: make_app_bundle.sh <gearth-desktop> <icon.png> <output-dir>}"

APP_DIR="$OUT_DIR/G-Earth Rust.app"
rm -rf "$APP_DIR"
mkdir -p "$APP_DIR/Contents/MacOS" "$APP_DIR/Contents/Resources"
cp "$BINARY" "$APP_DIR/Contents/MacOS/gearth-desktop"
chmod +x "$APP_DIR/Contents/MacOS/gearth-desktop"
cp "$SCRIPT_DIR/Info.plist" "$APP_DIR/Contents/Info.plist"
cp "$ICON" "$APP_DIR/Contents/Resources/g_earth_icon.png"
echo "Created $APP_DIR"
