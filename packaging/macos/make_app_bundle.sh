#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BINARY="${1:?usage: make_app_bundle.sh <gearth-desktop> <icon.png> <output-dir> [version]}"
ICON="${2:?usage: make_app_bundle.sh <gearth-desktop> <icon.png> <output-dir> [version]}"
OUT_DIR="${3:?usage: make_app_bundle.sh <gearth-desktop> <icon.png> <output-dir> [version]}"
VERSION="${4:-1.0.0}"

APP_DIR="$OUT_DIR/G-Earth Rust.app"
rm -rf "$APP_DIR"
mkdir -p "$APP_DIR/Contents/MacOS" "$APP_DIR/Contents/Resources"
cp "$BINARY" "$APP_DIR/Contents/MacOS/gearth-desktop"
chmod 755 "$APP_DIR/Contents/MacOS/gearth-desktop"
cp "$SCRIPT_DIR/Info.plist" "$APP_DIR/Contents/Info.plist"

if command -v /usr/libexec/PlistBuddy >/dev/null 2>&1; then
  /usr/libexec/PlistBuddy -c "Set :CFBundleShortVersionString $VERSION" "$APP_DIR/Contents/Info.plist"
  /usr/libexec/PlistBuddy -c "Set :CFBundleVersion $VERSION" "$APP_DIR/Contents/Info.plist"
fi

if command -v sips >/dev/null 2>&1 && command -v iconutil >/dev/null 2>&1; then
  ICONSET="$(mktemp -d)/AppIcon.iconset"
  mkdir -p "$ICONSET"
  for size in 16 32 128 256 512; do
    sips -z "$size" "$size" "$ICON" --out "$ICONSET/icon_${size}x${size}.png" >/dev/null
    double=$((size * 2))
    sips -z "$double" "$double" "$ICON" --out "$ICONSET/icon_${size}x${size}@2x.png" >/dev/null
  done
  iconutil -c icns "$ICONSET" -o "$APP_DIR/Contents/Resources/AppIcon.icns"
  rm -rf "$(dirname "$ICONSET")"
else
  cp "$ICON" "$APP_DIR/Contents/Resources/g_earth_icon.png"
fi

if command -v codesign >/dev/null 2>&1; then
  codesign --force --deep --sign - "$APP_DIR"
  codesign --verify --deep --strict "$APP_DIR"
fi

echo "Created $APP_DIR (version $VERSION)"
