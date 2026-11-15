#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
APP="$ROOT/TaskMonitor.app"
CACHE="${TMPDIR:-/tmp}/task-monitor-swift-cache"

mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" "$CACHE"

echo "==> Compiling arm64 (Apple Silicon)..."
swiftc -parse-as-library \
  -module-cache-path "$CACHE" \
  -target arm64-apple-macos13.0 \
  -O \
  -framework AppKit \
  -framework IOKit \
  -o "$CACHE/TaskMonitor_arm64" \
  "$ROOT/TaskMonitor.swift"

echo "==> Compiling x86_64 (Intel)..."
swiftc -parse-as-library \
  -module-cache-path "$CACHE" \
  -target x86_64-apple-macos13.0 \
  -O \
  -framework AppKit \
  -framework IOKit \
  -o "$CACHE/TaskMonitor_x86_64" \
  "$ROOT/TaskMonitor.swift"

echo "==> Creating Universal Binary..."
lipo -create -output "$APP/Contents/MacOS/TaskMonitor" \
  "$CACHE/TaskMonitor_arm64" \
  "$CACHE/TaskMonitor_x86_64"

cp "$ROOT/Info.plist" "$APP/Contents/Info.plist"
if [ -f "$ROOT/AppIcon.icns" ]; then
  cp "$ROOT/AppIcon.icns" "$APP/Contents/Resources/AppIcon.icns"
fi
/usr/bin/codesign --force --deep --sign - "$APP" >/dev/null
printf 'Built Universal binary at %s\n' "$APP"
