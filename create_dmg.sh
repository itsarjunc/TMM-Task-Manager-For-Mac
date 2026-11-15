#!/bin/sh
set -eu

ROOT="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
DMG_NAME="TaskMonitor.dmg"
VOL_NAME="Task Monitor"
STAGING="$ROOT/dmg_staging"

echo "==> Building Task Monitor..."
"$ROOT/build.sh"

echo "==> Preparing DMG staging directory..."
rm -rf "$STAGING" "$ROOT/$DMG_NAME"
mkdir -p "$STAGING"

echo "==> Copying TaskMonitor.app..."
cp -R "$ROOT/TaskMonitor.app" "$STAGING/"

echo "==> Creating /Applications symlink..."
ln -s /Applications "$STAGING/Applications"

cat << 'EOF' > "$STAGING/How to Install.txt"
Task Monitor for macOS
======================

Installation:
1. Drag "Task Monitor" into the "Applications" folder.
2. Open Applications and launch "Task Monitor".

Note on First Launch (macOS Gatekeeper):
If macOS displays "Apple cannot check it for malicious software" or "Unidentified Developer":
• Option 1: Right-click (or Control-click) "Task Monitor" in Applications, choose "Open", and click "Open".
• Option 2: Run this command in Terminal:
  xattr -cr /Applications/TaskMonitor.app

Enjoy using Task Monitor!
EOF

echo "==> Creating DMG disk image ($DMG_NAME)..."
hdiutil create -volname "$VOL_NAME" \
  -srcfolder "$STAGING" \
  -ov \
  -format UDZO \
  "$ROOT/$DMG_NAME" >/dev/null

rm -rf "$STAGING"

echo "==> Done! DMG created at:"
echo "    $ROOT/$DMG_NAME"
