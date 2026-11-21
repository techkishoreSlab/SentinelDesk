#!/usr/bin/env bash
# Build tiny DMG fixtures for inspector / privileged-service tests.
#
# Outputs under fixtures/dmgs/. Requires macOS hdiutil for the app/pkg images;
# SLA and encrypted markers are synthesised without mounting.
#
#   ./scripts/make-test-dmgs.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${ROOT}/fixtures/dmgs"
WORK="${OUT}/.work"
rm -rf "$WORK"
mkdir -p "$OUT" "$WORK/app" "$WORK/pkg"

cleanup() {
  rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$WORK/app/Fixture.app/Contents/MacOS"
cat >"$WORK/app/Fixture.app/Contents/Info.plist" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>CFBundleIdentifier</key>
  <string>com.sentineldesk.fixture</string>
  <key>CFBundleName</key>
  <string>Fixture</string>
  <key>CFBundleShortVersionString</key>
  <string>1.0.0</string>
  <key>CFBundleExecutable</key>
  <string>Fixture</string>
  <key>LSMinimumSystemVersion</key>
  <string>12.0</string>
</dict>
</plist>
EOF
printf '#!/bin/sh\necho fixture\n' >"$WORK/app/Fixture.app/Contents/MacOS/Fixture"
chmod +x "$WORK/app/Fixture.app/Contents/MacOS/Fixture"

rm -f "$OUT/fixture-app.dmg"
hdiutil create \
  -volname "Fixture" \
  -srcfolder "$WORK/app" \
  -ov -format UDZO \
  -size 8m \
  "$OUT/fixture-app.dmg" >/dev/null

printf 'placeholder\n' >"$WORK/pkg/README.txt"
rm -f "$OUT/fixture-pkg-carrier.dmg"
hdiutil create \
  -volname "FixturePkg" \
  -srcfolder "$WORK/pkg" \
  -ov -format UDZO \
  -size 8m \
  "$OUT/fixture-pkg-carrier.dmg" >/dev/null

export OUT
python3 - <<'PY'
from pathlib import Path
import os
import plistlib
import struct

out_dir = Path(os.environ["OUT"])

xml = plistlib.dumps(
    {"resource-fork": {"LPic": [{"Data": b"\x00\x00", "ID": "5000"}], "blkx": []}}
)
body = b"\x00" * 64
trailer = bytearray(512)
trailer[:4] = b"koly"
struct.pack_into(">QQ", trailer, 216, len(body), len(xml))
(out_dir / "fixture-sla.dmg").write_bytes(body + xml + bytes(trailer))

(out_dir / "fixture-encrypted.dmg").write_bytes(b"encrcdsa" + b"\x00" * 1024)
print("wrote SLA + encrypted markers")
PY

ls -la "$OUT"/*.dmg
echo "Wrote fixtures under $OUT"
