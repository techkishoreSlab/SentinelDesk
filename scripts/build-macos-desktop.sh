#!/usr/bin/env bash
# Build a shareable Sentinel.app (menu-bar SaaS desktop) + zip for other Macs.
# Only ONE installed app should live in /Applications; dist/ keeps the zip only.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SRC="${ROOT}/desktop/macos/Sources"
RES="${ROOT}/desktop/macos/Resources"
BUILD="${ROOT}/build/macos"
DIST="${ROOT}/dist/macos"
APP="${BUILD}/Sentinel.app"
MACOS_DIR="${APP}/Contents/MacOS"
RES_DIR="${APP}/Contents/Resources"
VERSION="0.1.2"

export PATH="${HOME}/.cargo/bin:${PATH}"

if ! command -v swiftc >/dev/null 2>&1; then
  echo "swiftc not found — install Xcode Command Line Tools." >&2
  exit 1
fi

echo "==> Building sentinel-agent (release)"
(cd "${ROOT}/endpoint" && cargo build --release -p sentinel-agent)

echo "==> Compiling Sentinel desktop UI"
rm -rf "${BUILD}"
mkdir -p "${DIST}" "${MACOS_DIR}" "${RES_DIR}"
# shellcheck disable=SC2046
swiftc -O \
  -target "$(uname -m)-apple-macosx12.0" \
  -sdk "$(xcrun --show-sdk-path)" \
  -framework AppKit -framework Foundation \
  -o "${MACOS_DIR}/Sentinel" \
  $(printf '%s\n' "${SRC}"/*.swift | sort)

echo "==> Generating AppIcon.icns"
ICON_WORK="${BUILD}/icon-work"
mkdir -p "${ICON_WORK}"
swift "${ROOT}/scripts/macos/generate-app-icon.swift" "${ICON_WORK}/AppIcon.iconset"
if ! iconutil -c icns "${ICON_WORK}/AppIcon.iconset" -o "${RES_DIR}/AppIcon.icns"; then
  echo "warning: iconutil failed; continuing without AppIcon.icns" >&2
fi
rm -rf "${ICON_WORK}"

echo "==> Assembling app bundle"
cp -f "${RES}/Info.plist" "${APP}/Contents/Info.plist"
cp -f "${ROOT}/endpoint/target/release/sentinel-agent" "${MACOS_DIR}/sentinel-agent"
chmod 755 "${MACOS_DIR}/Sentinel" "${MACOS_DIR}/sentinel-agent"

if [[ -f "${ROOT}/dev-certs/ca.pem" ]]; then
  cp -f "${ROOT}/dev-certs/ca.pem" "${RES_DIR}/ca.pem"
fi
if [[ -f "${ROOT}/dev-keys/job_signing_public.pem" ]]; then
  cp -f "${ROOT}/dev-keys/job_signing_public.pem" "${RES_DIR}/job_signing_public.pem"
fi

printf 'APPL????' > "${APP}/Contents/PkgInfo"

echo "==> Ad-hoc codesign (demo distribution)"
codesign --force --deep --sign - "${MACOS_DIR}/sentinel-agent" 2>/dev/null || true
codesign --force --deep --sign - "${APP}" 2>/dev/null || true

ZIP="${DIST}/SentinelDesk-macOS-${VERSION}.zip"
rm -f "${ZIP}" "${DIST}/Sentinel.app"
# Remove older demo zips so Finder/share folder stays clean.
rm -f "${DIST}"/SentinelDesk-macOS-*.zip
(
  cd "${BUILD}"
  ditto -c -k --sequesterRsrc --keepParent "Sentinel.app" "${ZIP}"
)

SHA="$(shasum -a 256 "${ZIP}" | awk '{print $1}')"
cat > "${DIST}/SHA256SUMS.txt" <<EOF
${SHA}  SentinelDesk-macOS-${VERSION}.zip
EOF

cat > "${DIST}/README-SHARE.txt" <<EOF
SentinelDesk macOS desktop (demo) — ${VERSION}

Share this folder’s ZIP only (not a second .app next to it).

  SentinelDesk-macOS-${VERSION}.zip
  SHA256SUMS.txt

Install on a Mac
  1. Unzip → drag the single Sentinel.app into Applications (replace if asked).
  2. If macOS blocks it: System Settings → Privacy & Security → Open Anyway.
  3. Open Applications → Sentinel (one menu-bar item).

On the build machine use: make macos-desktop-install

Backend defaults: https://localhost:8443  /  http://localhost:5173

SHA-256
  ${SHA}
EOF

# Keep zip for sharing; remove unpacked .app so Finder does not show a second copy.
rm -rf "${APP}"

echo "OK — share zip only: ${ZIP}"
echo "Install locally: make macos-desktop-install  → /Applications/Sentinel.app (only copy)"
echo "SHA-256: ${SHA}"
