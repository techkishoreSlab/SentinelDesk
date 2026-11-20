#!/usr/bin/env bash
# Download and SHA-256-verify the GitHub CLI macOS universal pkg (Phase 8 candidate).
# Does NOT install the package.

set -euo pipefail

VERSION="2.104.0"
URL="https://github.com/cli/cli/releases/download/v${VERSION}/gh_${VERSION}_macOS_universal.pkg"
EXPECTED_SHA256="5a4dd756bd3dea06c39edcc8c97653d85198774d9991790b7221f08b42281df6"
DEST_DIR="${SENTINEL_PACKAGE_DIR:-${TMPDIR:-/tmp}/sentineldesk-packages}"
DEST="${DEST_DIR}/gh_${VERSION}_macOS_universal.pkg"

mkdir -p "$DEST_DIR"
echo "Downloading ${URL}"
curl -fsSL -o "$DEST" "$URL"
ACTUAL="$(shasum -a 256 "$DEST" | awk '{print $1}')"
if [[ "$ACTUAL" != "$EXPECTED_SHA256" ]]; then
  echo "DIGEST_MISMATCH expected=${EXPECTED_SHA256} actual=${ACTUAL}" >&2
  rm -f "$DEST"
  exit 1
fi
echo "Staged OK: ${DEST}"
echo "sha256=${ACTUAL}"
echo "bytes=$(wc -c <"$DEST" | tr -d ' ')"
