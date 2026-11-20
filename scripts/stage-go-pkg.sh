#!/usr/bin/env bash
# Download and SHA-256-verify the official Go macOS Intel pkg. Does NOT install.

set -euo pipefail

VERSION="1.27.4"
FILE="go${VERSION}.darwin-amd64.pkg"
URL="https://go.dev/dl/${FILE}"
EXPECTED_SHA256="98b6668684006873a3befee5cf155a110f79c3156ac718ddf45f59e4043a16b9"
DEST_DIR="${SENTINEL_PACKAGE_DIR:-/Users/Shared/SentinelDesk/packages}"
DEST="${DEST_DIR}/${FILE}"

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
echo "receipt_id=org.golang.go (pkgutil version go1.27.4)"
