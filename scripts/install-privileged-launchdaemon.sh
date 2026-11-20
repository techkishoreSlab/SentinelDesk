#!/usr/bin/env bash
# Install the SentinelDesk privileged install service as a macOS LaunchDaemon.
#
# STOP / decision D2: Do NOT run this until the product owner explicitly approves
# installing a root LaunchDaemon. Real package installs require that approval.
#
# Safe preview (no root changes):
#   ./scripts/install-privileged-launchdaemon.sh --print-plist
#
# Install only after approval:
#   SENTINEL_APPROVE_LAUNCHDAEMON=I_APPROVE_D2 sudo -E ./scripts/install-privileged-launchdaemon.sh

set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LABEL="com.sentineldesk.privileged"
PLIST_DEST="/Library/LaunchDaemons/${LABEL}.plist"
BIN_DEST="/usr/local/sentineldesk/bin/sentinel-privileged"
SOCKET_PATH="/var/run/sentineldesk/privileged.sock"
# Shared package drop dir: agent (user) writes pkgs here; daemon (root) installs from here.
PACKAGE_ROOT="/Users/Shared/SentinelDesk/packages"
RUN_DIR="/var/run/sentineldesk"
SOCKET_GROUP="${SENTINEL_SOCKET_GROUP:-staff}"

usage() {
  cat <<EOF
Usage: $0 [--print-plist] [--build-only]

  --print-plist   Write the LaunchDaemon plist to stdout (no install).
  --build-only    cargo build --release -p sentinel-privileged and exit.

Environment:
  SENTINEL_APPROVE_LAUNCHDAEMON=I_APPROVE_D2   required for real install
  SENTINEL_PACKAGE_ROOT   override package root (default: ${PACKAGE_ROOT})
EOF
}

PRINT_PLIST=0
BUILD_ONLY=0
for arg in "$@"; do
  case "$arg" in
    --print-plist) PRINT_PLIST=1 ;;
    --build-only) BUILD_ONLY=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $arg" >&2; usage; exit 1 ;;
  esac
done

PACKAGE_ROOT="${SENTINEL_PACKAGE_ROOT:-$PACKAGE_ROOT}"

render_plist() {
  cat <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${LABEL}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${BIN_DEST}</string>
    <string>--socket</string>
    <string>${SOCKET_PATH}</string>
    <string>--package-root</string>
    <string>${PACKAGE_ROOT}</string>
    <string>--socket-group</string>
    <string>${SOCKET_GROUP}</string>
  </array>
  <key>RunAtLoad</key>
  <true/>
  <key>KeepAlive</key>
  <true/>
  <key>UserName</key>
  <string>root</string>
  <key>GroupName</key>
  <string>wheel</string>
  <key>StandardOutPath</key>
  <string>/var/log/sentineldesk/privileged.log</string>
  <key>StandardErrorPath</key>
  <string>/var/log/sentineldesk/privileged.err</string>
</dict>
</plist>
EOF
}

if [[ "$PRINT_PLIST" -eq 1 ]]; then
  render_plist
  exit 0
fi

echo "Building sentinel-privileged (release)…"
(cd "$ROOT/endpoint" && cargo build --release -p sentinel-privileged)
TARGET_DIR="$(
  cd "$ROOT/endpoint" && cargo metadata --format-version=1 --no-deps \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])'
)"
BIN_SRC="${TARGET_DIR}/release/sentinel-privileged"
if [[ ! -x "$BIN_SRC" ]]; then
  echo "missing binary: $BIN_SRC" >&2
  exit 1
fi

if [[ "$BUILD_ONLY" -eq 1 ]]; then
  echo "Built: $BIN_SRC"
  exit 0
fi

if [[ "${SENTINEL_APPROVE_LAUNCHDAEMON:-}" != "I_APPROVE_D2" ]]; then
  cat >&2 <<EOF
Refusing to install LaunchDaemon (decision D2).

Built binary (not installed): ${BIN_SRC}

This would copy a root daemon to ${BIN_DEST}, write ${PLIST_DEST},
and load it with launchctl. Real installs can then run /usr/sbin/installer.

After explicit owner approval, re-run:
  SENTINEL_APPROVE_LAUNCHDAEMON=I_APPROVE_D2 sudo -E $0

Preview plist only:
  $0 --print-plist
EOF
  exit 2
fi

if [[ "$(id -u)" -ne 0 ]]; then
  echo "root required for LaunchDaemon install (re-run with sudo -E)" >&2
  exit 1
fi

mkdir -p "$(dirname "$BIN_DEST")" "$PACKAGE_ROOT" "$RUN_DIR" /var/log/sentineldesk
# Agent must be able to drop verified .pkg files into package_root.
chmod 1777 "$PACKAGE_ROOT"
chown root:wheel "$PACKAGE_ROOT" 2>/dev/null || true
install -m 755 "$BIN_SRC" "$BIN_DEST"
render_plist >"$PLIST_DEST"
chmod 644 "$PLIST_DEST"
chown root:wheel "$PLIST_DEST" "$BIN_DEST"
launchctl bootout system/"$LABEL" 2>/dev/null || true
launchctl bootstrap system "$PLIST_DEST"
launchctl enable system/"$LABEL"
launchctl kickstart -k system/"$LABEL"
# Wait briefly for the socket, then ensure group access for the console user.
for _ in 1 2 3 4 5 6 7 8 9 10; do
  [[ -S "$SOCKET_PATH" ]] && break
  sleep 0.5
done
if [[ -S "$SOCKET_PATH" ]]; then
  chgrp "$SOCKET_GROUP" "$SOCKET_PATH" || true
  chmod 660 "$SOCKET_PATH" || true
fi
echo "Installed and started ${LABEL}"
echo "Socket: ${SOCKET_PATH}"
echo "Package root: ${PACKAGE_ROOT}"
echo "Socket group: ${SOCKET_GROUP}"
