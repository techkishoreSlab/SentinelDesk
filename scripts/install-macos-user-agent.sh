#!/usr/bin/env bash
# Install always-on user agent + menu bar for Mac demo (no Terminal after this).
# Does NOT install the root LaunchDaemon (that remains D2 / privileged path).

set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AGENT_BIN="${ROOT}/endpoint/target/release/sentinel-agent"
CFG="${HOME}/Library/Application Support/com.SentinelDesk.Agent"
LAUNCH_AGENTS="${HOME}/Library/LaunchAgents"
BIN_DIR="${HOME}/Library/Application Support/com.SentinelDesk.Agent/bin"
MENUBAR_BIN="${BIN_DIR}/SentinelMenuBar"
LABEL_AGENT="com.sentineldesk.agent"
LABEL_MENU="com.sentineldesk.menubar"
BACKEND_URL="${SENTINEL_BACKEND_URL:-https://localhost:8443}"
CA_CERT="${SENTINEL_CA_CERT:-${ROOT}/dev-certs/ca.pem}"

export PATH="${HOME}/.cargo/bin:${PATH}"

echo "Building sentinel-agent (release)…"
(cd "${ROOT}/endpoint" && cargo build --release -p sentinel-agent)

mkdir -p "${CFG}" "${BIN_DIR}" "${LAUNCH_AGENTS}"
mkdir -p /Users/Shared/SentinelDesk/packages
chmod 755 /Users/Shared/SentinelDesk /Users/Shared/SentinelDesk/packages 2>/dev/null || true
cp -f "${ROOT}/dev-keys/job_signing_public.pem" "${CFG}/job_signing_public.pem"
chmod 644 "${CFG}/job_signing_public.pem"

if ! command -v swiftc >/dev/null 2>&1; then
  echo "swiftc not found; install Xcode CLT for the menu bar helper." >&2
  exit 1
fi
echo "Building menu bar helper…"
swiftc -O -o "${MENUBAR_BIN}" "${ROOT}/scripts/macos/SentinelMenuBar.swift"
chmod 755 "${MENUBAR_BIN}"

# Persist backend settings for LaunchAgent environment.
cat > "${CFG}/agent.env" <<EOF
SENTINEL_BACKEND_URL=${BACKEND_URL}
SENTINEL_CA_CERT=${CA_CERT}
SENTINEL_PACKAGE_DIR=/Users/Shared/SentinelDesk/packages
SENTINEL_PRIVILEGED_SOCKET=/var/run/sentineldesk/privileged.sock
EOF

AGENT_PLIST="${LAUNCH_AGENTS}/${LABEL_AGENT}.plist"
MENU_PLIST="${LAUNCH_AGENTS}/${LABEL_MENU}.plist"

cat > "${AGENT_PLIST}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${LABEL_AGENT}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${AGENT_BIN}</string>
    <string>run</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>WorkingDirectory</key><string>${HOME}</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>SENTINEL_BACKEND_URL</key><string>${BACKEND_URL}</string>
    <key>SENTINEL_CA_CERT</key><string>${CA_CERT}</string>
    <key>SENTINEL_PACKAGE_DIR</key><string>/Users/Shared/SentinelDesk/packages</string>
    <key>SENTINEL_PRIVILEGED_SOCKET</key><string>/var/run/sentineldesk/privileged.sock</string>
    <key>SENTINEL_AGENT_CONFIG_DIR</key><string>${CFG}</string>
  </dict>
  <key>StandardOutPath</key><string>${CFG}/agent.out.log</string>
  <key>StandardErrorPath</key><string>${CFG}/agent.err.log</string>
</dict>
</plist>
EOF

cat > "${MENU_PLIST}" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>${LABEL_MENU}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${MENUBAR_BIN}</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict>
</plist>
EOF

launchctl bootout "gui/$(id -u)/${LABEL_AGENT}" 2>/dev/null || true
launchctl bootout "gui/$(id -u)/${LABEL_MENU}" 2>/dev/null || true
launchctl bootstrap "gui/$(id -u)" "${AGENT_PLIST}"
launchctl bootstrap "gui/$(id -u)" "${MENU_PLIST}"
launchctl enable "gui/$(id -u)/${LABEL_AGENT}"
launchctl enable "gui/$(id -u)/${LABEL_MENU}"
launchctl kickstart -k "gui/$(id -u)/${LABEL_AGENT}"
launchctl kickstart -k "gui/$(id -u)/${LABEL_MENU}"

echo "OK — user agent + menu bar installed."
echo "Menu bar should show: Sentinel · Online"
echo "Logs: ${CFG}/agent.out.log"
echo "Stop later: launchctl bootout gui/$(id -u)/${LABEL_AGENT}; launchctl bootout gui/$(id -u)/${LABEL_MENU}"
