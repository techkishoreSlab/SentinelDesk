#!/usr/bin/env bash
# Install the single Sentinel.app into /Applications (removes duplicates).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
APP_SRC="${ROOT}/build/macos/Sentinel.app"
APP_DST="/Applications/Sentinel.app"
ZIP="$(ls -1t "${ROOT}/dist/macos"/SentinelDesk-macOS-*.zip 2>/dev/null | head -1 || true)"

# Stop every prior Sentinel UI / agent so only one menu-bar item remains and the
# new binary can report installer capabilities on first heartbeat.
launchctl bootout "gui/$(id -u)/com.sentineldesk.menubar" 2>/dev/null || true
launchctl bootout "gui/$(id -u)/com.sentineldesk.agent" 2>/dev/null || true
pkill -x SentinelMenuBar 2>/dev/null || true
pkill -x Sentinel 2>/dev/null || true
pkill -x sentinel-agent 2>/dev/null || true
pkill -f "com.SentinelDesk.Agent/bin/SentinelMenuBar" 2>/dev/null || true
sleep 0.5
# Stubborn orphans after SIGTERM (multiple relaunches share one device credential).
pkill -9 -x sentinel-agent 2>/dev/null || true
sleep 0.2

# Prefer zip → temp extract (build/ no longer keeps a Finder-visible .app after build).
if [[ ! -d "${APP_SRC}" ]]; then
  if [[ -z "${ZIP}" || ! -f "${ZIP}" ]]; then
    "${ROOT}/scripts/build-macos-desktop.sh"
    ZIP="$(ls -1t "${ROOT}/dist/macos"/SentinelDesk-macOS-*.zip 2>/dev/null | head -1 || true)"
  fi
  if [[ -z "${ZIP}" || ! -f "${ZIP}" ]]; then
    echo "No SentinelDesk-macOS-*.zip found. Run make macos-desktop first." >&2
    exit 1
  fi
  echo "Extracting ${ZIP}"
  mkdir -p "${ROOT}/build/macos"
  ditto -x -k "${ZIP}" "${ROOT}/build/macos"
fi

if [[ ! -d "${APP_SRC}" ]]; then
  echo "Sentinel.app not found after extract at ${APP_SRC}" >&2
  exit 1
fi

# Remove any other Sentinel.app copies under the home tree (not the build input).
while IFS= read -r extra; do
  case "${extra}" in
    "${APP_DST}"|"${APP_SRC}") continue ;;
    *)
      echo "Removing duplicate: ${extra}"
      rm -rf "${extra}"
      ;;
  esac
done < <(mdfind 'kMDItemCFBundleIdentifier == "com.sentineldesk.desktop"' 2>/dev/null || true)
rm -rf "${ROOT}/dist/macos/Sentinel.app"

echo "Installing single app → ${APP_DST}"
rm -rf "${APP_DST}"
ditto "${APP_SRC}" "${APP_DST}"
codesign --force --deep --sign - "${APP_DST}" 2>/dev/null || true

# Never leave a second Sentinel.app in the repo (Finder shows duplicates).
rm -rf "${APP_SRC}" "${ROOT}/dist/macos/Sentinel.app"

# Seed demo-machine preferences (local stack lifecycle). Shared client zips leave manageLocalStack off.
CFG_DIR="${HOME}/Library/Application Support/com.SentinelDesk.Agent"
mkdir -p "${CFG_DIR}"
python3 - <<PY
import json, pathlib
p = pathlib.Path("${CFG_DIR}/desktop-config.json")
cfg = {
  "backendURL": "https://localhost:8443",
  "webConsoleURL": "http://localhost:5173",
  "caCertPath": "",
  "packageDir": "/Users/Shared/SentinelDesk/packages",
  "privilegedSocket": "/var/run/sentineldesk/privileged.sock",
  "startAgentOnLaunch": True,
  "manageLocalStack": True,
  "repoRoot": "${ROOT}",
  "startWebDevServer": True,
  "openConsoleOnLaunch": True,
  "stopStackOnQuit": True,
}
p.write_text(json.dumps(cfg, indent=2))
p.chmod(0o600)
print("Seeded demo preferences →", p)
PY

open "${APP_DST}"
echo "OK — only /Applications/Sentinel.app"
echo "Open: starts Docker (demo) + agent + opens console. Quit: stops agent + Docker."
echo "Shared builds: leave Preferences → Local demo stack unchecked (SaaS mode)."
