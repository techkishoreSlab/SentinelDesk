# Sentinel macOS desktop app

Premium menu-bar SaaS client for the Mac demo. Double-click **Sentinel** in Applications — no Terminal required for day-to-day use.

## Is “open app = start Docker, quit = docker down” correct for Agent SaaS?

**Not for production multi-user SaaS.** Correct product shape:

| Layer | Who runs it | Desktop app role |
|---|---|---|
| Control plane (API, DB, web) | Hosted / always-on | Connect via URLs only |
| Endpoint agent | Each employee Mac | **Start/stop with Sentinel.app** |

If every laptop started/stopped Docker Compose, each machine would own the company backend — wrong for SaaS, and shared `.app` builds cannot assume Docker or the repo exist.

**Yes as an optional local demo mode** on the builder Mac (`make macos-desktop-install` seeds this):

- **Open Sentinel** → Docker Compose up (+ optional Vite) → start agent → open web console  
- **Quit Sentinel** → stop agent → Docker Compose down (if enabled)

Shared client zips keep **Local demo stack** off (agent-only SaaS mode). Toggle in **Preferences**.

## What you get

| Surface | Behavior |
|---|---|
| Menu bar | Shield icon + `Online` / `Installing…` / `Off` (one instance only) |
| Popover | Status, device, control-plane line, console / prefs / restart / quit |
| Quit | Right‑click → **Quit Sentinel**, or popover Quit (⌘Q) |
| Preferences | Connection URLs + optional Local demo stack |
| Embedded agent | `sentinel-agent` inside the `.app` |

## Build & install (this machine)

```bash
cd ~/Documents/Sentinel_Desk
make macos-desktop-install    # builds, installs /Applications/Sentinel.app, seeds demo stack prefs
```

Share zip only (agent-only defaults for other Macs):

```bash
make macos-desktop
# dist/macos/SentinelDesk-macOS-*.zip
```

## Share with other demo Macs

1. Send the zip + verify SHA-256.
2. Unzip → drag **one** `Sentinel.app` into Applications.
3. First launch: System Settings → Privacy & Security → Open Anyway if blocked.
4. Preferences → set Backend / Web URLs to your demo host (leave Local demo stack off unless they have the repo + Docker).
5. Enroll the Mac; keep Sentinel open during installs.
