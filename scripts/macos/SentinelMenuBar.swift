import AppKit
import Foundation

/// Lightweight menu-bar status for the SentinelDesk user agent (demo / production Mac).
final class AppDelegate: NSObject, NSApplicationDelegate {
  private var item: NSStatusItem!
  private var timer: Timer?
  private let statusURL: URL

  override init() {
    let home = FileManager.default.homeDirectoryForCurrentUser
    statusURL = home
      .appendingPathComponent("Library/Application Support/com.SentinelDesk.Agent/status.json")
    super.init()
  }

  func applicationDidFinishLaunching(_ notification: Notification) {
    item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    if let button = item.button {
      button.title = "Sentinel"
      button.toolTip = "SentinelDesk agent"
    }
    let menu = NSMenu()
    menu.addItem(NSMenuItem(title: "Refresh", action: #selector(refresh), keyEquivalent: "r"))
    menu.addItem(NSMenuItem.separator())
    menu.addItem(NSMenuItem(title: "Quit", action: #selector(quit), keyEquivalent: "q"))
    item.menu = menu
    refresh()
    timer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
      self?.refresh()
    }
  }

  @objc private func refresh() {
    guard let data = try? Data(contentsOf: statusURL),
          let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    else {
      item.button?.title = "Sentinel · Off"
      return
    }
    let detail = (json["detail"] as? String) ?? "Online"
    let state = (json["state"] as? String) ?? "online"
    switch state {
    case "installing":
      item.button?.title = "Sentinel · Installing…"
    case "degraded":
      item.button?.title = "Sentinel · Issue"
    case "error", "stopped":
      item.button?.title = "Sentinel · Off"
    default:
      item.button?.title = "Sentinel · Online"
    }
    item.button?.toolTip = detail
  }

  @objc private func quit() {
    NSApp.terminate(nil)
  }
}

let app = NSApplication.shared
let delegate = AppDelegate()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
