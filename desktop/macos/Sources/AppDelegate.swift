import AppKit

final class AppDelegate: NSObject, NSApplicationDelegate {
  private var statusItem: NSStatusItem!
  private var statusMenu: NSMenu!
  private var popover: NSPopover!
  private var content: PopoverContentView!
  private var prefs: PreferencesWindowController?
  private var timer: Timer?
  private var config = ConfigStore.load()
  private var eventMonitor: Any?

  func applicationDidFinishLaunching(_ notification: Notification) {
    SingleInstance.claimOrExit()
    NSApp.setActivationPolicy(.accessory)
    try? ConfigStore.ensureSupportDir()
    bootstrapStatusItem()
    bootstrapPopover()
    refreshUI()

    // Production SaaS: manageLocalStack=false → agent only (cloud backend stays up).
    // Local demo: manageLocalStack=true → Docker (+ optional Vite), then agent; Quit can stop stack.
    if config.manageLocalStack {
      DemoStackSupervisor.shared.startIfEnabled(config: config) { [weak self] _, _ in
        guard let self else { return }
        if self.config.startAgentOnLaunch {
          try? AgentSupervisor.shared.start(config: self.config)
        }
        self.refreshUI()
      }
    } else {
      if config.startAgentOnLaunch {
        try? AgentSupervisor.shared.start(config: config)
      }
      if config.openConsoleOnLaunch, let url = URL(string: config.webConsoleURL) {
        NSWorkspace.shared.open(url)
      }
    }

    timer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
      self?.refreshUI()
    }
    RunLoop.main.add(timer!, forMode: .common)

    eventMonitor = NSEvent.addGlobalMonitorForEvents(matching: [.leftMouseDown, .rightMouseDown]) {
      [weak self] event in
      guard let self else { return }
      if let button = self.statusItem.button, let win = button.window, event.windowNumber == win.windowNumber {
        return
      }
      if self.popover.isShown {
        self.popover.performClose(nil)
      }
    }
  }

  func applicationWillTerminate(_ notification: Notification) {
    AgentSupervisor.shared.stop()
    DemoStackSupervisor.shared.stopIfEnabled(config: config)
    if let eventMonitor {
      NSEvent.removeMonitor(eventMonitor)
    }
  }

  private func bootstrapStatusItem() {
    statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
    statusMenu = NSMenu()
    statusMenu.addItem(NSMenuItem(title: "Open status", action: #selector(showPopoverFromMenu), keyEquivalent: ""))
    statusMenu.addItem(NSMenuItem(title: "Open web console", action: #selector(openConsoleMenu), keyEquivalent: "o"))
    statusMenu.addItem(NSMenuItem(title: "Preferences…", action: #selector(openPreferencesMenu), keyEquivalent: ","))
    statusMenu.addItem(NSMenuItem.separator())
    statusMenu.addItem(NSMenuItem(title: "Restart agent", action: #selector(restartAgentMenu), keyEquivalent: "r"))
    statusMenu.addItem(NSMenuItem.separator())
    let quit = NSMenuItem(title: "Quit Sentinel", action: #selector(quitApp), keyEquivalent: "q")
    statusMenu.addItem(quit)

    if let button = statusItem.button {
      button.image = Self.menuBarIcon()
      button.imagePosition = .imageLeading
      button.title = " Offline"
      button.toolTip = "SentinelDesk — click for status, right‑click to quit"
      button.target = self
      button.action = #selector(statusItemClicked(_:))
      button.sendAction(on: [.leftMouseUp, .rightMouseUp])
    }
  }

  private func bootstrapPopover() {
    content = PopoverContentView(frame: .zero)
    content.onOpenConsole = { [weak self] in self?.openConsole() }
    content.onPreferences = { [weak self] in self?.openPreferences() }
    content.onRestartAgent = { [weak self] in self?.restartAgent() }
    content.onQuit = { [weak self] in self?.quitApp() }

    popover = NSPopover()
    popover.contentSize = NSSize(width: 320, height: 410)
    popover.behavior = .transient
    popover.animates = true
    let hosting = NSViewController()
    hosting.view = content
    popover.contentViewController = hosting
  }

  @objc private func statusItemClicked(_ sender: Any?) {
    guard let event = NSApp.currentEvent else {
      showPopover()
      return
    }
    if event.type == .rightMouseUp || event.modifierFlags.contains(.control) {
      statusItem.menu = statusMenu
      statusItem.button?.performClick(nil)
      // Detach menu so left-click keeps opening the popover.
      DispatchQueue.main.async { [weak self] in
        self?.statusItem.menu = nil
      }
      return
    }
    showPopover()
  }

  @objc private func showPopoverFromMenu() { showPopover() }
  @objc private func openConsoleMenu() { openConsole() }
  @objc private func openPreferencesMenu() { openPreferences() }
  @objc private func restartAgentMenu() { restartAgent() }

  @objc private func quitApp() {
    popover.performClose(nil)
    NSApp.terminate(nil)
  }

  private func showPopover() {
    guard let button = statusItem.button else { return }
    if popover.isShown {
      popover.performClose(nil)
      return
    }
    refreshUI()
    popover.show(relativeTo: button.bounds, of: button, preferredEdge: .minY)
    NSApp.activate(ignoringOtherApps: true)
  }

  private func refreshUI() {
    let status = StatusReader.read()
    let running = AgentSupervisor.shared.isRunning
    statusItem.button?.image = Self.menuBarIcon()
    statusItem.button?.title = " " + Self.shortTitle(for: status)
    statusItem.button?.toolTip = status.detail + " — right‑click for Quit"
    content.apply(
      status: status,
      agentRunning: running,
      stackMessage: DemoStackSupervisor.shared.lastMessage
    )
  }

  private static func shortTitle(for status: AgentStatusSnapshot) -> String {
    switch status.state {
    case .installing: return "Installing…"
    case .degraded: return "Issue"
    case .error, .stopped, .offline: return "Off"
    case .online: return "Online"
    }
  }

  private static func menuBarIcon() -> NSImage {
    let config = NSImage.SymbolConfiguration(pointSize: 13, weight: .semibold)
    if let image = NSImage(systemSymbolName: "shield.lefthalf.filled", accessibilityDescription: "Sentinel")?
      .withSymbolConfiguration(config)
    {
      image.isTemplate = true
      return image
    }
    let fallback = NSImage(size: NSSize(width: 16, height: 16))
    fallback.isTemplate = true
    return fallback
  }

  private func openConsole() {
    guard let url = URL(string: config.webConsoleURL) else { return }
    NSWorkspace.shared.open(url)
    popover.performClose(nil)
  }

  private func openPreferences() {
    if prefs == nil {
      prefs = PreferencesWindowController()
      prefs?.onSaved = { [weak self] newConfig in
        self?.config = newConfig
        if newConfig.startAgentOnLaunch {
          try? AgentSupervisor.shared.restart(config: newConfig)
        }
        self?.refreshUI()
      }
    }
    prefs?.showWindow(nil)
    NSApp.activate(ignoringOtherApps: true)
    prefs?.window?.makeKeyAndOrderFront(nil)
    popover.performClose(nil)
  }

  private func restartAgent() {
    do {
      try AgentSupervisor.shared.restart(config: config)
      refreshUI()
    } catch {
      let alert = NSAlert()
      alert.messageText = "Could not start agent"
      alert.informativeText = error.localizedDescription
      alert.alertStyle = .warning
      alert.runModal()
    }
  }
}
