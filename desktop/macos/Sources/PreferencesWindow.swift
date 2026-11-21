import AppKit

final class PreferencesWindowController: NSWindowController, NSWindowDelegate {
  private var backendField: NSTextField!
  private var webField: NSTextField!
  private var caField: NSTextField!
  private var packageField: NSTextField!
  private var repoField: NSTextField!
  private var startOnLaunch: NSButton!
  private var manageStack: NSButton!
  private var startWeb: NSButton!
  private var openConsole: NSButton!
  private var stopOnQuit: NSButton!
  private var messageLabel: NSTextField!
  var onSaved: ((DesktopConfig) -> Void)?

  convenience init() {
    let window = NSWindow(
      contentRect: NSRect(x: 0, y: 0, width: 540, height: 660),
      styleMask: [.titled, .closable],
      backing: .buffered,
      defer: false
    )
    window.title = "Sentinel Preferences"
    // Match Theme.surface: system dark appearance paints checkbox/button titles white.
    window.appearance = NSAppearance(named: .aqua)
    window.backgroundColor = Theme.surface
    window.center()
    window.isReleasedWhenClosed = false
    self.init(window: window)
    window.delegate = self
    window.contentView = buildContent()
    loadFields()
  }

  private func buildContent() -> NSView {
    let root = NSView(frame: NSRect(x: 0, y: 0, width: 540, height: 660))
    root.wantsLayer = true
    root.layer?.backgroundColor = Theme.surface.cgColor
    root.appearance = NSAppearance(named: .aqua)

    let stack = NSStackView()
    stack.orientation = .vertical
    stack.alignment = .leading
    stack.spacing = 12
    stack.translatesAutoresizingMaskIntoConstraints = false
    root.addSubview(stack)

    backendField = field()
    webField = field()
    caField = field()
    packageField = field()
    repoField = field()

    startOnLaunch = checkbox("Start local agent when Sentinel opens")
    manageStack = checkbox("Start Docker Compose when Sentinel opens")
    startWeb = checkbox("Also start web UI (npm run dev)")
    openConsole = checkbox("Open web console in browser on launch")
    stopOnQuit = checkbox("Stop Docker Compose when quitting Sentinel")

    stack.addArrangedSubview(label("Connection", size: 17, weight: .bold, color: Theme.ink))
    stack.addArrangedSubview(label(
      "Production SaaS: point these URLs at your hosted control plane. The desktop app only runs the Mac agent.",
      size: 12,
      weight: .regular,
      color: Theme.muted
    ))
    stack.addArrangedSubview(labeled("Backend URL (agent gateway)", backendField))
    stack.addArrangedSubview(labeled("Web console URL", webField))
    stack.addArrangedSubview(labeled("TLS CA certificate path (optional)", caField))
    stack.addArrangedSubview(labeled("Package store directory", packageField))
    stack.addArrangedSubview(startOnLaunch)

    stack.addArrangedSubview(hairline())

    stack.addArrangedSubview(label("Local demo stack (this Mac only)", size: 17, weight: .bold, color: Theme.ink))
    stack.addArrangedSubview(label(
      "For a single-machine demo: open Sentinel → containers + agent; Quit → stop agent and optionally Docker. Shared client builds should leave this off.",
      size: 12,
      weight: .regular,
      color: Theme.muted
    ))
    stack.addArrangedSubview(manageStack)
    stack.addArrangedSubview(labeled("Repo root (folder with compose.yaml)", repoField))
    stack.addArrangedSubview(startWeb)
    stack.addArrangedSubview(openConsole)
    stack.addArrangedSubview(stopOnQuit)

    messageLabel = label("", size: 12, weight: .semibold, color: Theme.ok)
    messageLabel.isHidden = true
    stack.addArrangedSubview(messageLabel)

    let actions = NSStackView()
    actions.orientation = .horizontal
    actions.spacing = 10
    actions.addArrangedSubview(button("Save", accent: true) { [weak self] in self?.save() })
    actions.addArrangedSubview(button("Close", accent: false) { [weak self] in self?.window?.close() })
    stack.addArrangedSubview(actions)

    NSLayoutConstraint.activate([
      stack.leadingAnchor.constraint(equalTo: root.leadingAnchor, constant: 28),
      stack.trailingAnchor.constraint(equalTo: root.trailingAnchor, constant: -28),
      stack.topAnchor.constraint(equalTo: root.topAnchor, constant: 24),
      stack.bottomAnchor.constraint(lessThanOrEqualTo: root.bottomAnchor, constant: -24),
      backendField.widthAnchor.constraint(equalTo: stack.widthAnchor),
      webField.widthAnchor.constraint(equalTo: stack.widthAnchor),
      caField.widthAnchor.constraint(equalTo: stack.widthAnchor),
      packageField.widthAnchor.constraint(equalTo: stack.widthAnchor),
      repoField.widthAnchor.constraint(equalTo: stack.widthAnchor),
      startOnLaunch.widthAnchor.constraint(equalTo: stack.widthAnchor),
      manageStack.widthAnchor.constraint(equalTo: stack.widthAnchor),
      startWeb.widthAnchor.constraint(equalTo: stack.widthAnchor),
      openConsole.widthAnchor.constraint(equalTo: stack.widthAnchor),
      stopOnQuit.widthAnchor.constraint(equalTo: stack.widthAnchor),
    ])
    return root
  }

  private func loadFields() {
    let c = ConfigStore.load()
    backendField.stringValue = c.backendURL
    webField.stringValue = c.webConsoleURL
    caField.stringValue = c.caCertPath
    packageField.stringValue = c.packageDir
    repoField.stringValue = c.repoRoot
    startOnLaunch.state = c.startAgentOnLaunch ? .on : .off
    manageStack.state = c.manageLocalStack ? .on : .off
    startWeb.state = c.startWebDevServer ? .on : .off
    openConsole.state = c.openConsoleOnLaunch ? .on : .off
    stopOnQuit.state = c.stopStackOnQuit ? .on : .off
  }

  private func save() {
    var c = ConfigStore.load()
    let backend = backendField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
    let web = webField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
    guard let backendURL = URL(string: backend), backendURL.scheme == "https" || backendURL.scheme == "http" else {
      showMessage("Backend URL must be http(s).", ok: false)
      return
    }
    guard let webURL = URL(string: web), webURL.scheme == "http" || webURL.scheme == "https" else {
      showMessage("Web console URL must be http(s).", ok: false)
      return
    }
    _ = backendURL
    _ = webURL
    c.backendURL = backend
    c.webConsoleURL = web
    c.caCertPath = caField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
    c.packageDir = packageField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
    c.repoRoot = repoField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)
    c.startAgentOnLaunch = startOnLaunch.state == .on
    c.manageLocalStack = manageStack.state == .on
    c.startWebDevServer = startWeb.state == .on
    c.openConsoleOnLaunch = openConsole.state == .on
    c.stopStackOnQuit = stopOnQuit.state == .on
    if c.manageLocalStack {
      let compose = (c.repoRoot as NSString).appendingPathComponent("compose.yaml")
      if !FileManager.default.isReadableFile(atPath: compose) {
        showMessage("Repo root must contain compose.yaml.", ok: false)
        return
      }
    }
    do {
      try ConfigStore.save(c)
      showMessage("Saved.", ok: true)
      onSaved?(c)
    } catch {
      showMessage("Could not save preferences.", ok: false)
    }
  }

  private func showMessage(_ text: String, ok: Bool) {
    messageLabel.stringValue = text
    messageLabel.textColor = ok ? Theme.ok : Theme.bad
    messageLabel.isHidden = false
  }

  private func label(_ text: String, size: CGFloat, weight: NSFont.Weight, color: NSColor) -> NSTextField {
    let t = NSTextField(labelWithString: text)
    t.font = .systemFont(ofSize: size, weight: weight)
    t.textColor = color
    t.lineBreakMode = .byWordWrapping
    t.maximumNumberOfLines = 4
    t.drawsBackground = false
    t.isBezeled = false
    return t
  }

  private func field() -> NSTextField {
    let f = NSTextField(string: "")
    f.font = .systemFont(ofSize: 13, weight: .regular)
    f.isEditable = true
    f.isBezeled = true
    f.bezelStyle = .roundedBezel
    f.textColor = Theme.ink
    f.backgroundColor = NSColor.white
    f.drawsBackground = true
    f.focusRingType = .default
    return f
  }

  private func labeled(_ title: String, _ field: NSTextField) -> NSView {
    let stack = NSStackView()
    stack.orientation = .vertical
    stack.alignment = .leading
    stack.spacing = 5
    stack.addArrangedSubview(label(title, size: 11, weight: .semibold, color: Theme.muted))
    stack.addArrangedSubview(field)
    return stack
  }

  private func checkbox(_ title: String) -> NSButton {
    let b = NSButton(checkboxWithTitle: title, target: nil, action: nil)
    b.font = .systemFont(ofSize: 13, weight: .regular)
    b.contentTintColor = Theme.accent
    b.attributedTitle = NSAttributedString(
      string: title,
      attributes: [
        .foregroundColor: Theme.ink,
        .font: NSFont.systemFont(ofSize: 13, weight: .regular),
      ]
    )
    return b
  }

  private func hairline() -> NSView {
    let box = NSBox()
    box.boxType = .separator
    box.translatesAutoresizingMaskIntoConstraints = false
    box.heightAnchor.constraint(equalToConstant: 1).isActive = true
    return box
  }

  private func button(_ title: String, accent: Bool, action: @escaping () -> Void) -> NSButton {
    let b = NSButton(title: title, target: nil, action: nil)
    b.bezelStyle = .rounded
    b.setButtonType(.momentaryPushIn)
    b.font = .systemFont(ofSize: 13, weight: .semibold)
    if accent {
      b.bezelColor = Theme.accent
      b.contentTintColor = .white
      b.attributedTitle = NSAttributedString(
        string: title,
        attributes: [
          .foregroundColor: NSColor.white,
          .font: NSFont.systemFont(ofSize: 13, weight: .semibold),
        ]
      )
    } else {
      b.contentTintColor = Theme.ink
      b.attributedTitle = NSAttributedString(
        string: title,
        attributes: [
          .foregroundColor: Theme.ink,
          .font: NSFont.systemFont(ofSize: 13, weight: .semibold),
        ]
      )
    }
    b.target = ClosureTarget.retain(action)
    b.action = #selector(ClosureTarget.invoke)
    return b
  }
}

final class ClosureTarget: NSObject {
  private let block: () -> Void
  private static var retained: [ClosureTarget] = []

  init(_ block: @escaping () -> Void) {
    self.block = block
  }

  static func retain(_ block: @escaping () -> Void) -> ClosureTarget {
    let t = ClosureTarget(block)
    retained.append(t)
    return t
  }

  @objc func invoke() { block() }
}
