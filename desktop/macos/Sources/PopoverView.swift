import AppKit
import QuartzCore

final class PopoverContentView: NSView {
  var onOpenConsole: (() -> Void)?
  var onPreferences: (() -> Void)?
  var onRestartAgent: (() -> Void)?
  var onQuit: (() -> Void)?

  private let brand = NSTextField(labelWithString: "SentinelDesk")
  private let headline = NSTextField(labelWithString: "Connecting…")
  private let detail = NSTextField(labelWithString: "Starting Sentinel…")
  private let device = NSTextField(labelWithString: "Device —")
  private let agentLine = NSTextField(labelWithString: "Agent process: —")
  private let stackLine = NSTextField(labelWithString: "Control plane: —")
  private let statusDot = NSView(frame: .zero)
  private var lastState: PresenceState?

  override init(frame frameRect: NSRect) {
    super.init(frame: frameRect)
    wantsLayer = true
    layer?.backgroundColor = Theme.surface.cgColor
    build()
  }

  @available(*, unavailable)
  required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

  func apply(presence: PresenceViewModel) {
    let stateChanged = lastState != presence.state
    lastState = presence.state

    if stateChanged {
      NSAnimationContext.runAnimationGroup { ctx in
        ctx.duration = 0.18
        ctx.allowsImplicitAnimation = true
        headline.animator().alphaValue = 0.35
        detail.animator().alphaValue = 0.35
      } completionHandler: { [weak self] in
        guard let self else { return }
        self.headline.stringValue = presence.headline
        self.detail.stringValue = presence.detail
        NSAnimationContext.runAnimationGroup { ctx in
          ctx.duration = 0.18
          self.headline.animator().alphaValue = 1
          self.detail.animator().alphaValue = 1
        }
      }
    } else {
      headline.stringValue = presence.headline
      detail.stringValue = presence.detail
      headline.alphaValue = 1
      detail.alphaValue = 1
    }

    if let id = presence.deviceId, !id.isEmpty {
      let short = id.count > 12 ? String(id.prefix(8)) + "…" : id
      device.stringValue = "Device \(short)"
    } else {
      device.stringValue = "Device not linked yet"
    }
    agentLine.stringValue = presence.agentRunning ? "Agent process: running" : "Agent process: stopped"
    stackLine.stringValue = "Control plane: \(presence.stackMessage)"
    statusDot.layer?.backgroundColor = Theme.statusColor(presence.state).cgColor
    setDotPulsing(presence.animating)
  }

  /// Legacy bridge if anything still calls the old API.
  func apply(status: AgentStatusSnapshot, agentRunning: Bool, stackMessage: String) {
    let vm = PresenceController.shared.evaluate(
      status: status,
      agentRunning: agentRunning,
      stackMessage: stackMessage
    )
    apply(presence: vm)
  }

  private func setDotPulsing(_ animating: Bool) {
    statusDot.wantsLayer = true
    statusDot.layer?.removeAnimation(forKey: "sentinel.dotPulse")
    statusDot.layer?.opacity = 1
    guard animating else { return }
    let pulse = CABasicAnimation(keyPath: "opacity")
    pulse.fromValue = 1.0
    pulse.toValue = 0.28
    pulse.duration = 0.75
    pulse.autoreverses = true
    pulse.repeatCount = .infinity
    pulse.timingFunction = CAMediaTimingFunction(name: .easeInEaseOut)
    statusDot.layer?.add(pulse, forKey: "sentinel.dotPulse")
  }

  private func build() {
    let stack = NSStackView()
    stack.orientation = .vertical
    stack.alignment = .leading
    stack.spacing = 10
    stack.translatesAutoresizingMaskIntoConstraints = false
    addSubview(stack)

    brand.font = NSFont(name: "Georgia", size: 20) ?? .systemFont(ofSize: 20, weight: .bold)
    brand.textColor = Theme.navy

    let statusRow = NSStackView()
    statusRow.orientation = .horizontal
    statusRow.spacing = 8
    statusRow.alignment = .centerY
    statusDot.wantsLayer = true
    statusDot.layer?.cornerRadius = 5
    statusDot.translatesAutoresizingMaskIntoConstraints = false
    NSLayoutConstraint.activate([
      statusDot.widthAnchor.constraint(equalToConstant: 10),
      statusDot.heightAnchor.constraint(equalToConstant: 10),
    ])
    headline.font = .systemFont(ofSize: 15, weight: .semibold)
    headline.textColor = Theme.ink
    statusRow.addArrangedSubview(statusDot)
    statusRow.addArrangedSubview(headline)

    detail.font = .systemFont(ofSize: 12)
    detail.textColor = Theme.muted
    detail.maximumNumberOfLines = 4
    detail.lineBreakMode = .byWordWrapping
    detail.setContentCompressionResistancePriority(.defaultLow, for: .horizontal)

    device.font = .monospacedSystemFont(ofSize: 11, weight: .regular)
    device.textColor = Theme.muted
    agentLine.font = .systemFont(ofSize: 11)
    agentLine.textColor = Theme.muted
    stackLine.font = .systemFont(ofSize: 11)
    stackLine.textColor = Theme.muted
    stackLine.maximumNumberOfLines = 2
    stackLine.lineBreakMode = .byWordWrapping

    let divider = NSBox()
    divider.boxType = .separator

    let openBtn = makeButton("Open web console", accent: true) { [weak self] in self?.onOpenConsole?() }
    let prefsBtn = makeButton("Preferences…", accent: false) { [weak self] in self?.onPreferences?() }
    let restartBtn = makeButton("Restart agent", accent: false) { [weak self] in self?.onRestartAgent?() }
    let quitBtn = makeButton("Quit Sentinel", accent: false, destructive: true) { [weak self] in self?.onQuit?() }

    let hint = NSTextField(labelWithString: "SaaS: agent only. Demo mode can start/stop Docker on this Mac.")
    hint.font = .systemFont(ofSize: 11)
    hint.textColor = Theme.muted
    hint.maximumNumberOfLines = 2

    for v in [brand, statusRow, detail, device, agentLine, stackLine, divider, openBtn, prefsBtn, restartBtn, quitBtn, hint] {
      stack.addArrangedSubview(v)
      if let btn = v as? NSButton {
        btn.translatesAutoresizingMaskIntoConstraints = false
        btn.widthAnchor.constraint(equalTo: stack.widthAnchor).isActive = true
      }
    }

    NSLayoutConstraint.activate([
      stack.leadingAnchor.constraint(equalTo: leadingAnchor, constant: 16),
      stack.trailingAnchor.constraint(equalTo: trailingAnchor, constant: -16),
      stack.topAnchor.constraint(equalTo: topAnchor, constant: 16),
      stack.bottomAnchor.constraint(equalTo: bottomAnchor, constant: -16),
      widthAnchor.constraint(equalToConstant: 328),
    ])
  }

  private func makeButton(
    _ title: String,
    accent: Bool,
    destructive: Bool = false,
    action: @escaping () -> Void
  ) -> NSButton {
    let b = NSButton(title: title, target: nil, action: nil)
    b.bezelStyle = .rounded
    b.setButtonType(.momentaryPushIn)
    if accent {
      b.bezelColor = Theme.accent
    }
    if destructive {
      b.contentTintColor = Theme.bad
      b.toolTip = "Stop the agent and close Sentinel (⌘Q)"
    }
    let target = ClosureTarget.retain(action)
    b.target = target
    b.action = #selector(ClosureTarget.invoke)
    return b
  }
}
