import AppKit

enum Theme {
  static let navy = NSColor(calibratedRed: 0.09, green: 0.12, blue: 0.16, alpha: 1)
  static let ink = NSColor(calibratedRed: 0.12, green: 0.14, blue: 0.18, alpha: 1)
  static let muted = NSColor(calibratedRed: 0.42, green: 0.46, blue: 0.52, alpha: 1)
  static let accent = NSColor(calibratedRed: 0.12, green: 0.31, blue: 0.27, alpha: 1)
  static let accentSoft = NSColor(calibratedRed: 0.12, green: 0.31, blue: 0.27, alpha: 0.14)
  static let surface = NSColor(calibratedRed: 0.98, green: 0.98, blue: 0.97, alpha: 1)
  static let ok = NSColor(calibratedRed: 0.15, green: 0.48, blue: 0.36, alpha: 1)
  static let warn = NSColor(calibratedRed: 0.72, green: 0.52, blue: 0.18, alpha: 1)
  static let connecting = NSColor(calibratedRed: 0.78, green: 0.55, blue: 0.16, alpha: 1)
  static let bad = NSColor(calibratedRed: 0.72, green: 0.22, blue: 0.22, alpha: 1)
  static let line = NSColor(calibratedRed: 0.86, green: 0.88, blue: 0.90, alpha: 1)

  static func statusColor(_ state: PresenceState) -> NSColor {
    switch state {
    case .online: return ok
    case .installing: return accent
    case .connecting: return connecting
    case .issue: return bad
    case .off: return muted
    }
  }

  /// Legacy mapping for raw agent snapshots (tests / internals).
  static func statusColor(_ state: AgentStatusSnapshot.State) -> NSColor {
    switch state {
    case .online: return ok
    case .installing: return accent
    case .degraded, .error: return warn
    case .stopped, .offline: return bad
    }
  }
}
