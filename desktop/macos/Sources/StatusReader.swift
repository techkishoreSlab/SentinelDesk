import Foundation

struct AgentStatusSnapshot: Equatable {
  enum State: String {
    case online
    case installing
    case degraded
    case error
    case stopped
    case offline
  }

  var state: State
  var detail: String
  var deviceId: String?
  var updatedAtUnix: UInt64?

  static let offline = AgentStatusSnapshot(
    state: .offline,
    detail: "Agent is not running",
    deviceId: nil,
    updatedAtUnix: nil
  )

  /// Raw labels for debugging. Presentation UX uses `PresenceController`.
  var menuTitle: String {
    switch state {
    case .installing: return "Installing…"
    case .degraded: return "Degraded"
    case .error, .stopped, .offline: return "Off"
    case .online: return "Online"
    }
  }

  var headline: String {
    switch state {
    case .installing: return "Installing software"
    case .degraded: return "Degraded"
    case .error, .stopped, .offline: return "Offline"
    case .online: return "Online"
    }
  }
}

enum StatusReader {
  static func read(from url: URL = ConfigStore.statusURL) -> AgentStatusSnapshot {
    guard let data = try? Data(contentsOf: url),
          let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
    else {
      return .offline
    }
    let raw = (json["state"] as? String)?.lowercased() ?? "online"
    let state = AgentStatusSnapshot.State(rawValue: raw) ?? .online
    let detail = (json["detail"] as? String) ?? state.rawValue
    let deviceId = json["device_id"] as? String
    let updated = json["updated_at_unix"] as? UInt64
    // Stale file (>3 minutes) → treat as offline for honesty.
    if let updated, updated > 0 {
      let now = UInt64(Date().timeIntervalSince1970)
      if now > updated + 180 {
        return AgentStatusSnapshot(
          state: .offline,
          detail: "Last heartbeat is stale — restart the agent",
          deviceId: deviceId,
          updatedAtUnix: updated
        )
      }
    }
    return AgentStatusSnapshot(state: state, detail: detail, deviceId: deviceId, updatedAtUnix: updated)
  }
}
