import Foundation

/// Desktop-owned presentation state. Raw `status.json` can briefly say "degraded"
/// during warm-up; this controller maps that to Connecting… unless a hard failure
/// or grace expiry makes it a real Issue.
enum PresenceState: Equatable {
  case connecting
  case online
  case installing
  case issue
  case off
}

struct PresenceViewModel: Equatable {
  var state: PresenceState
  var headline: String
  var detail: String
  var shortTitle: String
  var animating: Bool
  var deviceId: String?
  var agentRunning: Bool
  var stackMessage: String

  static let connectingLaunch = PresenceViewModel(
    state: .connecting,
    headline: "Connecting…",
    detail: "Starting Sentinel…",
    shortTitle: "Connecting…",
    animating: true,
    deviceId: nil,
    agentRunning: false,
    stackMessage: "—"
  )
}

final class PresenceController {
  static let shared = PresenceController()

  /// How long after launch/restart we treat offline/degraded as Connecting.
  private let warmUpSeconds: TimeInterval = 18
  /// After warm-up, how long a soft failure must persist before Issue.
  private let issueGraceSeconds: TimeInterval = 4

  private var launchStartedAt: Date?
  private var softFailureSince: Date?
  private var hardFailureMessage: String?
  private var stackPending: Bool = false
  private var expectsAgent: Bool = true
  private var lastViewModel: PresenceViewModel = .connectingLaunch

  var viewModel: PresenceViewModel { lastViewModel }

  func beginLaunch(manageLocalStack: Bool, startAgent: Bool) {
    launchStartedAt = Date()
    softFailureSince = nil
    hardFailureMessage = nil
    stackPending = manageLocalStack
    expectsAgent = startAgent
    lastViewModel = PresenceViewModel(
      state: .connecting,
      headline: "Connecting…",
      detail: manageLocalStack ? "Starting local stack…" : "Connecting to control plane…",
      shortTitle: "Connecting…",
      animating: true,
      deviceId: nil,
      agentRunning: false,
      stackMessage: manageLocalStack ? "Starting…" : "Cloud / external control plane"
    )
  }

  func noteStackStarting() {
    stackPending = true
    hardFailureMessage = nil
  }

  func noteStackSucceeded(message: String) {
    stackPending = false
    // Keep warm-up clock; agent still needs heartbeats.
    if hardFailureMessage != nil { hardFailureMessage = nil }
    _ = message
  }

  func noteStackFailed(_ message: String) {
    stackPending = false
    hardFailureMessage = humanizeStackFailure(message)
  }

  func noteHardFailure(_ message: String) {
    hardFailureMessage = message.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
      ? "Something went wrong. See Preferences or Restart agent."
      : message
  }

  func noteAgentRestart() {
    launchStartedAt = Date()
    softFailureSince = nil
    hardFailureMessage = nil
  }

  func clearHardFailure() {
    hardFailureMessage = nil
  }

  @discardableResult
  func evaluate(
    status: AgentStatusSnapshot,
    agentRunning: Bool,
    stackMessage: String,
    now: Date = Date()
  ) -> PresenceViewModel {
    let inWarmUp: Bool = {
      guard let start = launchStartedAt else { return false }
      return now.timeIntervalSince(start) < warmUpSeconds
    }()

    // Hard stack / docker failures win immediately.
    if let hard = hardFailureMessage {
      softFailureSince = nil
      lastViewModel = PresenceViewModel(
        state: .issue,
        headline: "Issue",
        detail: hard,
        shortTitle: "Issue",
        animating: false,
        deviceId: status.deviceId,
        agentRunning: agentRunning,
        stackMessage: stackMessage
      )
      return lastViewModel
    }

    // Still bringing Docker / Vite up.
    if stackPending {
      softFailureSince = nil
      lastViewModel = PresenceViewModel(
        state: .connecting,
        headline: "Connecting…",
        detail: "Starting local stack…",
        shortTitle: "Connecting…",
        animating: true,
        deviceId: status.deviceId,
        agentRunning: agentRunning,
        stackMessage: stackMessage
      )
      return lastViewModel
    }

    // Installing is always honest — show it even during warm-up.
    if status.state == .installing {
      softFailureSince = nil
      lastViewModel = PresenceViewModel(
        state: .installing,
        headline: "Installing…",
        detail: status.detail.isEmpty ? "Installing software on this Mac" : status.detail,
        shortTitle: "Installing…",
        animating: false,
        deviceId: status.deviceId,
        agentRunning: agentRunning,
        stackMessage: stackMessage
      )
      return lastViewModel
    }

    // Healthy online clears everything.
    if status.state == .online {
      softFailureSince = nil
      launchStartedAt = nil // leave warm-up once healthy
      lastViewModel = PresenceViewModel(
        state: .online,
        headline: "Online",
        detail: humanizeOnlineDetail(status.detail),
        shortTitle: "Online",
        animating: false,
        deviceId: status.deviceId,
        agentRunning: agentRunning,
        stackMessage: stackMessage
      )
      return lastViewModel
    }

    // Soft / transient path.
    let soft = isSoftFailure(status: status, agentRunning: agentRunning)
    if soft {
      if softFailureSince == nil { softFailureSince = now }
      let softAge = now.timeIntervalSince(softFailureSince ?? now)
      // Warm-up or short grace → Connecting (never flash Issue). Past that → Issue.
      let stillConnecting = inWarmUp || softAge < issueGraceSeconds

      if stillConnecting {
        lastViewModel = PresenceViewModel(
          state: .connecting,
          headline: "Connecting…",
          detail: connectingDetail(status: status, agentRunning: agentRunning, stackMessage: stackMessage),
          shortTitle: "Connecting…",
          animating: true,
          deviceId: status.deviceId,
          agentRunning: agentRunning,
          stackMessage: stackMessage
        )
        return lastViewModel
      }
    } else {
      softFailureSince = nil
    }

    // Agent expected but process down after warm-up → Off or Issue.
    if expectsAgent && !agentRunning && !inWarmUp {
      lastViewModel = PresenceViewModel(
        state: .off,
        headline: "Offline",
        detail: "Agent process is not running. Use Restart agent.",
        shortTitle: "Off",
        animating: false,
        deviceId: status.deviceId,
        agentRunning: false,
        stackMessage: stackMessage
      )
      return lastViewModel
    }

    // Agent not started yet during warm-up.
    if expectsAgent && !agentRunning && inWarmUp {
      lastViewModel = PresenceViewModel(
        state: .connecting,
        headline: "Connecting…",
        detail: "Starting agent…",
        shortTitle: "Connecting…",
        animating: true,
        deviceId: status.deviceId,
        agentRunning: false,
        stackMessage: stackMessage
      )
      return lastViewModel
    }

    // Persistent soft failure past grace → Issue with clear cause.
    if soft {
      lastViewModel = PresenceViewModel(
        state: .issue,
        headline: "Issue",
        detail: humanizeIssueDetail(status),
        shortTitle: "Issue",
        animating: false,
        deviceId: status.deviceId,
        agentRunning: agentRunning,
        stackMessage: stackMessage
      )
      return lastViewModel
    }

    // Hard agent error / stopped.
    switch status.state {
    case .error, .stopped, .offline:
      if inWarmUp {
        lastViewModel = PresenceViewModel(
          state: .connecting,
          headline: "Connecting…",
          detail: connectingDetail(status: status, agentRunning: agentRunning, stackMessage: stackMessage),
          shortTitle: "Connecting…",
          animating: true,
          deviceId: status.deviceId,
          agentRunning: agentRunning,
          stackMessage: stackMessage
        )
      } else {
        lastViewModel = PresenceViewModel(
          state: status.state == .offline || status.state == .stopped ? .off : .issue,
          headline: status.state == .offline || status.state == .stopped ? "Offline" : "Issue",
          detail: humanizeIssueDetail(status),
          shortTitle: status.state == .offline || status.state == .stopped ? "Off" : "Issue",
          animating: false,
          deviceId: status.deviceId,
          agentRunning: agentRunning,
          stackMessage: stackMessage
        )
      }
    default:
      lastViewModel = PresenceViewModel(
        state: .connecting,
        headline: "Connecting…",
        detail: connectingDetail(status: status, agentRunning: agentRunning, stackMessage: stackMessage),
        shortTitle: "Connecting…",
        animating: true,
        deviceId: status.deviceId,
        agentRunning: agentRunning,
        stackMessage: stackMessage
      )
    }
    return lastViewModel
  }

  // MARK: - Copy

  private func isSoftFailure(status: AgentStatusSnapshot, agentRunning: Bool) -> Bool {
    if status.state == .degraded { return true }
    if status.state == .offline, agentRunning { return true }
    if isRetryDetail(status.detail) { return true }
    if status.detail.localizedCaseInsensitiveContains("stale") { return true }
    return false
  }

  private func isRetryDetail(_ detail: String) -> Bool {
    let lower = detail.lowercased()
    return lower.contains("retry")
      || lower.contains("rate_limited")
      || lower.contains("rate limited")
      || lower.contains("offline")
  }

  private func connectingDetail(
    status: AgentStatusSnapshot,
    agentRunning: Bool,
    stackMessage: String
  ) -> String {
    if stackPending { return "Starting local stack…" }
    if !agentRunning { return "Starting agent…" }
    if isRetryDetail(status.detail) {
      return "Connecting to control plane…"
    }
    if status.state == .degraded || status.state == .offline {
      return "Waiting for first heartbeat…"
    }
    if stackMessage.localizedCaseInsensitiveContains("stack") {
      return "Connecting to control plane…"
    }
    return "Connecting to control plane…"
  }

  private func humanizeOnlineDetail(_ detail: String) -> String {
    if detail.isEmpty { return "Ready · waiting for jobs" }
    if detail.localizedCaseInsensitiveContains("waiting for jobs") {
      return "Online · waiting for jobs"
    }
    return detail
  }

  private func humanizeIssueDetail(_ status: AgentStatusSnapshot) -> String {
    let d = status.detail
    if d.localizedCaseInsensitiveContains("stale") {
      return "Agent stopped updating — Restart agent"
    }
    if isRetryDetail(d) || status.state == .degraded {
      let trimmed = d.trimmingCharacters(in: .whitespacesAndNewlines)
      if trimmed.isEmpty {
        return "Can’t reach the control plane. Check Docker / backend, then Restart agent."
      }
      return "Can’t reach the control plane yet — \(trimmed)"
    }
    if status.state == .offline {
      return d.isEmpty ? "Agent is not running" : d
    }
    if d.isEmpty {
      return "Something went wrong. Open Preferences or Restart agent."
    }
    return d
  }

  private func humanizeStackFailure(_ message: String) -> String {
    let lower = message.lowercased()
    if lower.contains("docker") && (lower.contains("not found") || lower.contains("missing")) {
      return "Docker isn’t available. Start Docker Desktop, then reopen Sentinel."
    }
    if lower.contains("compose") || lower.contains("stack start failed") || lower.contains("exit") {
      return "Couldn’t start the local control plane — Docker Compose failed. See stack.log"
    }
    if lower.contains("repo") || lower.contains("compose.yaml") {
      return "Repo root must contain compose.yaml (Preferences → Local demo stack)."
    }
    if message.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
      return "Couldn’t start the local control plane. See stack.log"
    }
    return message
  }
}
