import Foundation

/// Runs the embedded `sentinel-agent` as a supervised child process (no shell).
final class AgentSupervisor {
  static let shared = AgentSupervisor()

  private var process: Process?
  private let queue = DispatchQueue(label: "com.sentineldesk.desktop.agent")

  var isRunning: Bool {
    queue.sync { process?.isRunning == true }
  }

  func start(config: DesktopConfig) throws {
    try queue.sync {
      if process?.isRunning == true { return }
      try ConfigStore.ensureSupportDir()
      try Self.materializeBundledAssets()

      guard let agentURL = Self.embeddedAgentURL() else {
        throw SupervisorError.agentMissing
      }

      let proc = Process()
      proc.executableURL = agentURL
      proc.arguments = ["run"]
      proc.currentDirectoryURL = ConfigStore.supportDir

      var env = ProcessInfo.processInfo.environment
      env["SENTINEL_BACKEND_URL"] = config.backendURL
      env["SENTINEL_AGENT_CONFIG_DIR"] = ConfigStore.supportDir.path
      env["SENTINEL_PACKAGE_DIR"] = config.packageDir
      env["SENTINEL_PRIVILEGED_SOCKET"] = config.privilegedSocket
      if let ca = ConfigStore.resolvedCaCert(config: config) {
        env["SENTINEL_CA_CERT"] = ca
      }
      proc.environment = env

      let out = try Self.appendHandle(ConfigStore.agentLogOut)
      let err = try Self.appendHandle(ConfigStore.agentLogErr)
      proc.standardOutput = out
      proc.standardError = err

      proc.terminationHandler = { [weak self] _ in
        self?.queue.async {
          self?.process = nil
        }
      }

      try proc.run()
      process = proc
    }
  }

  func stop() {
    queue.sync {
      guard let proc = process, proc.isRunning else {
        process = nil
        return
      }
      proc.terminate()
      // Give it a moment; avoid force-kill unless needed.
      DispatchQueue.global().asyncAfter(deadline: .now() + 2) {
        if proc.isRunning {
          proc.interrupt()
        }
      }
      process = nil
    }
  }

  func restart(config: DesktopConfig) throws {
    stop()
    // Brief pause so the previous process can release resources.
    Thread.sleep(forTimeInterval: 0.4)
    try start(config: config)
  }

  private static func embeddedAgentURL() -> URL? {
    if let exec = Bundle.main.executableURL {
      let sibling = exec.deletingLastPathComponent().appendingPathComponent("sentinel-agent")
      if FileManager.default.isExecutableFile(atPath: sibling.path) {
        return sibling
      }
    }
    return Bundle.main.url(forResource: "sentinel-agent", withExtension: nil)
  }

  private static func appendHandle(_ url: URL) throws -> FileHandle {
    try ConfigStore.ensureSupportDir()
    if !FileManager.default.fileExists(atPath: url.path) {
      FileManager.default.createFile(atPath: url.path, contents: nil)
    }
    let handle = try FileHandle(forWritingTo: url)
    _ = try handle.seekToEnd()
    return handle
  }

  private static func materializeBundledAssets() throws {
    try ConfigStore.ensureSupportDir()
    if let pub = Bundle.main.url(forResource: "job_signing_public", withExtension: "pem"),
       !FileManager.default.fileExists(atPath: ConfigStore.jobPublicKeyURL.path)
    {
      try FileManager.default.copyItem(at: pub, to: ConfigStore.jobPublicKeyURL)
      try FileManager.default.setAttributes(
        [.posixPermissions: 0o644],
        ofItemAtPath: ConfigStore.jobPublicKeyURL.path
      )
    }
    // Ensure shared package store exists (agent cache).
    let pkg = "/Users/Shared/SentinelDesk/packages"
    try? FileManager.default.createDirectory(
      atPath: pkg,
      withIntermediateDirectories: true
    )
  }
}

enum SupervisorError: LocalizedError {
  case agentMissing

  var errorDescription: String? {
    switch self {
    case .agentMissing:
      return "Embedded sentinel-agent binary is missing from the app bundle."
    }
  }
}
