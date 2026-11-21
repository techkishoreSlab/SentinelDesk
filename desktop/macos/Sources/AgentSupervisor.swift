import Foundation

/// Runs the embedded `sentinel-agent` as a supervised child process (no shell).
final class AgentSupervisor {
  static let shared = AgentSupervisor()

  private var process: Process?
  private let lock = NSLock()

  var isRunning: Bool {
    lock.lock()
    defer { lock.unlock() }
    return process?.isRunning == true
  }

  func start(config: DesktopConfig) throws {
    try ConfigStore.ensureSupportDir()
    try Self.materializeBundledAssets()

    guard let agentURL = Self.embeddedAgentURL() else {
      throw SupervisorError.agentMissing
    }

    // Reap outside the lock: sleep + process enumeration must not block isRunning.
    Self.reapOrphanAgents(matching: agentURL)

    lock.lock()
    defer { lock.unlock() }
    if process?.isRunning == true { return }

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
      guard let self else { return }
      self.lock.lock()
      if self.process === proc {
        self.process = nil
      }
      self.lock.unlock()
    }

    try proc.run()
    process = proc
  }

  func stop() {
    let proc: Process?
    lock.lock()
    proc = process
    process = nil
    lock.unlock()

    guard let proc, proc.isRunning else { return }
    proc.terminate()
    DispatchQueue.global().asyncAfter(deadline: .now() + 2) {
      if proc.isRunning {
        proc.interrupt()
      }
    }
  }

  func restart(config: DesktopConfig) throws {
    stop()
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

  /// Terminate other live processes whose argv0 equals our bundled agent path.
  private static func reapOrphanAgents(matching agentURL: URL) {
    let target = agentURL.resolvingSymlinksInPath().path
    let orphans = pids(withArgv0: target)
    guard !orphans.isEmpty else { return }
    for pid in orphans {
      kill(pid_t(pid), SIGTERM)
    }
    Thread.sleep(forTimeInterval: 0.35)
    for pid in pids(withArgv0: target) {
      kill(pid_t(pid), SIGKILL)
    }
  }

  private static func pids(withArgv0 target: String) -> [Int32] {
    let selfPid = ProcessInfo.processInfo.processIdentifier
    guard let raw = runCapture("/bin/ps", arguments: ["-axo", "pid=,args="]) else {
      return []
    }
    var matches: [Int32] = []
    for line in raw.split(whereSeparator: \.isNewline) {
      let trimmed = line.trimmingCharacters(in: .whitespaces)
      guard let space = trimmed.firstIndex(of: " ") else { continue }
      let pidText = String(trimmed[..<space]).trimmingCharacters(in: .whitespaces)
      guard let pid = Int32(pidText), pid > 0, pid != selfPid else { continue }
      let args = String(trimmed[trimmed.index(after: space)...]).trimmingCharacters(in: .whitespaces)
      if args == target || args.hasPrefix(target + " ") {
        matches.append(pid)
      }
    }
    return matches
  }

  private static func runCapture(_ launchPath: String, arguments: [String]) -> String? {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: launchPath)
    task.arguments = arguments
    let pipe = Pipe()
    task.standardOutput = pipe
    task.standardError = FileHandle.nullDevice
    do {
      try task.run()
    } catch {
      return nil
    }
    // Read before waitUntilExit — a full pipe (~64KB) otherwise deadlocks `ps`.
    let data = pipe.fileHandleForReading.readDataToEndOfFile()
    task.waitUntilExit()
    return String(data: data, encoding: .utf8)
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
