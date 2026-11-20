import AppKit
import Foundation

/// Optional local demo/dev control plane lifecycle (Docker Compose + Vite).
/// Production SaaS: leave `manageLocalStack` off — cloud backend stays up; this app only runs the agent.
final class DemoStackSupervisor {
  static let shared = DemoStackSupervisor()

  private let queue = DispatchQueue(label: "com.sentineldesk.desktop.stack")
  private var webProcess: Process?
  private(set) var lastMessage: String = "Stack idle"
  private(set) var isComposeUp: Bool = false

  private static let dockerBinDirs = [
    "/usr/local/bin",
    "/opt/homebrew/bin",
    "/Applications/Docker.app/Contents/Resources/bin",
  ]

  func startIfEnabled(config: DesktopConfig, completion: ((Bool, String) -> Void)? = nil) {
    guard config.manageLocalStack else {
      lastMessage = "Cloud / external control plane"
      completion?(true, lastMessage)
      return
    }
    queue.async {
      do {
        let root = try self.validatedRepoRoot(config.repoRoot)
        try FileManager.default.createDirectory(
          atPath: config.packageDir,
          withIntermediateDirectories: true
        )
        self.appendLog("Starting Docker Compose in \(root.path)")
        // Reopen path: no --build (avoids credential-helper / bake issues). Rebuild only if up fails.
        do {
          try self.runDockerCompose(
            root: root,
            args: ["up", "-d", "--wait", "backend", "agent-gateway"]
          )
        } catch {
          self.appendLog("compose up failed; retrying with --build")
          try self.runDockerCompose(
            root: root,
            args: ["up", "-d", "--build", "--wait", "backend", "agent-gateway"]
          )
        }
        self.isComposeUp = true
        self.lastMessage = "Local stack running"

        if config.startWebDevServer {
          self.ensureWebDev(repoRoot: root)
          self.lastMessage = "Local stack + web ready"
        }

        if config.openConsoleOnLaunch, let url = URL(string: config.webConsoleURL) {
          DispatchQueue.main.async {
            NSWorkspace.shared.open(url)
          }
        }
        DispatchQueue.main.async { completion?(true, self.lastMessage) }
      } catch {
        self.lastMessage = error.localizedDescription
        self.appendLog("Stack start failed: \(error.localizedDescription)")
        DispatchQueue.main.async { completion?(false, self.lastMessage) }
      }
    }
  }

  func stopIfEnabled(config: DesktopConfig) {
    guard config.manageLocalStack, config.stopStackOnQuit else { return }
    queue.sync {
      self.stopVite()
      guard let root = try? self.validatedRepoRoot(config.repoRoot) else { return }
      self.appendLog("Stopping Docker Compose")
      try? self.runDockerCompose(root: root, args: ["down"])
      self.isComposeUp = false
      self.lastMessage = "Local stack stopped"
    }
  }

  private func validatedRepoRoot(_ raw: String) throws -> URL {
    let path = (raw as NSString).expandingTildeInPath
    let url = URL(fileURLWithPath: path, isDirectory: true)
    let compose = url.appendingPathComponent("compose.yaml")
    guard FileManager.default.isReadableFile(atPath: compose.path) else {
      throw StackError.repoMissing
    }
    return url
  }

  private func dockerEnvironment() -> [String: String] {
    var env = ProcessInfo.processInfo.environment
    let extras = Self.dockerBinDirs.joined(separator: ":")
    let path = env["PATH"] ?? "/usr/bin:/bin:/usr/sbin:/sbin"
    env["PATH"] = extras + ":" + path
    // App-local Docker config omits credsStore so LaunchServices launches don't fail
    // on missing docker-credential-desktop. Symlink compose into that config's
    // cli-plugins — Docker ignores DOCKER_CLI_PLUGIN_EXTRA_DIRS when DOCKER_CONFIG
    // is overridden.
    let cfgDir = ConfigStore.supportDir.appendingPathComponent("docker-cli", isDirectory: true)
    let pluginsDir = cfgDir.appendingPathComponent("cli-plugins", isDirectory: true)
    try? FileManager.default.createDirectory(at: pluginsDir, withIntermediateDirectories: true)
    let cfgFile = cfgDir.appendingPathComponent("config.json")
    if !FileManager.default.fileExists(atPath: cfgFile.path) {
      let minimal = Data("{\"auths\":{}}\n".utf8)
      try? minimal.write(to: cfgFile, options: .atomic)
    }
    Self.ensureComposePluginLink(in: pluginsDir)
    env["DOCKER_CONFIG"] = cfgDir.path
    return env
  }

  private static func ensureComposePluginLink(in pluginsDir: URL) {
    let link = pluginsDir.appendingPathComponent("docker-compose")
    let candidates = [
      (NSHomeDirectory() as NSString).appendingPathComponent(".docker/cli-plugins/docker-compose"),
      "/Applications/Docker.app/Contents/Resources/cli-plugins/docker-compose",
      "/usr/local/lib/docker/cli-plugins/docker-compose",
      "/opt/homebrew/lib/docker/cli-plugins/docker-compose",
    ]
    guard let target = candidates.first(where: { FileManager.default.isExecutableFile(atPath: $0) })
    else { return }
    let fm = FileManager.default
    if fm.fileExists(atPath: link.path) {
      // Refresh if broken or pointing elsewhere.
      if let dest = try? fm.destinationOfSymbolicLink(atPath: link.path), dest == target {
        return
      }
      try? fm.removeItem(at: link)
    }
    try? fm.createSymbolicLink(atPath: link.path, withDestinationPath: target)
  }

  private func runDockerCompose(root: URL, args: [String]) throws {
    guard let docker = Self.findBinary(named: "docker", extras: Self.dockerBinDirs.map { "\($0)/docker" })
    else {
      throw StackError.dockerMissing
    }
    let proc = Process()
    proc.executableURL = docker
    proc.arguments = ["compose", "--project-directory", root.path] + args
    proc.currentDirectoryURL = root
    proc.environment = dockerEnvironment()
    let log = try Self.appendHandle(ConfigStore.stackLogURL)
    proc.standardOutput = log
    proc.standardError = log
    try proc.run()
    proc.waitUntilExit()
    if proc.terminationStatus != 0 {
      throw StackError.composeFailed(proc.terminationStatus)
    }
  }

  /// Start Vite only if nothing is already serving :5173. Never fail the stack for web.
  private func ensureWebDev(repoRoot: URL) {
    if isPortOpen(5173) {
      appendLog("Web already listening on :5173 — skipping npm run dev")
      return
    }
    do {
      try startVite(repoRoot: repoRoot)
      // Give Vite a moment; if it dies because port raced, still OK if port opens.
      Thread.sleep(forTimeInterval: 1.2)
      if webProcess?.isRunning != true, !isPortOpen(5173) {
        appendLog("Vite did not stay up; open console manually if needed")
      }
    } catch {
      appendLog("Web start skipped: \(error.localizedDescription)")
    }
  }

  private func isPortOpen(_ port: Int) -> Bool {
    var hints = addrinfo(
      ai_flags: AI_NUMERICHOST,
      ai_family: AF_INET,
      ai_socktype: SOCK_STREAM,
      ai_protocol: 0,
      ai_addrlen: 0,
      ai_canonname: nil,
      ai_addr: nil,
      ai_next: nil
    )
    var info: UnsafeMutablePointer<addrinfo>?
    let host = "127.0.0.1"
    let portStr = String(port)
    guard getaddrinfo(host, portStr, &hints, &info) == 0, let info else { return false }
    defer { freeaddrinfo(info) }
    let fd = socket(info.pointee.ai_family, info.pointee.ai_socktype, info.pointee.ai_protocol)
    guard fd >= 0 else { return false }
    defer { close(fd) }
    let result = connect(fd, info.pointee.ai_addr, info.pointee.ai_addrlen)
    return result == 0
  }

  private func startVite(repoRoot: URL) throws {
    if webProcess?.isRunning == true { return }
    let webDir = repoRoot.appendingPathComponent("web")
    guard FileManager.default.fileExists(atPath: webDir.appendingPathComponent("package.json").path) else {
      throw StackError.webMissing
    }
    guard let npm = Self.findBinary(named: "npm", extras: [
      "/usr/local/bin/npm",
      "/opt/homebrew/bin/npm",
      (NSHomeDirectory() as NSString).appendingPathComponent(".nvm/versions/node/v24.13.0/bin/npm"),
    ]) else {
      throw StackError.npmMissing
    }
    let proc = Process()
    proc.executableURL = npm
    proc.arguments = ["run", "dev", "--", "--host", "127.0.0.1", "--port", "5173"]
    proc.currentDirectoryURL = webDir
    var env = dockerEnvironment()
    let npmBin = npm.deletingLastPathComponent().path
    env["PATH"] = npmBin + ":" + (env["PATH"] ?? "")
    proc.environment = env
    let log = try Self.appendHandle(ConfigStore.stackLogURL)
    proc.standardOutput = log
    proc.standardError = log
    try proc.run()
    webProcess = proc
  }

  private func stopVite() {
    guard let proc = webProcess, proc.isRunning else {
      webProcess = nil
      return
    }
    proc.terminate()
    webProcess = nil
  }

  private static func findBinary(named name: String, extras: [String]) -> URL? {
    for path in extras where FileManager.default.isExecutableFile(atPath: path) {
      return URL(fileURLWithPath: path)
    }
    if let path = ProcessInfo.processInfo.environment["PATH"] {
      for dir in path.split(separator: ":") {
        let candidate = URL(fileURLWithPath: String(dir)).appendingPathComponent(name)
        if FileManager.default.isExecutableFile(atPath: candidate.path) {
          return candidate
        }
      }
    }
    return nil
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

  private func appendLog(_ line: String) {
    let stamp = ISO8601DateFormatter().string(from: Date())
    let text = "[\(stamp)] \(line)\n"
    guard let data = text.data(using: .utf8) else { return }
    try? ConfigStore.ensureSupportDir()
    if !FileManager.default.fileExists(atPath: ConfigStore.stackLogURL.path) {
      FileManager.default.createFile(atPath: ConfigStore.stackLogURL.path, contents: nil)
    }
    if let handle = try? FileHandle(forWritingTo: ConfigStore.stackLogURL) {
      _ = try? handle.seekToEnd()
      try? handle.write(contentsOf: data)
      try? handle.close()
    }
  }
}

private enum StackError: LocalizedError {
  case repoMissing
  case dockerMissing
  case composeFailed(Int32)
  case webMissing
  case npmMissing

  var errorDescription: String? {
    switch self {
    case .repoMissing:
      return "Repo root must contain compose.yaml (set Preferences → Local demo stack)."
    case .dockerMissing:
      return "Docker CLI not found. Start Docker Desktop, then try again."
    case .composeFailed(let code):
      return "docker compose failed (exit \(code)). See stack.log."
    case .webMissing:
      return "web/package.json not found under repo root."
    case .npmMissing:
      return "npm not found on PATH. Start the web UI manually or install Node."
    }
  }
}
