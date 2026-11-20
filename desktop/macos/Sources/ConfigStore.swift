import Foundation

/// Persisted desktop preferences (URLs and paths only — no secrets).
struct DesktopConfig: Codable, Equatable {
  var backendURL: String
  var webConsoleURL: String
  var caCertPath: String
  var packageDir: String
  var privilegedSocket: String
  var startAgentOnLaunch: Bool
  /// Demo/dev only: start/stop Docker Compose with this Mac's repo. Off for real SaaS clients.
  var manageLocalStack: Bool
  var repoRoot: String
  var startWebDevServer: Bool
  var openConsoleOnLaunch: Bool
  var stopStackOnQuit: Bool

  static let `default` = DesktopConfig(
    backendURL: "https://localhost:8443",
    webConsoleURL: "http://localhost:5173",
    caCertPath: "",
    packageDir: "/Users/Shared/SentinelDesk/packages",
    privilegedSocket: "/var/run/sentineldesk/privileged.sock",
    startAgentOnLaunch: true,
    manageLocalStack: false,
    repoRoot: "",
    startWebDevServer: false,
    openConsoleOnLaunch: true,
    stopStackOnQuit: true
  )

  enum CodingKeys: String, CodingKey {
    case backendURL, webConsoleURL, caCertPath, packageDir, privilegedSocket
    case startAgentOnLaunch, manageLocalStack, repoRoot, startWebDevServer
    case openConsoleOnLaunch, stopStackOnQuit
  }

  init(
    backendURL: String,
    webConsoleURL: String,
    caCertPath: String,
    packageDir: String,
    privilegedSocket: String,
    startAgentOnLaunch: Bool,
    manageLocalStack: Bool,
    repoRoot: String,
    startWebDevServer: Bool,
    openConsoleOnLaunch: Bool,
    stopStackOnQuit: Bool
  ) {
    self.backendURL = backendURL
    self.webConsoleURL = webConsoleURL
    self.caCertPath = caCertPath
    self.packageDir = packageDir
    self.privilegedSocket = privilegedSocket
    self.startAgentOnLaunch = startAgentOnLaunch
    self.manageLocalStack = manageLocalStack
    self.repoRoot = repoRoot
    self.startWebDevServer = startWebDevServer
    self.openConsoleOnLaunch = openConsoleOnLaunch
    self.stopStackOnQuit = stopStackOnQuit
  }

  init(from decoder: Decoder) throws {
    let c = try decoder.container(keyedBy: CodingKeys.self)
    let d = DesktopConfig.default
    backendURL = try c.decodeIfPresent(String.self, forKey: .backendURL) ?? d.backendURL
    webConsoleURL = try c.decodeIfPresent(String.self, forKey: .webConsoleURL) ?? d.webConsoleURL
    caCertPath = try c.decodeIfPresent(String.self, forKey: .caCertPath) ?? d.caCertPath
    packageDir = try c.decodeIfPresent(String.self, forKey: .packageDir) ?? d.packageDir
    privilegedSocket = try c.decodeIfPresent(String.self, forKey: .privilegedSocket) ?? d.privilegedSocket
    startAgentOnLaunch = try c.decodeIfPresent(Bool.self, forKey: .startAgentOnLaunch) ?? d.startAgentOnLaunch
    manageLocalStack = try c.decodeIfPresent(Bool.self, forKey: .manageLocalStack) ?? d.manageLocalStack
    repoRoot = try c.decodeIfPresent(String.self, forKey: .repoRoot) ?? d.repoRoot
    startWebDevServer = try c.decodeIfPresent(Bool.self, forKey: .startWebDevServer) ?? d.startWebDevServer
    openConsoleOnLaunch = try c.decodeIfPresent(Bool.self, forKey: .openConsoleOnLaunch) ?? d.openConsoleOnLaunch
    stopStackOnQuit = try c.decodeIfPresent(Bool.self, forKey: .stopStackOnQuit) ?? d.stopStackOnQuit
  }
}

enum ConfigStore {
  static let appSupportName = "com.SentinelDesk.Agent"
  static let bundleId = "com.sentineldesk.desktop"

  static var supportDir: URL {
    let home = FileManager.default.homeDirectoryForCurrentUser
    return home
      .appendingPathComponent("Library/Application Support", isDirectory: true)
      .appendingPathComponent(appSupportName, isDirectory: true)
  }

  static var statusURL: URL { supportDir.appendingPathComponent("status.json") }
  static var configURL: URL { supportDir.appendingPathComponent("desktop-config.json") }
  static var agentLogOut: URL { supportDir.appendingPathComponent("agent.out.log") }
  static var agentLogErr: URL { supportDir.appendingPathComponent("agent.err.log") }
  static var stackLogURL: URL { supportDir.appendingPathComponent("stack.log") }
  static var jobPublicKeyURL: URL { supportDir.appendingPathComponent("job_signing_public.pem") }

  static func ensureSupportDir() throws {
    try FileManager.default.createDirectory(at: supportDir, withIntermediateDirectories: true)
  }

  static func load() -> DesktopConfig {
    guard let data = try? Data(contentsOf: configURL),
          let decoded = try? JSONDecoder().decode(DesktopConfig.self, from: data)
    else {
      return .default
    }
    return decoded
  }

  static func save(_ config: DesktopConfig) throws {
    try ensureSupportDir()
    let data = try JSONEncoder().encode(config)
    try data.write(to: configURL, options: [.atomic])
    try? FileManager.default.setAttributes(
      [.posixPermissions: 0o600],
      ofItemAtPath: configURL.path
    )
  }

  static func resolvedCaCert(config: DesktopConfig) -> String? {
    if !config.caCertPath.isEmpty, FileManager.default.isReadableFile(atPath: config.caCertPath) {
      return config.caCertPath
    }
    if let bundled = Bundle.main.url(forResource: "ca", withExtension: "pem") {
      return bundled.path
    }
    return nil
  }
}
