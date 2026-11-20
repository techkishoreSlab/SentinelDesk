import AppKit
import Foundation

enum SingleInstance {
  /// Ensure only one Sentinel desktop UI is visible; retire the legacy menu-bar helper.
  static func claimOrExit() {
    terminateLegacyMenuBarHelper()
    let mine = ProcessInfo.processInfo.processIdentifier
    let others = NSWorkspace.shared.runningApplications.filter {
      $0.bundleIdentifier == ConfigStore.bundleId && $0.processIdentifier != mine
    }
    for app in others {
      app.terminate()
    }
    // Brief wait so the previous status item is removed before we add ours.
    if !others.isEmpty {
      Thread.sleep(forTimeInterval: 0.35)
    }
  }

  private static func terminateLegacyMenuBarHelper() {
    let task = Process()
    task.executableURL = URL(fileURLWithPath: "/usr/bin/pkill")
    task.arguments = ["-x", "SentinelMenuBar"]
    try? task.run()
    task.waitUntilExit()
  }
}
