import Foundation
import CryptoKit

/// Finds the `portablefsd` executable the app should spawn.
///
/// Search order (first executable wins):
/// 1. explicit user override (Settings / UserDefaults)
/// 2. `PFSPortableFSDBinaryPath` from the app Info.plist
/// 3. `PORTABLEFSD_BIN` environment variable
/// 4. `portablefsd` bundled in the app's Resources directory
/// 5. `~/bin/portablefsd` (documented dev install: `go build -o ~/bin/portablefsd ./cmd/portablefsd`)
/// 6. `/usr/local/bin/portablefsd`
/// 7. `/opt/homebrew/bin/portablefsd`
public struct DaemonBinaryLocator: Sendable {
    public var userOverride: String?
    public var infoPlistPath: String?
    public var environment: [String: String]
    public var bundledPath: String?
    public var homeDirectory: String
    public var isExecutableFile: @Sendable (String) -> Bool

    public init(
        userOverride: String? = nil,
        infoPlistPath: String? = nil,
        environment: [String: String] = ProcessInfo.processInfo.environment,
        bundledPath: String? = nil,
        homeDirectory: String = NSHomeDirectory(),
        isExecutableFile: @escaping @Sendable (String) -> Bool = { FileManager.default.isExecutableFile(atPath: $0) }
    ) {
        self.userOverride = userOverride
        self.infoPlistPath = infoPlistPath
        self.environment = environment
        self.bundledPath = bundledPath
        self.homeDirectory = homeDirectory
        self.isExecutableFile = isExecutableFile
    }

    public var candidates: [String] {
        var paths: [String] = []
        if let userOverride, !userOverride.isEmpty {
            paths.append(userOverride)
        }
        if let infoPlistPath, !infoPlistPath.isEmpty {
            paths.append(infoPlistPath)
        }
        if let envPath = environment["PORTABLEFSD_BIN"], !envPath.isEmpty {
            paths.append(envPath)
        }
        if let bundledPath, !bundledPath.isEmpty {
            paths.append(bundledPath)
        }
        paths.append((homeDirectory as NSString).appendingPathComponent("bin/portablefsd"))
        paths.append("/usr/local/bin/portablefsd")
        paths.append("/opt/homebrew/bin/portablefsd")
        return paths
    }

    public func locate() -> String? {
        candidates.first(where: isExecutableFile)
    }
}

public struct DaemonBinaryIdentity: Equatable, Sendable {
    public var version: String
    public var executableSha256: String

    public init(path: String) throws {
        let data = try Data(contentsOf: URL(fileURLWithPath: path), options: [.mappedIfSafe])
        executableSha256 = SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()

        let process = Process()
        let output = Pipe()
        process.executableURL = URL(fileURLWithPath: path)
        process.arguments = ["-version"]
        process.standardOutput = output
        process.standardError = output
        try process.run()
        process.waitUntilExit()
        let bytes = output.fileHandleForReading.readDataToEndOfFile()
        version = String(data: bytes, encoding: .utf8)?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard process.terminationStatus == 0, !version.isEmpty else {
            throw CocoaError(.executableNotLoadable)
        }
    }

    public func matches(_ running: DaemonIdentity) -> Bool {
        running.schemaVersion == 1 &&
            running.controlProtocol == 1 &&
            running.daemonVersion == version &&
            running.executableSha256 == executableSha256 &&
            running.pfslocalMajor == 1
    }
}
