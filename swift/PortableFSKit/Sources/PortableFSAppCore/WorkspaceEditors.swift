import AppKit
import Foundation

public enum PortableFSWorkspaceEditor: String, CaseIterable, Sendable {
    case vscode, cursor
    public var name: String { self == .vscode ? "VS Code" : "Cursor" }
    public var scheme: String { self == .vscode ? "vscode-remote" : "cursor" }
    var bundleIdentifier: String { self == .vscode ? "com.microsoft.VSCode" : "com.todesktop.230313mzl4w4u92" }
    var cli: String { self == .vscode ? "code" : "cursor" }
    func recognizes(_ identifier: String) -> Bool {
        identifier == "ms-vscode-remote.remote-ssh" || (self == .cursor && identifier == "anysphere.remote-ssh")
    }
    public func folderURL(volume: String) throws -> URL {
        let address = self == .vscode
            ? "vscode-remote://ssh-remote+portablefs-workspace/workspaces/\(volume)"
            : "cursor://vscode-remote/ssh-remote+portablefs-workspace/workspaces/\(volume)"
        guard PortableFSWorkspaceStatus.validVolume(volume), let url = URL(string: address) else { throw PortableFSWorkspaceError("Invalid workspace volume") }
        return url
    }
    public func requireRemoteSSH(extensions: String) throws {
        guard extensions.split(whereSeparator: \.isNewline).contains(where: { recognizes($0.trimmingCharacters(in: .whitespaces).lowercased()) }) else { throw PortableFSWorkspaceError("\(name) Remote-SSH extension is not installed. Install it in \(name), then try again.") }
    }
    /// Test callers pass both isolated profile directories. Production opens
    /// the user's editor only after this action is explicitly selected.
    @MainActor public func open(volume: String, application: URL? = nil, userData: URL? = nil, extensions: URL? = nil) async throws {
        guard (userData == nil) == (extensions == nil) else { throw PortableFSWorkspaceError("Both editor test directories are required") }
        guard let app = application ?? NSWorkspace.shared.urlForApplication(withBundleIdentifier: bundleIdentifier) else { throw PortableFSWorkspaceError("\(name) is not installed.") }
        let executable = app.appendingPathComponent("Contents/Resources/app/bin/" + cli)
        guard FileManager.default.isExecutableFile(atPath: executable.path) else { throw PortableFSWorkspaceError("\(name) command is unavailable.") }
        var profile: [String] = []
        if let userData, let extensions { profile = ["--user-data-dir", userData.path, "--extensions-dir", extensions.path] }
        let installed = try await Self.run(executable, arguments: profile + ["--list-extensions"])
        try requireRemoteSSH(extensions: installed)
        let action = self == .vscode ? "--folder-uri" : "--open-url"
        _ = try await Self.run(executable, arguments: profile + ["--new-window", action, folderURL(volume: volume).absoluteString])
    }
    private static func run(_ executable: URL, arguments: [String]) async throws -> String {
        try await Task.detached {
            let process = Process(), output = Pipe()
            process.executableURL = executable; process.arguments = arguments
            process.standardInput = FileHandle.nullDevice; process.standardOutput = output; process.standardError = FileHandle.nullDevice
            try process.run()
            let data = output.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
            guard process.terminationStatus == 0 else { throw PortableFSWorkspaceError("Editor command failed (\(process.terminationStatus)).") }
            return String(decoding: data, as: UTF8.self)
        }.value
    }
}
