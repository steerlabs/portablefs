import Foundation
import Darwin

public final class WorkspaceState {
    public let directory: URL
    private let lock: WorkspaceFileLock
    private let privateDirectory: WorkspacePrivateDirectory
    public var socket: URL { directory.appendingPathComponent("ssh.sock") }
    public var formatAuthorized: String { FileManager.default.fileExists(atPath: directory.appendingPathComponent("format-authorized").path) ? "8" : "" }
    public let machineID: String
    public let macAddress: String
    public init(directory: URL, ownership: WorkspaceFileLock? = nil) throws {
        self.directory = directory
        privateDirectory = try WorkspacePrivateDirectory(directory)
        if let ownership {
            try privateDirectory.validateLock(ownership, name: "owner.lock")
            lock = ownership
        } else { lock = try privateDirectory.lock("owner.lock") }
        let identity = directory.appendingPathComponent("network-identity")
        if !FileManager.default.fileExists(atPath: identity.path) {
            let id = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
            let mac = "02:" + stride(from: 0, to: 10, by: 2).map { offset in String(id.dropFirst(offset).prefix(2)) }.joined(separator: ":")
            try Self.atomic(Data((id + "\n" + mac + "\n").utf8), to: identity)
        }
        let lines = try String(contentsOf: identity, encoding: .utf8).split(separator: "\n")
        guard lines.count == 2, lines[0].count == 32, lines[0].allSatisfy({ $0.isHexDigit }), lines[1].count == 17 else { throw WorkspaceVMError("invalid persistent network identity") }
        machineID = String(lines[0]); macAddress = String(lines[1])
        let disk = directory.appendingPathComponent("data.ext4")
        if !FileManager.default.fileExists(atPath: disk.path) {
            let attributes = try FileManager.default.attributesOfFileSystem(forPath: directory.path)
            guard let free = attributes[.systemFreeSize] as? NSNumber, free.uint64Value >= 8 * 1024 * 1024 * 1024 else { throw WorkspaceVMError("Not enough disk space") }
            try Self.atomic(Data("8\n".utf8), to: directory.appendingPathComponent("format-authorized"))
            let temporary = directory.appendingPathComponent("data.initializing")
            let fd = open(temporary.path, O_CREAT | O_TRUNC | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0o600)
            guard fd >= 0 else { throw WorkspaceVMError("create sparse data disk: \(errno)") }
            defer { Darwin.close(fd) }
            guard ftruncate(fd, 64 * 1024 * 1024 * 1024) == 0, fsync(fd) == 0, rename(temporary.path, disk.path) == 0 else { throw WorkspaceVMError("commit sparse data disk: \(errno)") }
            try Self.syncDirectory(directory)
        }
        let key = directory.appendingPathComponent("client_ed25519")
        if !FileManager.default.fileExists(atPath: key.path) {
            let temporary = directory.appendingPathComponent("client.initializing")
            try? FileManager.default.removeItem(at: temporary)
            try? FileManager.default.removeItem(atPath: temporary.path + ".pub")
            _ = try Self.keygen(["-q", "-t", "ed25519", "-N", "", "-f", temporary.path])
            _ = try Self.keygen(["-y", "-f", temporary.path])
            let fd = open(temporary.path, O_RDONLY | O_NOFOLLOW); guard fd >= 0 else { throw WorkspaceVMError("open generated key") }
            defer { Darwin.close(fd) }
            guard fsync(fd) == 0, rename(temporary.path, key.path) == 0 else { throw WorkspaceVMError("commit client key: \(errno)") }
            try Self.syncDirectory(directory)
            try FileManager.default.removeItem(atPath: temporary.path + ".pub")
        }
        // Derive public material from the one durable private identity on every
        // start; a missing .pub file cannot strand the workspace.
        let publicKey = try Self.keygen(["-y", "-f", key.path])
        try Self.atomic(Data(publicKey.utf8), to: directory.appendingPathComponent("client_ed25519.pub"))
    }
    private static func keygen(_ arguments: [String]) throws -> String {
        let process = Process(); let output = Pipe()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen"); process.arguments = arguments; process.standardOutput = output
        try process.run()
        let data = output.fileHandleForReading.readDataToEndOfFile(); process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw WorkspaceVMError("ssh-keygen validation/creation failed") }
        return String(decoding: data, as: UTF8.self)
    }
    private static func syncDirectory(_ directory: URL) throws {
        let fd = open(directory.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
        guard fd >= 0 else { throw WorkspaceVMError("open state directory: \(errno)") }; defer { Darwin.close(fd) }
        guard fsync(fd) == 0 else { throw WorkspaceVMError("sync state directory: \(errno)") }
    }
    private static func atomic(_ data: Data, to path: URL) throws {
        let temporary = path.appendingPathExtension("initializing")
        let fd = open(temporary.path, O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0o600)
        guard fd >= 0 else { throw WorkspaceVMError("create state temporary: \(errno)") }; defer { Darwin.close(fd) }
        guard data.withUnsafeBytes({ Darwin.write(fd, $0.baseAddress, $0.count) }) == data.count, fsync(fd) == 0,
              rename(temporary.path, path.path) == 0 else { throw WorkspaceVMError("commit state file: \(errno)") }
        try syncDirectory(path.deletingLastPathComponent())
    }
    public func formatCompleted() throws {
        let marker = directory.appendingPathComponent("format-authorized")
        if unlink(marker.path) != 0 && errno != ENOENT { throw WorkspaceVMError("remove format authorization: \(errno)") }
        try Self.syncDirectory(directory)
    }
    public var authorizedKey: String { get throws { try String(contentsOf: directory.appendingPathComponent("client_ed25519.pub"), encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines) } }
    public func pin(hostKey: String) throws -> URL {
        let parts = hostKey.split(separator: " ")
        guard parts.count >= 2, parts[0] == "ssh-ed25519", !hostKey.contains("\n"), !hostKey.contains("\r") else { throw WorkspaceVMError("invalid guest host key") }
        let canonical = parts.prefix(2).joined(separator: " ") + "\n"
        let pin = directory.appendingPathComponent("guest_host_key.pub")
        if FileManager.default.fileExists(atPath: pin.path) {
            guard try String(contentsOf: pin, encoding: .utf8) == canonical else { throw WorkspaceVMError("SSH identity changed") }
        } else { try Self.atomic(Data(canonical.utf8), to: pin) }
        let known = directory.appendingPathComponent("known_hosts")
        try Self.atomic(Data(("portablefs-workspace " + canonical).utf8), to: known)
        func quote(_ text: String) throws -> String {
            guard !text.contains("\n"), !text.contains("\r") else { throw WorkspaceVMError("invalid SSH state path") }
            return "\"" + text.replacingOccurrences(of: "%", with: "%%").replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
        }
        let shellPath = "'" + socket.path.replacingOccurrences(of: "'", with: "'\\''").replacingOccurrences(of: "%", with: "%%") + "'"
        let config = """
        Host portablefs-workspace
          HostName portablefs-workspace
          ProxyCommand /usr/bin/nc -U \(shellPath)
          User workspace
          IdentityFile \(try quote(directory.appendingPathComponent("client_ed25519").path))
          IdentitiesOnly yes
          HostKeyAlias portablefs-workspace
          StrictHostKeyChecking yes
          UserKnownHostsFile \(try quote(known.path))
          BatchMode yes
          ConnectTimeout 10

        """
        let path = directory.appendingPathComponent("ssh_config")
        try Self.atomic(Data(config.utf8), to: path)
        return path
    }
}
