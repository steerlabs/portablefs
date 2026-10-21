import Foundation
import Darwin
@preconcurrency import Virtualization

@MainActor public final class WorkspaceSSHBridge {
    private struct Session { let client: Int32; let guest: VZVirtioSocketConnection; var pending = 2 }
    private let vm: WorkspaceMachine
    private var listener: Int32 = -1
    private var source: DispatchSourceRead?
    private var sessions: [UUID: Session] = [:]
    public private(set) var port: UInt16 = 0
    public init(vm: WorkspaceMachine) { self.vm = vm }
    public func start() throws {
        guard listener == -1 else { throw WorkspaceVMError("SSH bridge already started") }
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw WorkspaceVMError("SSH bridge socket failed") }
        listener = fd
        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size); address.sin_family = sa_family_t(AF_INET)
        address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1")); address.sin_port = 0
        let bound = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
        guard bound == 0, listen(fd, 16) == 0 else { close(); throw WorkspaceVMError("loopback SSH bind failed") }
        var size = socklen_t(MemoryLayout<sockaddr_in>.size)
        let status = withUnsafeMutablePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &size) } }
        guard status == 0 else { close(); throw WorkspaceVMError("SSH port lookup failed") }
        port = UInt16(bigEndian: address.sin_port)
        _ = fcntl(fd, F_SETFL, O_NONBLOCK)
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: .main)
        source.setEventHandler { [weak self] in self?.acceptClients() }
        self.source = source; source.resume()
    }
    private func acceptClients() {
        while listener >= 0 {
            let client = accept(listener, nil, nil)
            if client < 0 { return }
            guard sessions.count < 64 else { Darwin.close(client); continue }
            let id = UUID()
            vm.connect(port: 22) { [weak self] result in
                guard let self, self.listener >= 0 else { Darwin.close(client); return }
                guard case .success(let guest) = result else { Darwin.close(client); return }
                for fd in [client, guest.fileDescriptor] {
                    var flag: Int32 = 1; setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &flag, socklen_t(MemoryLayout.size(ofValue: flag)))
                    _ = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) & ~O_NONBLOCK)
                }
                self.sessions[id] = Session(client: client, guest: guest)
                for (input, output) in [(client, guest.fileDescriptor), (guest.fileDescriptor, client)] {
                    WorkspaceIO({ try Self.pump(input, output) }, completion: { [weak self] result in self?.finished(id, result) }).start()
                }
            }
        }
    }
    nonisolated private static func pump(_ input: Int32, _ output: Int32) throws {
        var bytes = [UInt8](repeating: 0, count: 65536)
        while true {
            let count = Darwin.read(input, &bytes, bytes.count)
            if count < 0 && errno == EINTR { continue }
            guard count >= 0 else { throw WorkspaceVMError("SSH relay read failed") }
            if count == 0 { shutdown(output, SHUT_WR); return }
            var offset = 0
            while offset < count {
                let n = bytes.withUnsafeBytes { Darwin.write(output, $0.baseAddress?.advanced(by: offset), count - offset) }
                if n < 0 && errno == EINTR { continue }
                guard n > 0 else { throw WorkspaceVMError("SSH relay write failed") }; offset += n
            }
        }
    }
    private func finished(_ id: UUID, _ result: Result<Void, Error>) {
        guard var session = sessions[id] else { return }
        if case .failure = result { shutdown(session.client, SHUT_RDWR); shutdown(session.guest.fileDescriptor, SHUT_RDWR) }
        session.pending -= 1
        if session.pending == 0 { Darwin.close(session.client); session.guest.close(); sessions.removeValue(forKey: id) }
        else { sessions[id] = session }
    }
    public func close() {
        source?.cancel(); source = nil
        if listener >= 0 { Darwin.close(listener); listener = -1 }
        for session in sessions.values { shutdown(session.client, SHUT_RDWR); shutdown(session.guest.fileDescriptor, SHUT_RDWR) }
    }
}

public final class WorkspaceDevState {
    public let directory: URL
    private let lock: Int32
    public init(directory: URL) throws {
        self.directory = directory
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        let owner = open(directory.appendingPathComponent("owner.lock").path, O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW, 0o600)
        guard owner >= 0 else { throw WorkspaceVMError("workspace state lock failed") }
        guard flock(owner, LOCK_EX | LOCK_NB) == 0 else { Darwin.close(owner); throw WorkspaceVMError("workspace state already owned") }
        lock = owner
        let disk = directory.appendingPathComponent("data.ext4")
        if !FileManager.default.fileExists(atPath: disk.path) {
            let attributes = try FileManager.default.attributesOfFileSystem(forPath: directory.path)
            guard let free = attributes[.systemFreeSize] as? NSNumber, free.uint64Value >= 8 * 1024 * 1024 * 1024 else { throw WorkspaceVMError("data disk requires at least 8 GiB free host storage") }
            let fd = open(disk.path, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0o600)
            guard fd >= 0 else { throw WorkspaceVMError("data disk creation failed") }
            defer { Darwin.close(fd) }
            let header = Data("PFS-WORKSPACE-DATA-8\n".utf8)
            guard ftruncate(fd, 64 * 1024 * 1024 * 1024) == 0,
                  header.withUnsafeBytes({ Darwin.write(fd, $0.baseAddress, $0.count) }) == header.count,
                  fsync(fd) == 0 else { throw WorkspaceVMError("sparse data disk initialization failed") }
        }
        let key = directory.appendingPathComponent("client_ed25519")
        if !FileManager.default.fileExists(atPath: key.path) {
            let process = Process(); process.executableURL = URL(fileURLWithPath: "/usr/bin/ssh-keygen")
            process.arguments = ["-q", "-t", "ed25519", "-N", "", "-f", key.path]
            try process.run(); process.waitUntilExit()
            guard process.terminationStatus == 0 else { throw WorkspaceVMError("client key creation failed") }
        }
    }
    deinit { if lock >= 0 { flock(lock, LOCK_UN); Darwin.close(lock) } }
    public var authorizedKey: String { get throws { try String(contentsOf: directory.appendingPathComponent("client_ed25519.pub"), encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines) } }
    public func pin(hostKey: String, port: UInt16) throws -> URL {
        let parts = hostKey.split(separator: " ")
        guard parts.count >= 2, parts[0] == "ssh-ed25519", !hostKey.contains("\n"), !hostKey.contains("\r") else { throw WorkspaceVMError("invalid guest host key") }
        let canonical = parts.prefix(2).joined(separator: " ")
        let pin = directory.appendingPathComponent("guest_host_key.pub")
        if FileManager.default.fileExists(atPath: pin.path) {
            guard try String(contentsOf: pin, encoding: .utf8) == canonical + "\n" else { throw WorkspaceVMError("persistent guest host key changed") }
        } else { try (canonical + "\n").write(to: pin, atomically: true, encoding: .utf8) }
        let known = directory.appendingPathComponent("known_hosts")
        try ("portablefs-workspace " + canonical + "\n").write(to: known, atomically: true, encoding: .utf8)
        func quote(_ path: URL) throws -> String {
            guard !path.path.contains("\n"), !path.path.contains("\r") else { throw WorkspaceVMError("invalid SSH state path") }
            return "\"" + path.path.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"") + "\""
        }
        let config = """
        Host portablefs-workspace
          HostName 127.0.0.1
          Port \(port)
          User workspace
          IdentityFile \(try quote(directory.appendingPathComponent("client_ed25519")))
          IdentitiesOnly yes
          HostKeyAlias portablefs-workspace
          StrictHostKeyChecking yes
          UserKnownHostsFile \(try quote(known))
          BatchMode yes
          ConnectTimeout 10

        """
        let path = directory.appendingPathComponent("ssh_config")
        try config.write(to: path, atomically: true, encoding: .utf8)
        return path
    }
}
