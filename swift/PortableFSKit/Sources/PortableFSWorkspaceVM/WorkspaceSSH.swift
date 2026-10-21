import Foundation
import Darwin
@preconcurrency import Virtualization

@MainActor public final class WorkspaceSSHBridge {
    private struct Session { let guest: VZVirtioSocketConnection; let relay: WorkspaceRelay }
    private let vm: WorkspaceMachine
    private let path: URL
    private var listener: Int32 = -1
    private var source: DispatchSourceRead?
    private var pending: [UUID: Int32] = [:]
    private var sessions: [UUID: Session] = [:]
    public init(vm: WorkspaceMachine, socket: URL) { self.vm = vm; path = socket }
    public func start() throws {
        guard listener == -1 else { throw WorkspaceVMError("SSH bridge already started") }
        var address = sockaddr_un()
        let bytes = Array(path.path.utf8) + [0]
        guard bytes.count <= MemoryLayout.size(ofValue: address.sun_path) else { throw WorkspaceVMError("SSH Unix socket path exceeds native limit") }
        address.sun_family = sa_family_t(AF_UNIX); address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        withUnsafeMutableBytes(of: &address.sun_path) { $0.copyBytes(from: bytes) }
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw WorkspaceVMError("SSH bridge socket: \(errno)") }
        unlink(path.path)
        let bound = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
        guard bound == 0, chmod(path.path, 0o600) == 0, listen(fd, 16) == 0 else { Darwin.close(fd); throw WorkspaceVMError("SSH Unix bind: \(errno)") }
        listener = fd; _ = fcntl(fd, F_SETFL, O_NONBLOCK)
        let source = DispatchSource.makeReadSource(fileDescriptor: fd, queue: .main)
        source.setCancelHandler { Darwin.close(fd) }
        source.setEventHandler { [weak self] in self?.acceptClients() }
        self.source = source; source.resume()
    }
    private func acceptClients() {
        while listener >= 0 {
            let client = accept(listener, nil, nil)
            if client < 0 { return }
            guard sessions.count + pending.count < 64 else { Darwin.close(client); continue }
            let id = UUID(); pending[id] = client
            vm.connect(port: 22) { [weak self] result in
                guard let self else { Darwin.close(client); return }
                guard self.pending.removeValue(forKey: id) != nil else { if case .success(let guest) = result { guest.close() }; return }
                guard self.listener >= 0 else { Darwin.close(client); if case .success(let guest) = result { guest.close() }; return }
                do {
                    let guest = try result.get()
                    let relay = try WorkspaceRelay(client: client, guest: guest.fileDescriptor) { [weak self] in
                        self?.sessions.removeValue(forKey: id)?.guest.close()
                    }
                    self.sessions[id] = Session(guest: guest, relay: relay)
                } catch { Darwin.close(client) }
            }
        }
    }
    public func close() {
        listener = -1; source?.cancel(); source = nil; unlink(path.path)
        for client in pending.values { Darwin.close(client) }
        pending.removeAll()
        for session in sessions.values { session.relay.close() }
    }
}
