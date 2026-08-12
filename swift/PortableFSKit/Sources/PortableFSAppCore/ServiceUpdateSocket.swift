import Darwin
import Dispatch
import Foundation

enum PortableFSDUpdateSocketError: Error, Equatable {
    case invalidPath
    case inspect(path: String, errno: Int32)
    case unsafeSocket(String)
    case listenerActive
    case peerIdentity
    case timeout
    case closed
    case invalidFrame
}

final class PortableFSDUpdateListener: @unchecked Sendable {
    typealias AcceptSystemCall = @Sendable (Int32) -> Int32

    private let store: PortableFSDUpdateLeaseStore
    private let descriptor: Int32
    private let socketURL: URL
    private let device: dev_t
    private let inode: ino_t
    private let acceptSystemCall: AcceptSystemCall
    private var stopped = false
    private let stateLock = NSLock()

    init(
        store: PortableFSDUpdateLeaseStore,
        acceptSystemCall: @escaping AcceptSystemCall = {
            Darwin.accept($0, nil, nil)
        }
    ) throws {
        self.store = store
        self.acceptSystemCall = acceptSystemCall
        socketURL = store.directoryURL.appendingPathComponent(
            PortableFSDUpdateLeaseStore.socketFilename,
            isDirectory: false
        )
        guard socketURL.path.utf8.count < MemoryLayout.size(
            ofValue: sockaddr_un().sun_path
        ) else {
            throw PortableFSDUpdateSocketError.invalidPath
        }
        try store.requireDirectoryPathPinned()
        try Self.reclaimStaleSocket(at: socketURL, store: store)

        let socketDescriptor = try Self.createStreamSocket(path: socketURL.path)
        do {
            try store.requireDirectoryPathPinned()
            try Self.bind(socketDescriptor, to: socketURL.path)
            try store.requireDirectoryPathPinned()
            guard Darwin.chmod(socketURL.path, 0o600) == 0 else {
                throw PortableFSDUpdateSocketError.inspect(
                    path: socketURL.path,
                    errno: errno
                )
            }
            var status = stat()
            guard Darwin.lstat(socketURL.path, &status) == 0 else {
                throw PortableFSDUpdateSocketError.inspect(
                    path: socketURL.path,
                    errno: errno
                )
            }
            try Self.validateSocket(status, path: socketURL.path)
            guard Darwin.listen(socketDescriptor, 1) == 0 else {
                throw PortableFSDUpdateSocketError.inspect(
                    path: socketURL.path,
                    errno: errno
                )
            }
            descriptor = socketDescriptor
            device = status.st_dev
            inode = status.st_ino
        } catch {
            Darwin.close(socketDescriptor)
            var status = stat()
            if (try? store.requireDirectoryPathPinned()) != nil,
               Darwin.lstat(socketURL.path, &status) == 0,
               status.st_uid == geteuid(),
               status.st_mode & S_IFMT == S_IFSOCK {
                _ = Darwin.unlink(socketURL.path)
            }
            throw error
        }
    }

    deinit {
        stop()
    }

    func accept() throws -> PortableFSDUpdateConnection {
        let connection: Int32
        while true {
            try requirePinnedListener()
            let accepted = acceptSystemCall(descriptor)
            if accepted < 0, errno == EINTR || errno == ECONNABORTED {
                // A signal or a client that abandons a queued connection does
                // not invalidate the listening endpoint. Looping re-proves
                // the exact named listener inode before every retry.
                continue
            }
            guard accepted >= 0 else {
                throw PortableFSDUpdateSocketError.inspect(
                    path: socketURL.path,
                    errno: errno
                )
            }
            connection = accepted
            break
        }
        do {
            guard Darwin.fcntl(connection, F_SETFD, FD_CLOEXEC) == 0 else {
                throw PortableFSDUpdateSocketError.peerIdentity
            }
            var peerUID: uid_t = 0
            var peerGID: gid_t = 0
            guard Darwin.getpeereid(connection, &peerUID, &peerGID) == 0,
                  peerUID == geteuid() else {
                throw PortableFSDUpdateSocketError.peerIdentity
            }
            var peerPID: pid_t = 0
            var peerPIDSize = socklen_t(MemoryLayout<pid_t>.size)
            guard Darwin.getsockopt(
                connection,
                SOL_LOCAL,
                LOCAL_PEERPID,
                &peerPID,
                &peerPIDSize
            ) == 0,
                  peerPIDSize == MemoryLayout<pid_t>.size,
                  peerPID > 0 else {
                throw PortableFSDUpdateSocketError.peerIdentity
            }
            try requirePinnedListener()
            return PortableFSDUpdateConnection(
                descriptor: connection,
                peerPID: peerPID
            )
        } catch {
            Darwin.close(connection)
            throw error
        }
    }

    func stop() {
        try? stopAndProveAbsent()
    }

    /// Closes this listener and removes only the exact socket inode it
    /// published. A successful return is the host-exit publication edge: the
    /// canonical name has been re-proved absent while the pinned parent still
    /// names the lease store directory.
    func stopAndProveAbsent() throws {
        stateLock.lock()
        defer { stateLock.unlock() }
        if !stopped {
            stopped = true
            _ = Darwin.shutdown(descriptor, SHUT_RDWR)
            Darwin.close(descriptor)
        }
        try store.requireDirectoryPathPinned()
        var status = stat()
        if Darwin.lstat(socketURL.path, &status) != 0 {
            let code = errno
            guard code == ENOENT else {
                throw PortableFSDUpdateSocketError.inspect(
                    path: socketURL.path,
                    errno: code
                )
            }
            try store.requireDirectoryPathPinned()
            return
        }
        try Self.validateSocket(status, path: socketURL.path)
        guard status.st_dev == device, status.st_ino == inode else {
            throw PortableFSDUpdateSocketError.unsafeSocket(socketURL.path)
        }
        guard Darwin.unlink(socketURL.path) == 0 else {
            throw PortableFSDUpdateSocketError.inspect(
                path: socketURL.path,
                errno: errno
            )
        }
        try store.requireDirectoryPathPinned()
        if Darwin.lstat(socketURL.path, &status) == 0 {
            throw PortableFSDUpdateSocketError.unsafeSocket(socketURL.path)
        }
        let code = errno
        guard code == ENOENT else {
            throw PortableFSDUpdateSocketError.inspect(
                path: socketURL.path,
                errno: code
            )
        }
    }

    private func requirePinnedListener() throws {
        try store.requireDirectoryPathPinned()
        var status = stat()
        guard Darwin.lstat(socketURL.path, &status) == 0 else {
            throw PortableFSDUpdateSocketError.inspect(
                path: socketURL.path,
                errno: errno
            )
        }
        try Self.validateSocket(status, path: socketURL.path)
        guard status.st_dev == device, status.st_ino == inode else {
            throw PortableFSDUpdateSocketError.unsafeSocket(socketURL.path)
        }
    }

    private static func reclaimStaleSocket(
        at url: URL,
        store: PortableFSDUpdateLeaseStore
    ) throws {
        try store.requireDirectoryPathPinned()
        var original = stat()
        if Darwin.lstat(url.path, &original) != 0 {
            guard errno == ENOENT else {
                throw PortableFSDUpdateSocketError.inspect(
                    path: url.path,
                    errno: errno
                )
            }
            return
        }
        try validateSocket(original, path: url.path)
        let probe = try createStreamSocket(path: url.path)
        let connected: Bool
        let code: Int32
        do {
            try connectBounded(probe, to: url.path, timeoutMilliseconds: 1_000)
            connected = true
            code = 0
        } catch PortableFSDUpdateSocketError.inspect(_, let connectErrno) {
            connected = false
            code = connectErrno
        } catch {
            Darwin.close(probe)
            throw error
        }
        Darwin.close(probe)
        if connected {
            throw PortableFSDUpdateSocketError.listenerActive
        }
        guard code == ECONNREFUSED || code == ENOENT else {
            throw PortableFSDUpdateSocketError.inspect(path: url.path, errno: code)
        }
        var current = stat()
        guard Darwin.lstat(url.path, &current) == 0,
              current.st_dev == original.st_dev,
              current.st_ino == original.st_ino else {
            throw PortableFSDUpdateSocketError.unsafeSocket(url.path)
        }
        try validateSocket(current, path: url.path)
        try store.requireDirectoryPathPinned()
        guard Darwin.unlink(url.path) == 0 else {
            throw PortableFSDUpdateSocketError.inspect(path: url.path, errno: errno)
        }
    }

    private static func validateSocket(_ status: stat, path: String) throws {
        guard status.st_mode & S_IFMT == S_IFSOCK,
              status.st_uid == geteuid(),
              status.st_nlink == 1,
              status.st_mode & 0o777 == 0o600 else {
            throw PortableFSDUpdateSocketError.unsafeSocket(path)
        }
    }

    private static func createStreamSocket(path: String) throws -> Int32 {
        let descriptor = Darwin.socket(AF_UNIX, SOCK_STREAM, 0)
        guard descriptor >= 0 else {
            throw PortableFSDUpdateSocketError.inspect(path: path, errno: errno)
        }
        guard Darwin.fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0 else {
            let code = errno
            Darwin.close(descriptor)
            throw PortableFSDUpdateSocketError.inspect(path: path, errno: code)
        }
        return descriptor
    }

    static func connect(_ descriptor: Int32, to path: String) throws {
        var address = try unixAddress(path)
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(
                    descriptor,
                    $0,
                    socklen_t(MemoryLayout<sockaddr_un>.size)
                )
            }
        }
        guard result == 0 else {
            throw PortableFSDUpdateSocketError.inspect(path: path, errno: errno)
        }
    }

    /// A stale-name probe must never let host startup block behind a live
    /// listener whose accept queue is full. Nonblocking connect plus poll gives
    /// the probe a hard deadline; timeout is ambiguous and therefore never
    /// authorizes reclaiming the named socket.
    static func connectBounded(
        _ descriptor: Int32,
        to path: String,
        timeoutMilliseconds: Int32
    ) throws {
        guard timeoutMilliseconds > 0 else {
            throw PortableFSDUpdateSocketError.timeout
        }
        let originalFlags = Darwin.fcntl(descriptor, F_GETFL)
        guard originalFlags >= 0,
              Darwin.fcntl(descriptor, F_SETFL, originalFlags | O_NONBLOCK) == 0 else {
            throw PortableFSDUpdateSocketError.inspect(path: path, errno: errno)
        }
        defer { _ = Darwin.fcntl(descriptor, F_SETFL, originalFlags) }

        var address = try unixAddress(path)
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(
                    descriptor,
                    $0,
                    socklen_t(MemoryLayout<sockaddr_un>.size)
                )
            }
        }
        if result == 0 { return }
        let connectError = errno
        guard connectError == EINPROGRESS || connectError == EAGAIN else {
            throw PortableFSDUpdateSocketError.inspect(
                path: path,
                errno: connectError
            )
        }

        let deadline = DispatchTime.now().uptimeNanoseconds
            + UInt64(timeoutMilliseconds) * 1_000_000
        while true {
            let now = DispatchTime.now().uptimeNanoseconds
            guard now < deadline else {
                throw PortableFSDUpdateSocketError.timeout
            }
            var pollDescriptor = pollfd(
                fd: descriptor,
                events: Int16(POLLOUT | POLLERR | POLLHUP),
                revents: 0
            )
            let remainingNanoseconds = deadline - now
            let roundedMilliseconds = (remainingNanoseconds + 999_999) / 1_000_000
            let milliseconds = Int32(min(
                UInt64(Int32.max),
                max(1, roundedMilliseconds)
            ))
            let ready = Darwin.poll(&pollDescriptor, 1, milliseconds)
            if ready < 0, errno == EINTR { continue }
            guard ready > 0 else {
                throw PortableFSDUpdateSocketError.timeout
            }
            var socketError: Int32 = 0
            var errorSize = socklen_t(MemoryLayout<Int32>.size)
            guard Darwin.getsockopt(
                descriptor,
                SOL_SOCKET,
                SO_ERROR,
                &socketError,
                &errorSize
            ) == 0,
                  errorSize == MemoryLayout<Int32>.size else {
                throw PortableFSDUpdateSocketError.inspect(path: path, errno: errno)
            }
            guard socketError == 0 else {
                throw PortableFSDUpdateSocketError.inspect(
                    path: path,
                    errno: socketError
                )
            }
            return
        }
    }

    private static func bind(_ descriptor: Int32, to path: String) throws {
        var address = try unixAddress(path)
        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(
                    descriptor,
                    $0,
                    socklen_t(MemoryLayout<sockaddr_un>.size)
                )
            }
        }
        guard result == 0 else {
            throw PortableFSDUpdateSocketError.inspect(path: path, errno: errno)
        }
    }

    private static func unixAddress(_ path: String) throws -> sockaddr_un {
        let bytes = Array(path.utf8)
        var address = sockaddr_un()
        guard bytes.count < MemoryLayout.size(ofValue: address.sun_path) else {
            throw PortableFSDUpdateSocketError.invalidPath
        }
        address.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)
        address.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &address.sun_path) { destination in
            destination.initializeMemory(as: UInt8.self, repeating: 0)
            destination.copyBytes(from: bytes)
        }
        return address
    }
}

final class PortableFSDUpdateConnection: @unchecked Sendable {
    static let maximumFrameBytes = 4_096
    static let timeoutSeconds: TimeInterval = 20

    private let descriptor: Int32
    let peerPID: pid_t
    private var closed = false
    private let stateLock = NSLock()

    init(descriptor: Int32, peerPID: pid_t) {
        self.descriptor = descriptor
        self.peerPID = peerPID
    }

    deinit {
        close()
    }

    func readFrame() throws -> Data {
        let deadline = Date().addingTimeInterval(Self.timeoutSeconds)
        var frame = Data()
        while frame.count < Self.maximumFrameBytes {
            let milliseconds = max(1, Int32(deadline.timeIntervalSinceNow * 1_000))
            guard deadline.timeIntervalSinceNow > 0 else {
                throw PortableFSDUpdateSocketError.timeout
            }
            var pollDescriptor = pollfd(
                fd: descriptor,
                events: Int16(POLLIN | POLLHUP),
                revents: 0
            )
            let ready = Darwin.poll(&pollDescriptor, 1, milliseconds)
            if ready < 0, errno == EINTR { continue }
            guard ready > 0 else {
                throw PortableFSDUpdateSocketError.timeout
            }
            var byte: UInt8 = 0
            let count = Darwin.read(descriptor, &byte, 1)
            if count < 0, errno == EINTR { continue }
            guard count == 1 else {
                throw PortableFSDUpdateSocketError.closed
            }
            frame.append(byte)
            if byte == 0x0a {
                guard frame.count > 1 else {
                    throw PortableFSDUpdateSocketError.invalidFrame
                }
                return frame
            }
        }
        throw PortableFSDUpdateSocketError.invalidFrame
    }

    func writeFrame(_ data: Data) throws {
        guard !data.isEmpty,
              data.count <= Self.maximumFrameBytes,
              data.last == 0x0a,
              !data.dropLast().contains(0x0a) else {
            throw PortableFSDUpdateSocketError.invalidFrame
        }
        let deadline = Date().addingTimeInterval(Self.timeoutSeconds)
        var offset = 0
        while offset < data.count {
            let milliseconds = max(1, Int32(deadline.timeIntervalSinceNow * 1_000))
            guard deadline.timeIntervalSinceNow > 0 else {
                throw PortableFSDUpdateSocketError.timeout
            }
            var pollDescriptor = pollfd(
                fd: descriptor,
                events: Int16(POLLOUT | POLLHUP),
                revents: 0
            )
            let ready = Darwin.poll(&pollDescriptor, 1, milliseconds)
            if ready < 0, errno == EINTR { continue }
            guard ready > 0 else {
                throw PortableFSDUpdateSocketError.timeout
            }
            guard pollDescriptor.revents & Int16(POLLNVAL | POLLERR) == 0 else {
                throw PortableFSDUpdateSocketError.closed
            }
            let remaining = data.count - offset
            let count = data.withUnsafeBytes { bytes in
                Darwin.write(
                    descriptor,
                    bytes.baseAddress!.advanced(by: offset),
                    remaining
                )
            }
            if count < 0, errno == EINTR { continue }
            guard count > 0 else {
                throw PortableFSDUpdateSocketError.closed
            }
            offset += count
        }
    }

    func close() {
        stateLock.lock()
        defer { stateLock.unlock() }
        guard !closed else { return }
        closed = true
        _ = Darwin.shutdown(descriptor, SHUT_RDWR)
        Darwin.close(descriptor)
    }
}
