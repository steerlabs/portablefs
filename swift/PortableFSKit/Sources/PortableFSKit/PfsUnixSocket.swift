import Foundation
@preconcurrency import Darwin

public enum PfsUnixSocket {
    public static func connect(path: String) throws -> Int32 {
        // The failure paths below must close the fd exactly once: a
        // guard-close followed by a rethrow into an outer catch-close would
        // double-close, and with fd numbers recycled across threads the
        // second close can tear down an unrelated descriptor.
        var address: sockaddr_un
        do {
            address = try sockaddrUnix(path: path)
        } catch {
            throw error
        }

        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw PfsLocalClientError.system(errno: pfsErrno(), operation: "socket")
        }
        disableSigPipe(fd: fd)

        let result = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                Darwin.connect(fd, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard result == 0 else {
            let error = pfsErrno()
            Darwin.close(fd)
            throw PfsLocalClientError.system(errno: error, operation: "connect")
        }
        return fd
    }

    public static func bindAndListen(path: String, backlog: Int32 = 16) throws -> Int32 {
        var address = try sockaddrUnix(path: path)

        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw PfsLocalClientError.system(errno: pfsErrno(), operation: "socket")
        }
        disableSigPipe(fd: fd)

        unlink(path)
        let bindResult = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                Darwin.bind(fd, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bindResult == 0 else {
            let error = pfsErrno()
            Darwin.close(fd)
            throw PfsLocalClientError.system(errno: error, operation: "bind")
        }
        guard listen(fd, backlog) == 0 else {
            let error = pfsErrno()
            Darwin.close(fd)
            throw PfsLocalClientError.system(errno: error, operation: "listen")
        }
        return fd
    }

    public static func accept(_ fd: Int32) throws -> Int32 {
        while true {
            let client = Darwin.accept(fd, nil, nil)
            if client >= 0 {
                disableSigPipe(fd: client)
                return client
            }
            let error = pfsErrno()
            if error == EINTR {
                continue
            }
            throw PfsLocalClientError.system(errno: error, operation: "accept")
        }
    }

    public static func close(_ fd: Int32) {
        _ = Darwin.close(fd)
    }

    private static func disableSigPipe(fd: Int32) {
        var value: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &value, socklen_t(MemoryLayout<Int32>.size))
    }

    private static func sockaddrUnix(path: String) throws -> sockaddr_un {
        guard path.hasPrefix("/") else {
            throw PfsLocalClientError.socketPath("Unix socket path must be absolute: \(path)")
        }
        let pathBytes = Array(path.utf8)
        let capacity = MemoryLayout.size(ofValue: sockaddr_un().sun_path)
        guard pathBytes.count < capacity else {
            throw PfsLocalClientError.socketPath("path is too long for sockaddr_un: \(path)")
        }

        var address = sockaddr_un()
        address.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &address.sun_path) { rawBuffer in
            let buffer = rawBuffer.bindMemory(to: CChar.self)
            for index in 0..<pathBytes.count {
                buffer[index] = CChar(bitPattern: pathBytes[index])
            }
            buffer[pathBytes.count] = 0
        }
        return address
    }
}
