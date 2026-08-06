import Foundation
@preconcurrency import Darwin

/// Receives this mount's kernel root descriptor from portablefsd.
///
/// The macOS app sandbox hides an FSKit extension's own kernel mount from the
/// extension itself: `getfsstat` inside the extension enumerates every volume
/// on the machine except the one the extension is serving, so in-process
/// mount-root location is impossible by construction — the first live peer
/// repair proved it. portablefsd is not sandboxed, knows the attach's exact
/// mount path, and shares a socket directory the extension may connect into,
/// so it opens the root and passes the DESCRIPTOR over a dedicated unix
/// socket via SCM_RIGHTS; descriptors cross sandbox boundaries by design.
///
/// Wire form: send the attach ref and a newline; receive one status byte —
/// 1 with the O_DIRECTORY descriptor attached, 0 with nothing. The received
/// descriptor is attested locally (`fstat` must project this adapter's root
/// file identifier) before it is trusted, exactly like the scan-based
/// locator attested its own open.
enum PfsMountRootHandoff {
    static func socketPath(besideFrontendSocket frontendSocket: String) -> String {
        (frontendSocket as NSString).deletingLastPathComponent + "/pfs-root.sock"
    }

    static func openRoot(
        handoffSocketPath: String,
        attachRef: String,
        expectedRootFileID: UInt64
    ) throws -> Int32 {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            throw PfsMacOSCoherenceError.posix(operation: "mount-root handoff socket", errno: errno)
        }
        defer { close(fd) }
        var timeout = timeval(tv_sec: 5, tv_usec: 0)
        _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
        _ = setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(handoffSocketPath.utf8)
        let capacity = MemoryLayout.size(ofValue: addr.sun_path) - 1
        guard pathBytes.count <= capacity else {
            throw PfsMacOSCoherenceError.posix(operation: "mount-root handoff path", errno: ENAMETOOLONG)
        }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: pathBytes)
        }
        let connected = withUnsafePointer(to: &addr) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sa in
                connect(fd, sa, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard connected == 0 else {
            throw PfsMacOSCoherenceError.posix(operation: "mount-root handoff connect", errno: errno)
        }

        let request = Array((attachRef + "\n").utf8)
        guard request.withUnsafeBytes({ write(fd, $0.baseAddress, $0.count) }) == request.count else {
            throw PfsMacOSCoherenceError.posix(operation: "mount-root handoff send", errno: errno)
        }

        var status: UInt8 = 0
        var control = [UInt8](repeating: 0, count: 64)
        var rootFD: Int32 = -1
        let received: Int = withUnsafeMutableBytes(of: &status) { statusRaw in
            control.withUnsafeMutableBytes { controlRaw in
                var iov = iovec(iov_base: statusRaw.baseAddress, iov_len: 1)
                return withUnsafeMutablePointer(to: &iov) { iovPointer in
                    var msg = msghdr(
                        msg_name: nil,
                        msg_namelen: 0,
                        msg_iov: iovPointer,
                        msg_iovlen: 1,
                        msg_control: controlRaw.baseAddress,
                        msg_controllen: socklen_t(controlRaw.count),
                        msg_flags: 0
                    )
                    let n = recvmsg(fd, &msg, 0)
                    if n >= 1 {
                        // One cmsghdr with one Int32 descriptor: the header is
                        // 12 bytes on Darwin, and CMSG_DATA is 4-byte aligned
                        // directly after it.
                        let headerSize = MemoryLayout<cmsghdr>.size
                        let base = controlRaw.baseAddress!
                        let header = base.assumingMemoryBound(to: cmsghdr.self).pointee
                        if Int(msg.msg_controllen) >= headerSize + MemoryLayout<Int32>.size,
                           header.cmsg_level == SOL_SOCKET,
                           header.cmsg_type == SCM_RIGHTS,
                           Int(header.cmsg_len) >= headerSize + MemoryLayout<Int32>.size {
                            rootFD = base.advanced(by: headerSize)
                                .assumingMemoryBound(to: Int32.self).pointee
                        }
                    }
                    return n
                }
            }
        }
        guard received >= 1, status == 1, rootFD >= 0 else {
            if rootFD >= 0 { close(rootFD) }
            throw PfsMacOSCoherenceError.posix(operation: "mount-root handoff refused", errno: ENXIO)
        }

        var attested = stat()
        guard fstat(rootFD, &attested) == 0, attested.st_ino == expectedRootFileID else {
            let observed = attested.st_ino
            close(rootFD)
            pfsClientLogger.error(
                "mount-root handoff attestation failed: st_ino \(observed) != expected \(expectedRootFileID)"
            )
            throw PfsMacOSCoherenceError.posix(operation: "attest handed-off mount root", errno: ENXIO)
        }
        return rootFD
    }
}
