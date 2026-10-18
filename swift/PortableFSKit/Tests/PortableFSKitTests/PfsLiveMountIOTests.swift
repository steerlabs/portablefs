import CryptoKit
import Foundation
import Testing
@preconcurrency import Darwin

// Native syscall I/O through a live PortableFS FSKit mount. The suite runs
// only when PFS_LIVE_MOUNT_PATH names the canonical mount point and
// PFS_LIVE_ATTACH_REF its attach reference; otherwise it returns without
// asserting anything. It is the supported-profile home of the I/O matrix the
// deleted macOS 27 qualification app carried: create, write, fsync, stat,
// pread, exact enumeration, rename identity, reopen and open-after-unlink,
// plus the write-only and chmod-after-open descriptor boundaries and the
// buffered-write drain at close. It runs the same on macOS 26 and 27.
//
// It distinguishes what a syscall's success establishes from what it does
// not: fsync and close returning 0 mean the kernel delivered its dirty pages
// as FSKit callbacks that the authority acknowledged durably; they do not
// certify pages the kernel never delivered.

private struct LiveMountIdentity: Equatable {
    let type: String
    let source: String
    let mountPoint: String
    let fileSystemID: String
}

private enum LiveIOFailure: Error, CustomStringConvertible {
    case posix(String, Int32)
    case invalid(String)

    var description: String {
        switch self {
        case let .posix(operation, code):
            return "\(operation): errno \(code) (\(String(cString: strerror(code))))"
        case let .invalid(message):
            return message
        }
    }
}

private func posixFailure(_ operation: String) -> LiveIOFailure {
    .posix(operation, errno)
}

private func fixedCString<T>(_ value: T) -> String {
    withUnsafeBytes(of: value) { raw in
        String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self)
    }
}

private func mountIdentity(_ status: statfs) -> LiveMountIdentity {
    LiveMountIdentity(
        type: fixedCString(status.f_fstypename),
        source: fixedCString(status.f_mntfromname),
        mountPoint: fixedCString(status.f_mntonname),
        fileSystemID: withUnsafeBytes(of: status.f_fsid) { bytes in
            bytes.map { String(format: "%02x", $0) }.joined()
        }
    )
}

private func pathMountIdentity(_ path: String) throws -> LiveMountIdentity {
    var status = statfs()
    guard statfs(path, &status) == 0 else { throw posixFailure("statfs mount path") }
    return mountIdentity(status)
}

private func descriptorMountIdentity(_ fd: Int32) throws -> LiveMountIdentity {
    var status = statfs()
    guard fstatfs(fd, &status) == 0 else { throw posixFailure("fstatfs mount root") }
    return mountIdentity(status)
}

private func requireExactMount(
    _ identity: LiveMountIdentity,
    mountPath: String,
    attachRef: String
) throws {
    guard identity.type == "pfs",
          identity.source == "dev.portablefs.oss://" + attachRef,
          identity.mountPoint == mountPath else {
        throw LiveIOFailure.invalid("kernel mount identity is not the exact PortableFS attach: \(identity)")
    }
}

private func deterministicPayload(seed: String, count: Int) -> [UInt8] {
    var result: [UInt8] = []
    result.reserveCapacity(count)
    var counter: UInt64 = 0
    while result.count < count {
        var input = Data(seed.utf8)
        var bigEndian = counter.bigEndian
        withUnsafeBytes(of: &bigEndian) { input.append(contentsOf: $0) }
        result.append(contentsOf: SHA256.hash(data: input))
        counter += 1
    }
    return Array(result.prefix(count))
}

private func writeAll(_ fd: Int32, _ bytes: [UInt8]) throws {
    var offset = 0
    while offset < bytes.count {
        let written = bytes.withUnsafeBytes { raw -> Int in
            Darwin.write(fd, raw.baseAddress!.advanced(by: offset), bytes.count - offset)
        }
        if written < 0 {
            if errno == EINTR { continue }
            throw posixFailure("write")
        }
        guard written > 0 else { throw LiveIOFailure.invalid("write made no progress") }
        offset += written
    }
}

/// Reads exactly `count` bytes from offset zero and proves the file has no
/// byte beyond them.
private func preadExactly(_ fd: Int32, count: Int) throws -> [UInt8] {
    var result = [UInt8](repeating: 0, count: count)
    var offset = 0
    while offset < count {
        let amount = result.withUnsafeMutableBytes { raw -> Int in
            Darwin.pread(fd, raw.baseAddress!.advanced(by: offset), count - offset, off_t(offset))
        }
        if amount < 0 {
            if errno == EINTR { continue }
            throw posixFailure("pread")
        }
        guard amount > 0 else { throw LiveIOFailure.invalid("file ended before its expected size") }
        offset += amount
    }
    var extra: UInt8 = 0
    while true {
        let amount = Darwin.pread(fd, &extra, 1, off_t(count))
        if amount < 0, errno == EINTR { continue }
        if amount < 0 { throw posixFailure("pread boundary") }
        guard amount == 0 else { throw LiveIOFailure.invalid("file is longer than expected") }
        return result
    }
}

private func regularStatus(_ fd: Int32) throws -> stat {
    var status = stat()
    guard fstat(fd, &status) == 0 else { throw posixFailure("fstat") }
    guard status.st_mode & S_IFMT == S_IFREG else { throw LiveIOFailure.invalid("not a regular file") }
    return status
}

private func regularStatus(_ directory: Int32, _ name: String) throws -> stat {
    var status = stat()
    guard fstatat(directory, name, &status, AT_SYMLINK_NOFOLLOW) == 0 else {
        throw posixFailure("fstatat \(name)")
    }
    guard status.st_mode & S_IFMT == S_IFREG else { throw LiveIOFailure.invalid("\(name) is not a regular file") }
    return status
}

private func requireAbsent(_ directory: Int32, _ name: String) throws {
    var status = stat()
    if fstatat(directory, name, &status, AT_SYMLINK_NOFOLLOW) == 0 {
        throw LiveIOFailure.invalid("\(name) is still present")
    }
    guard errno == ENOENT else { throw posixFailure("fstatat absent \(name)") }
}

private func directoryEntries(_ fd: Int32) throws -> Set<String> {
    let duplicate = dup(fd)
    guard duplicate >= 0 else { throw posixFailure("dup directory") }
    guard let stream = fdopendir(duplicate) else {
        close(duplicate)
        throw posixFailure("fdopendir")
    }
    defer { closedir(stream) }
    rewinddir(stream)
    var names = Set<String>()
    while true {
        errno = 0
        guard let entry = readdir(stream) else {
            guard errno == 0 else { throw posixFailure("readdir") }
            return names
        }
        names.insert(fixedCString(entry.pointee.d_name))
    }
}

private func sameObject(_ left: stat, _ right: stat) -> Bool {
    left.st_dev == right.st_dev && left.st_ino == right.st_ino
}

@Test func liveMountNativeIOMatrix() throws {
    let environment = ProcessInfo.processInfo.environment
    guard let mountPath = environment["PFS_LIVE_MOUNT_PATH"],
          let attachRef = environment["PFS_LIVE_ATTACH_REF"] else {
        return
    }

    let mountBefore = try pathMountIdentity(mountPath)
    try requireExactMount(mountBefore, mountPath: mountPath, attachRef: attachRef)
    let root = open(mountPath, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    guard root >= 0 else { throw posixFailure("open mount root") }
    defer { close(root) }
    #expect(try descriptorMountIdentity(root) == mountBefore)

    let run = ".portablefs-live-io-\(UUID().uuidString.lowercased())"
    guard mkdirat(root, run, 0o700) == 0 else { throw posixFailure("mkdirat run directory") }
    let directory = openat(root, run, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    guard directory >= 0 else { throw posixFailure("open run directory") }
    defer {
        for name in ["original.bin", "renamed.bin", "write-only.bin", "chmod.bin", "drained.bin", "xattr.bin", "._xattr.bin"] {
            _ = unlinkat(directory, name, 0)
        }
        close(directory)
        _ = unlinkat(root, run, AT_REMOVEDIR)
    }

    // Create, write, fsync, stat and pread through one descriptor.
    let payload = deterministicPayload(seed: run, count: 128 * 1_024)
    let output = openat(directory, "original.bin", O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o600)
    guard output >= 0 else { throw posixFailure("create original.bin") }
    defer { close(output) }
    try writeAll(output, payload)
    #expect(fsync(output) == 0, "fsync failed: errno \(errno)")
    // F_FULLFSYNC asks for the device-cache flush. Either it succeeds or it is
    // refused as unsupported; any other failure is a real I/O failure.
    if fcntl(output, F_FULLFSYNC) != 0 {
        #expect([ENOTSUP, EINVAL, ENOTTY].contains(errno), "F_FULLFSYNC failed: errno \(errno)")
    }
    let opened = try regularStatus(output)
    #expect(opened.st_size == off_t(payload.count))
    #expect(opened.st_mode & 0o777 == 0o600)
    #expect(sameObject(opened, try regularStatus(directory, "original.bin")))
    #expect(try preadExactly(output, count: payload.count) == payload)
    #expect(try directoryEntries(directory) == [".", "..", "original.bin"])

    // Rename keeps the object; reopen sees its bytes.
    guard renameat(directory, "original.bin", directory, "renamed.bin") == 0 else {
        throw posixFailure("renameat")
    }
    try requireAbsent(directory, "original.bin")
    #expect(sameObject(opened, try regularStatus(directory, "renamed.bin")))
    let reopened = openat(directory, "renamed.bin", O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    guard reopened >= 0 else { throw posixFailure("reopen renamed.bin") }
    defer { close(reopened) }
    #expect(try preadExactly(reopened, count: payload.count) == payload)

    // Open after unlink keeps reading the same object.
    guard unlinkat(directory, "renamed.bin", 0) == 0 else { throw posixFailure("unlink open file") }
    try requireAbsent(directory, "renamed.bin")
    #expect(try preadExactly(reopened, count: payload.count) == payload)

    // A write-only 0200 file is writable through its creation description and
    // a later write-only open, and unreadable by a new read open.
    let writeOnly = openat(directory, "write-only.bin", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o200)
    guard writeOnly >= 0 else { throw posixFailure("create write-only.bin") }
    try writeAll(writeOnly, Array("first".utf8))
    #expect(close(writeOnly) == 0)
    let writeAgain = openat(directory, "write-only.bin", O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW)
    guard writeAgain >= 0 else { throw posixFailure("reopen write-only.bin for writing") }
    try writeAll(writeAgain, Array("-second".utf8))
    #expect(fsync(writeAgain) == 0)
    #expect(close(writeAgain) == 0)
    let unreadable = openat(directory, "write-only.bin", O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    let unreadableErrno = errno
    if unreadable >= 0 { close(unreadable) }
    #expect(unreadable < 0 && unreadableErrno == EACCES)
    #expect(try regularStatus(directory, "write-only.bin").st_size == off_t("first-second".utf8.count))

    // chmod after open does not revoke an existing write description.
    let chmodded = openat(directory, "chmod.bin", O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o600)
    guard chmodded >= 0 else { throw posixFailure("create chmod.bin") }
    #expect(fchmod(chmodded, 0o400) == 0)
    try writeAll(chmodded, Array("still-writable".utf8))
    #expect(fsync(chmodded) == 0)
    #expect(close(chmodded) == 0)
    #expect(try regularStatus(directory, "chmod.bin").st_size == off_t("still-writable".utf8.count))

    // Buffered writes with no explicit fsync are delivered by close: a fresh
    // descriptor reads every byte back.
    let drainedPayload = deterministicPayload(seed: run + "-drained", count: 3 * 1_024 * 1_024 + 17)
    let drained = openat(directory, "drained.bin", O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o644)
    guard drained >= 0 else { throw posixFailure("create drained.bin") }
    try writeAll(drained, drainedPayload)
    #expect(close(drained) == 0, "close of a dirty file failed: errno \(errno)")
    let drainedReader = openat(directory, "drained.bin", O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    guard drainedReader >= 0 else { throw posixFailure("reopen drained.bin") }
    defer { close(drainedReader) }
    #expect(try preadExactly(drainedReader, count: drainedPayload.count) == drainedPayload)

    // User xattrs are read-only: setxattr is refused with EOPNOTSUPP and the
    // VFS never falls back to an AppleDouble sidecar.
    let xattrFile = openat(directory, "xattr.bin", O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o644)
    guard xattrFile >= 0 else { throw posixFailure("create xattr.bin") }
    #expect(close(xattrFile) == 0)
    let value = Array("refused".utf8)
    let setResult = "\(mountPath)/\(run)/xattr.bin".withCString { path in
        value.withUnsafeBytes { raw in
            setxattr(path, "user.portablefs.live", raw.baseAddress, raw.count, 0, 0)
        }
    }
    #expect(setResult == -1 && errno == EOPNOTSUPP)
    try requireAbsent(directory, "._xattr.bin")

    for name in ["write-only.bin", "chmod.bin", "drained.bin", "xattr.bin"] {
        #expect(unlinkat(directory, name, 0) == 0)
    }
    #expect(try directoryEntries(directory) == [".", ".."])
    #expect(try descriptorMountIdentity(root) == mountBefore)
    #expect(try pathMountIdentity(mountPath) == mountBefore)
}
