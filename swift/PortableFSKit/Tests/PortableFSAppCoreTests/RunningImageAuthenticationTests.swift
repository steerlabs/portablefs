import Darwin
import Foundation
import PortableFSKit
import Security
import Testing
@testable import PortableFSAppCore

// The running-image rule against the real kernel primitive: socket peers are
// real processes, and every verdict comes from csops_audittoken and
// proc_pidpath_audittoken on the captured LOCAL_PEERTOKEN. The listeners are
// ad hoc signed native fixtures, which differ only in their code
// signatures, so a CodeDirectory hash names exactly one of them.

private typealias Coordinator = PortableFSDServiceCoordinator

@_silgen_name("csops_audittoken")
private func fixtureCSOps(
    _ pid: pid_t,
    _ operation: UInt32,
    _ buffer: UnsafeMutableRawPointer?,
    _ size: Int,
    _ token: UnsafeMutablePointer<audit_token_t>
) -> Int32

/// These tests spawn listener processes and bind sockets, so they run one at
/// a time.
@Suite(.serialized)
struct PortableFSDRunningImageTests {}

private enum RunningImageFixtureError: Error {
    case command(String)
    case listenerDidNotStart(String)
    case signingInformation
}

private func run(_ executable: String, _ arguments: [String]) throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    let output = Pipe()
    process.standardOutput = output
    process.standardError = output
    try process.run()
    let diagnostics = output.fileHandleForReading.readDataToEndOfFile()
    process.waitUntilExit()
    guard process.terminationStatus == 0 else {
        throw RunningImageFixtureError.command(
            "\(executable) \(arguments.joined(separator: " ")): status=\(process.terminationStatus) " +
            String(decoding: diagnostics.prefix(8_192), as: UTF8.self)
        )
    }
}

/// Sign code built for the same supported architecture as the test process.
/// System utilities can use arm64e slices and platform launch policy that an
/// ad hoc fixture does not own, particularly on virtualized macOS hosts.
private func signedListenerImage(at url: URL, identifier: String, hardenedRuntime: Bool = true) throws {
    try FileManager.default.copyItem(at: url.deletingLastPathComponent().appendingPathComponent("listener"), to: url)
    var arguments = ["-f", "-s", "-", "-i", identifier]
    if hardenedRuntime { arguments += ["-o", "runtime"] }
    try run("/usr/bin/codesign", arguments + [url.path])
    var code: SecStaticCode?
    var information: CFDictionary?
    let created = SecStaticCodeCreateWithPath(url as CFURL, SecCSFlags(), &code)
    let staticCode = try #require(code, "fixture SecStaticCode status=\(created)")
    try #require(SecStaticCodeCheckValidity(staticCode, SecCSFlags(), nil) == errSecSuccess)
    let status = SecCodeCopySigningInformation(staticCode, SecCSFlags(rawValue: kSecCSSigningInformation), &information)
    let flags = try #require((information as? [CFString: Any])?[kSecCodeInfoFlags] as? UInt32,
                             "fixture signing flags status=\(status)")
    try #require((flags & Coordinator.hardenedRuntimeFlag != 0) == hardenedRuntime)
}

/// The static CodeDirectory hash a release check would derive from disk.
private func staticCDHash(_ url: URL) throws -> String {
    var code: SecStaticCode?
    var information: CFDictionary?
    guard SecStaticCodeCreateWithPath(url as CFURL, SecCSFlags(), &code) == errSecSuccess,
          let code,
          SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
          let unique = (information as? [CFString: Any])?[kSecCodeInfoUnique] as? Data else {
        throw RunningImageFixtureError.signingInformation
    }
    return unique.map { String(format: "%02x", $0) }.joined()
}

private final class Listener {
    let process: Process
    let image: URL
    let socket: String

    init(image: URL, socket: String) throws {
        self.image = image
        self.socket = socket
        process = Process()
        process.executableURL = image
        process.arguments = [socket]
        let ready = Pipe()
        process.standardOutput = ready
        process.standardError = ready
        try process.run()
        var descriptor = pollfd(fd: ready.fileHandleForReading.fileDescriptor, events: Int16(POLLIN), revents: 0)
        let result = Darwin.poll(&descriptor, 1, 5_000)
        let message = result > 0 ? try ready.fileHandleForReading.read(upToCount: 1) : nil
        guard message == Data("R".utf8) else {
            stop()
            let diagnostics = (message ?? Data()) + ready.fileHandleForReading.readDataToEndOfFile()
            throw RunningImageFixtureError.listenerDidNotStart(
                "\(image.path): poll=\(result) reason=\(process.terminationReason.rawValue) " +
                "status=\(process.terminationStatus) output=\(String(decoding: diagnostics.prefix(8_192), as: UTF8.self))"
            )
        }
    }

    func stop() {
        if process.isRunning {
            process.terminate()
            process.waitUntilExit()
        }
    }

    deinit { stop() }
}

/// Unix socket paths must fit sockaddr_un, so fixtures live under /tmp. The
/// kernel reports executable paths through the /private/tmp realpath.
private func withRunningImageFixture(_ body: (URL) throws -> Void) throws {
    var template = Array("/tmp/pfs-image.XXXXXX".utf8CString)
    guard let created = Darwin.mkdtemp(&template),
          let real = Darwin.realpath(created, nil) else {
        throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
    let root = URL(fileURLWithPath: String(cString: real), isDirectory: true)
    free(real)
    defer { try? FileManager.default.removeItem(at: root) }
    let source = try #require(Bundle.module.url(forResource: "running-image-listener", withExtension: "c", subdirectory: "Fixtures"))
    #if arch(arm64)
    let architecture = "arm64"
    #else
    let architecture = "x86_64"
    #endif
    try run("/usr/bin/xcrun", ["--sdk", "macosx", "clang", "-arch", architecture,
                              "-Wall", "-Wextra", "-Werror", source.path,
                              "-o", root.appendingPathComponent("listener").path])
    try body(root)
}

private func kernelSigningInformation(_ peer: Coordinator.DaemonPeer) throws -> (flags: UInt32, cdhash: String) {
    var token = peer.auditToken
    var flags: UInt32 = 0
    let status = fixtureCSOps(peer.processWitness.pid, 0, &flags, MemoryLayout<UInt32>.size, &token)
    try #require(status == 0, "fixture CS_OPS_STATUS result=\(status) errno=\(errno)")
    var cdhash = [UInt8](repeating: 0, count: 20)
    let hashStatus = fixtureCSOps(peer.processWitness.pid, 5, &cdhash, cdhash.count, &token)
    try #require(hashStatus == 0, "fixture CS_OPS_CDHASH result=\(hashStatus) errno=\(errno) flags=\(String(flags, radix: 16))")
    return (flags, cdhash.map { String(format: "%02x", $0) }.joined())
}

private func capturePeer(_ listener: Listener, hardenedRuntime: Bool = true) throws -> (Int32, Coordinator.DaemonPeer) {
    let fd = try PfsUnixSocket.connect(path: listener.socket)
    do {
        let peer = try Coordinator.captureDaemonPeer(fd)
        // A negative runtime verdict must not pass because of an unrelated
        // bad hash, path, or invalid signature. Prove those premises first.
        try #require(peer.executableURL.path == listener.image.path)
        let signing = try kernelSigningInformation(peer)
        try #require(signing.flags & 1 != 0, "fixture lacks CS_VALID: flags=\(String(signing.flags, radix: 16))")
        try #require((signing.flags & Coordinator.hardenedRuntimeFlag != 0) == hardenedRuntime,
                     "fixture runtime mismatch: flags=\(String(signing.flags, radix: 16))")
        let expectedHash = try staticCDHash(listener.image)
        try #require(signing.cdhash == expectedHash)
        return (fd, peer)
    } catch {
        PfsUnixSocket.close(fd)
        throw error
    }
}

private func authenticates(
    _ peer: Coordinator.DaemonPeer,
    path: String,
    cdhash: String
) -> Bool {
    (try? Coordinator.requireRunningImage(peer, expectedPath: path, expectedCDHash: cdhash)) != nil
}

extension PortableFSDRunningImageTests {
/// The exact running image at the exact path authenticates. A different
/// CodeDirectory hash, a different path, a stale pid version or a departed
/// execution refuses, before any request reaches the peer.
@Test func runningImageAuthenticatesOnlyTheExactExecution() throws {
    try withRunningImageFixture { root in
        let image = root.appendingPathComponent("portablefsd")
        let other = root.appendingPathComponent("other")
        try signedListenerImage(at: image, identifier: "dev.portablefs.test.daemon-a")
        try signedListenerImage(at: other, identifier: "dev.portablefs.test.daemon-b")
        let cdhash = try staticCDHash(image)
        let otherCDHash = try staticCDHash(other)
        #expect(cdhash != otherCDHash)

        let listener = try Listener(image: image, socket: root.appendingPathComponent("s").path)
        defer { listener.stop() }
        let (fd, peer) = try capturePeer(listener)
        defer { PfsUnixSocket.close(fd) }
        #expect(peer.executableURL.path == image.path)

        try Coordinator.requireRunningImage(peer, expectedPath: image.path, expectedCDHash: cdhash)
        #expect(!authenticates(peer, path: image.path, cdhash: otherCDHash))
        #expect(!authenticates(peer, path: other.path, cdhash: cdhash))
        #expect(!authenticates(peer, path: image.path, cdhash: String(repeating: "0", count: 40)))

        var otherUID = peer.auditToken
        otherUID.val.1 = geteuid() &+ 1
        #expect(!authenticates(Coordinator.DaemonPeer(
            auditToken: otherUID,
            executableURL: peer.executableURL,
            processWitness: peer.processWitness
        ), path: image.path, cdhash: cdhash))

        // The kernel refuses a token whose pid version names no live
        // execution, even with a witness built to agree with it.
        var stale = peer.auditToken
        stale.val.7 &+= 1
        let staleWitness = try Coordinator.DaemonProcessWitness(
            pid: peer.processWitness.pid,
            pidVersion: Int32(bitPattern: stale.val.7)
        )
        let stalePeer = Coordinator.DaemonPeer(
            auditToken: stale,
            executableURL: peer.executableURL,
            processWitness: staleWitness
        )
        #expect(!authenticates(stalePeer, path: image.path, cdhash: cdhash))

        listener.stop()
        #expect(!authenticates(peer, path: image.path, cdhash: cdhash))
    }
}

/// Renaming an authenticated image B over the path of running image A does
/// not make A authenticate as B: the kernel answers from A's running text,
/// while the release check derives B's hash from the file now at that path.
@Test func runningImageRefusesARenameSubstitution() throws {
    try withRunningImageFixture { root in
        let image = root.appendingPathComponent("portablefsd")
        let replacement = root.appendingPathComponent("replacement")
        try signedListenerImage(at: image, identifier: "dev.portablefs.test.daemon-a")
        try signedListenerImage(at: replacement, identifier: "dev.portablefs.test.daemon-b")
        let listener = try Listener(image: image, socket: root.appendingPathComponent("s").path)
        defer { listener.stop() }

        let (fd, peer) = try capturePeer(listener)
        defer { PfsUnixSocket.close(fd) }
        let original = try staticCDHash(image)
        try Coordinator.requireRunningImage(peer, expectedPath: image.path, expectedCDHash: original)

        try #require(Darwin.rename(replacement.path, image.path) == 0, "rename errno=\(errno)")
        let installed = try staticCDHash(image)
        #expect(installed != original)
        #expect(try kernelSigningInformation(peer).cdhash == original)
        #expect(!authenticates(peer, path: image.path, cdhash: installed))
    }
}

/// Validly signed code without the hardened runtime is not the shipping
/// daemon, even at the right path with the right hash.
@Test func runningImageRequiresHardenedRuntimeCode() throws {
    try withRunningImageFixture { root in
        let image = root.appendingPathComponent("portablefsd")
        try signedListenerImage(
            at: image,
            identifier: "dev.portablefs.test.no-runtime",
            hardenedRuntime: false
        )
        let cdhash = try staticCDHash(image)
        let listener = try Listener(image: image, socket: root.appendingPathComponent("s").path)
        defer { listener.stop() }
        let (fd, peer) = try capturePeer(listener, hardenedRuntime: false)
        defer { PfsUnixSocket.close(fd) }
        #expect(!authenticates(peer, path: image.path, cdhash: cdhash))
    }
}
}
