import Darwin
import Foundation
import PortableFSKit
import Security
import Testing
@testable import PortableFSAppCore

// The running-image rule against the real kernel primitive: socket peers are
// real processes, and every verdict comes from csops_audittoken and
// proc_pidpath_audittoken on the captured LOCAL_PEERTOKEN. The listeners are
// ad hoc signed copies of /usr/bin/nc, which differ only in their code
// signatures, so a CodeDirectory hash names exactly one of them.

private typealias Coordinator = PortableFSDServiceCoordinator

/// These tests spawn listener processes and bind sockets, so they run one at
/// a time.
@Suite(.serialized)
struct PortableFSDRunningImageTests {}

private enum RunningImageFixtureError: Error {
    case command(String)
    case listenerDidNotStart
    case signingInformation
}

private func run(_ executable: String, _ arguments: [String]) throws {
    let process = Process()
    process.executableURL = URL(fileURLWithPath: executable)
    process.arguments = arguments
    process.standardOutput = FileHandle.nullDevice
    process.standardError = FileHandle.nullDevice
    try process.run()
    process.waitUntilExit()
    guard process.terminationStatus == 0 else {
        throw RunningImageFixtureError.command("\(executable) \(arguments.joined(separator: " "))")
    }
}

/// A distinct, ad hoc signed copy of nc. `identifier` changes the signature
/// and therefore the CodeDirectory hash; `hardenedRuntime` sets CS_RUNTIME.
private func signedListenerImage(at url: URL, identifier: String, hardenedRuntime: Bool = true) throws {
    try? FileManager.default.removeItem(at: url)
    // One slice, the one this machine's kernel runs, so the static hash and
    // the running image's hash describe the same code.
    #if arch(arm64)
    let slice = "arm64e"
    #else
    let slice = "x86_64"
    #endif
    try run("/usr/bin/lipo", ["/usr/bin/nc", "-thin", slice, "-output", url.path])
    var arguments = ["-f", "-s", "-", "-i", identifier]
    if hardenedRuntime { arguments += ["-o", "runtime"] }
    try run("/usr/bin/codesign", arguments + [url.path])
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
    let input = Pipe()
    let socket: String

    init(image: URL, socket: String) throws {
        self.socket = socket
        process = Process()
        process.executableURL = image
        process.arguments = ["-lU", socket]
        process.standardInput = input
        process.standardOutput = FileHandle.nullDevice
        process.standardError = FileHandle.nullDevice
        try process.run()
        let deadline = Date().addingTimeInterval(5)
        while !FileManager.default.fileExists(atPath: socket) {
            guard Date() < deadline, process.isRunning else {
                stop()
                throw RunningImageFixtureError.listenerDidNotStart
            }
            Thread.sleep(forTimeInterval: 0.01)
        }
    }

    func stop() {
        if process.isRunning {
            process.terminate()
            process.waitUntilExit()
        }
        try? input.fileHandleForWriting.close()
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
    try body(root)
}

private func capturePeer(_ listener: Listener) throws -> (Int32, Coordinator.DaemonPeer) {
    let fd = try PfsUnixSocket.connect(path: listener.socket)
    do {
        return (fd, try Coordinator.captureDaemonPeer(fd))
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

        #expect(authenticates(peer, path: image.path, cdhash: cdhash))
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
        #expect(authenticates(peer, path: image.path, cdhash: try staticCDHash(image)))

        #expect(Darwin.rename(replacement.path, image.path) == 0)
        let installed = try staticCDHash(image)
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
        let (fd, peer) = try capturePeer(listener)
        defer { PfsUnixSocket.close(fd) }
        #expect(!authenticates(peer, path: image.path, cdhash: cdhash))
    }
}
}
