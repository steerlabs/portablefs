import Foundation
import CryptoKit
import Darwin
import Testing
import PortableFSWorkspaceCore
@testable import PortableFSWorkspaceVM

private func temporaryDirectory() throws -> URL {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("workspace-vm-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    return directory
}

@Test @MainActor func workspaceRequestEncodingChargesFIFOResidenceAndRefusesExpiry() throws {
    let request = try WorkspaceControl.decode(workspaceGolden("suspend")).suspend
    let deadline: UInt64 = 15_000_001_000
    for now: UInt64 in [1_000, 7_000_001_000, deadline - 1] {
        let raw = try WorkspaceVsockChannel.encodeRequest(.suspend(request), requestID: 9, deadline: deadline, now: now)
        let envelope = try WorkspaceControl.decode(raw)
        #expect(envelope.drainBudgetNanos == deadline - now)
        #expect(envelope.suspend == request)
        #expect(envelope.requestID == 9)
    }
    for now in [deadline, deadline + 1, UInt64.max] {
        #expect(throws: (any Error).self) { try WorkspaceVsockChannel.encodeRequest(.suspend(request), requestID: 9, deadline: deadline, now: now) }
    }
    let status = try WorkspaceVsockChannel.encodeRequest(.status(WorkspaceStatusRequest()), requestID: 10, deadline: UInt64.max, now: UInt64.max - 1)
    #expect(try WorkspaceControl.decode(status).drainBudgetNanos == 0)
    #expect(throws: (any Error).self) { try WorkspaceVsockChannel.encodeRequest(.suspend(request), requestID: 9, deadline: deadline + 1, now: 1_000) }
}

@Suite struct WorkspaceArtifactTests {
    private func artifact(_ directory: URL) throws {
        let names = ["kernel", "initramfs", "system.ext4", "kernel.config", "packages.json", "packages.tsv", "source-manifest.json", "licenses.tar.gz", "initramfs.inventory", "image-inputs.json", "release.json", "bin/portablefs", "bin/portablefsd", "bin/portablefs-workspaced"]
        let inputs = Data("exact-inputs".utf8)
        let release: [String: Any] = ["app_version":"dev", "commit":String(repeating:"a",count:40), "image_digest":hex(Data(SHA256.hash(data:inputs))), "authority_major":8]
        var files: [String: Any] = [:]
        try FileManager.default.createDirectory(at: directory.appendingPathComponent("bin"), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        for name in names {
            let data = name == "release.json" ? try JSONSerialization.data(withJSONObject:release) : (name == "image-inputs.json" ? inputs : Data(name.utf8))
            try data.write(to:directory.appendingPathComponent(name))
            files[name] = ["sha256":hex(Data(SHA256.hash(data:data))), "size":data.count]
        }
        try JSONSerialization.data(withJSONObject:["format":8,"release":release,"files":files]).write(to:directory.appendingPathComponent("manifest.json"))
    }
    @Test func exactArtifactAndCorruption() throws {
        let directory = try temporaryDirectory(); defer { try? FileManager.default.removeItem(at:directory) }
        try artifact(directory)
        #expect(try WorkspaceArtifact(directory:directory).release.authorityMajor == 8)
        try Data("xxxxxx".utf8).write(to:directory.appendingPathComponent("kernel"))
        do { _ = try WorkspaceArtifact(directory: directory); Issue.record("corrupt artifact accepted") }
        catch let error as WorkspaceVMError { #expect(error.description == "artifact hash mismatch: kernel") }
    }
    @Test func manifestCannotNameExtraPaths() throws {
        let directory = try temporaryDirectory(); defer { try? FileManager.default.removeItem(at:directory) }
        try artifact(directory)
        let path = directory.appendingPathComponent("manifest.json")
        var value = try #require(JSONSerialization.jsonObject(with:Data(contentsOf:path)) as? [String:Any])
        var files = try #require(value["files"] as? [String:Any]); files["../outside"] = ["sha256":"bad","size":1]; value["files"] = files
        try JSONSerialization.data(withJSONObject:value).write(to:path)
        #expect(throws: (any Error).self) { try WorkspaceArtifact(directory:directory) }
    }
    @Test func artifactSymlinkRefused() throws {
        let directory = try temporaryDirectory(); defer { try? FileManager.default.removeItem(at:directory) }
        try artifact(directory)
        let kernel = directory.appendingPathComponent("kernel")
        try FileManager.default.moveItem(at:kernel,to:directory.appendingPathComponent("target"))
        try FileManager.default.createSymbolicLink(atPath:kernel.path,withDestinationPath:"target")
        #expect(throws: (any Error).self) { try WorkspaceArtifact(directory:directory) }
    }
}

@Suite(.serialized) struct WorkspaceSocketAndIdentityTests {
    @Test @MainActor func nonblockingStreamPartialFrameAndEOF() async throws {
        var fds: [Int32] = [-1,-1]
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)
        defer { close(fds[0]); close(fds[1]) }
        let stream = try WorkspaceStream(fd: fds[1], label: "workspace.test", onLost: { _ in })
        defer { stream.close() }
        let data = Data([0,0,0,2,8,8])
        _ = data.withUnsafeBytes { Darwin.write(fds[0], $0.baseAddress, $0.count) }
        let first: Data = try await withCheckedThrowingContinuation { continuation in
            stream.read(count: 4, deadline: clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)+1_000_000_000) { continuation.resume(with: $0) }
        }
        #expect(first == data.prefix(4))
        let second: Data = try await withCheckedThrowingContinuation { continuation in
            stream.read(count: 2, deadline: clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)+1_000_000_000) { continuation.resume(with: $0) }
        }
        #expect(second == data.suffix(2))
        shutdown(fds[0], SHUT_WR)
        do {
            let _: Data = try await withCheckedThrowingContinuation { continuation in
                stream.read(count: 1, deadline: clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)+1_000_000_000) { continuation.resume(with: $0) }
            }
            Issue.record("EOF accepted as data")
        } catch {}
    }
    @Test @MainActor func finalBufferedFrameSurvivesImmediatePeerEOF() async throws {
        var fds: [Int32] = [-1,-1]
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)
        defer { close(fds[0]); close(fds[1]) }
        let stream = try WorkspaceStream(fd: fds[1], label: "workspace.test.final-frame", onLost: { _ in })
        defer { stream.close() }
        let frame = Data([0,0,0,2,8,8])
        _ = frame.withUnsafeBytes { Darwin.write(fds[0], $0.baseAddress, $0.count) }
        shutdown(fds[0], SHUT_WR)
        let header: Data = try await withCheckedThrowingContinuation { continuation in
            stream.read(count: 4, deadline: clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)+1_000_000_000) { continuation.resume(with: $0) }
        }
        #expect(header == frame.prefix(4))
        let body: Data = try await withCheckedThrowingContinuation { continuation in
            stream.read(count: 2, deadline: clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)+1_000_000_000) { continuation.resume(with: $0) }
        }
        #expect(body == frame.suffix(2))
    }
    @Test @MainActor func idleRelaysCannotStarveControlStream() async throws {
        var relays: [WorkspaceRelay] = []; var peers: [Int32] = []
        defer { relays.forEach { $0.close() }; peers.forEach { close($0) } }
        for _ in 0..<64 {
            var client: [Int32] = [-1,-1]; var guest: [Int32] = [-1,-1]
            #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &client) == 0)
            #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &guest) == 0)
            relays.append(try WorkspaceRelay(client: client[0], guest: guest[0], completion: {}))
            close(guest[0]); peers += [client[1], guest[1]]
        }
        var control: [Int32] = [-1,-1]
        #expect(socketpair(AF_UNIX, SOCK_STREAM, 0, &control) == 0)
        defer { close(control[0]); close(control[1]) }
        let stream = try WorkspaceStream(fd: control[1], label: "workspace.test.control", onLost: { _ in })
        defer { stream.close() }
        var byte: UInt8 = 42; #expect(Darwin.write(control[0], &byte, 1) == 1)
        let reply: Data = try await withCheckedThrowingContinuation { continuation in
            stream.read(count: 1, deadline: clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)+1_000_000_000) { continuation.resume(with: $0) }
        }
        #expect(reply == Data([42]))
    }
    @Test func missingClientPublicKeyIsReconstructedFromDurableIdentity() throws {
        let directory = try temporaryDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
        let before: String
        do { let state = try WorkspaceDevState(directory: directory); before = try state.authorizedKey }
        try FileManager.default.removeItem(at: directory.appendingPathComponent("client_ed25519.pub"))
        let reopened = try WorkspaceDevState(directory: directory)
        #expect(try reopened.authorizedKey == before)
        #expect(reopened.formatAuthorized == "8")
        try reopened.formatCompleted()
        #expect(reopened.formatAuthorized.isEmpty)
    }
    @Test func unsafeStateDirectoryRefused() throws {
        let directory = try temporaryDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: directory.path)
        #expect(throws: (any Error).self) { try WorkspaceDevState(directory: directory) }
    }
    @Test func sshConfigEscapesPercentInEveryPath() throws {
        let parent = try temporaryDirectory(); defer { try? FileManager.default.removeItem(at: parent) }
        let directory = parent.appendingPathComponent("literal %h %d")
        let state = try WorkspaceDevState(directory: directory)
        let path = try state.pin(hostKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample")
        let config = try String(contentsOf: path, encoding: .utf8)
        for directive in ["ProxyCommand", "IdentityFile", "UserKnownHostsFile"] {
            let line = try #require(config.split(separator: "\n").first { $0.contains(directive) })
            #expect(line.contains("literal %%h %%d"))
        }
        withExtendedLifetime(state) {}
    }
    @Test func persistentHostPinAndExclusiveOwner() throws {
        let directory = try temporaryDirectory(); defer { try? FileManager.default.removeItem(at:directory) }
        let state = try WorkspaceDevState(directory:directory)
        #expect(throws: (any Error).self) { try WorkspaceDevState(directory:directory) }
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample"
        _ = try state.pin(hostKey:key)
        _ = try state.pin(hostKey:key)
        #expect(throws: (any Error).self) { try state.pin(hostKey:key+"changed") }
        let config = try String(contentsOf:directory.appendingPathComponent("ssh_config"),encoding:.utf8)
        #expect(config.contains("ProxyCommand /usr/bin/nc -U")); #expect(config.contains("StrictHostKeyChecking yes"))
        #expect(!config.contains("PRIVATE KEY"))
        withExtendedLifetime(state) {}
    }
}
