import Foundation
import CryptoKit
import Darwin
import Testing
@testable import PortableFSWorkspaceVM

private func temporaryDirectory() throws -> URL {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("workspace-vm-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
    return directory
}

@Suite struct WorkspaceArtifactTests {
    private func artifact(_ directory: URL) throws {
        let names = ["kernel", "initramfs", "system.ext4", "kernel.config", "packages.json", "packages.tsv", "source-manifest.json", "licenses.tar.gz", "initramfs.inventory", "image-inputs.json", "release.json", "bin/portablefs", "bin/portablefsd", "bin/portablefs-workspaced"]
        let inputs = Data("exact-inputs".utf8)
        let release: [String: Any] = ["app_version":"dev", "commit":String(repeating:"a",count:40), "image_digest":hex(Data(SHA256.hash(data:inputs))), "authority_major":8]
        var files: [String: Any] = [:]
        try FileManager.default.createDirectory(at: directory.appendingPathComponent("bin"), withIntermediateDirectories: true)
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
        try Data("corruption".utf8).write(to:directory.appendingPathComponent("kernel"))
        #expect(throws: (any Error).self) { try WorkspaceArtifact(directory:directory) }
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
    @MainActor @Test func transportWorkerLeavesOwnerQueueAndReturns() async throws {
        let value: Bool = try await withCheckedThrowingContinuation { continuation in
            WorkspaceIO({ !Thread.isMainThread }, completion: { result in
                #expect(Thread.isMainThread)
                continuation.resume(with: result)
            }).start()
        }
        #expect(value)
    }
    @Test func socketPartialFrameAndEOF() throws {
        var fds: [Int32] = [-1,-1]
        #expect(socketpair(AF_UNIX,SOCK_STREAM,0,&fds) == 0)
        defer { close(fds[0]); close(fds[1]) }
        let data = Data([0,0,0,2,8,8])
        try WorkspaceSocket.write(fds[0],data:data,deadline:clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)+1_000_000_000)
        #expect(try WorkspaceSocket.read(fds[1],count:4,deadline:clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)+1_000_000_000) == data.prefix(4))
        #expect(try WorkspaceSocket.read(fds[1],count:2,deadline:clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)+1_000_000_000) == data.suffix(2))
        shutdown(fds[0],SHUT_WR)
        #expect(throws: (any Error).self) { try WorkspaceSocket.read(fds[1],count:1,deadline:clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)+1_000_000_000) }
    }
    @Test func expiredSocketDeadlineRefused() throws {
        #expect(throws: (any Error).self) { try WorkspaceSocket.read(-1,count:1,deadline:0) }
    }
    @Test func persistentHostPinAndExclusiveOwner() throws {
        let directory = try temporaryDirectory(); defer { try? FileManager.default.removeItem(at:directory) }
        let state = try WorkspaceDevState(directory:directory)
        #expect(throws: (any Error).self) { try WorkspaceDevState(directory:directory) }
        let key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIexample"
        _ = try state.pin(hostKey:key,port:12345)
        _ = try state.pin(hostKey:key,port:23456)
        #expect(throws: (any Error).self) { try state.pin(hostKey:key+"changed",port:23456) }
        let config = try String(contentsOf:directory.appendingPathComponent("ssh_config"),encoding:.utf8)
        #expect(config.contains("HostName 127.0.0.1")); #expect(config.contains("StrictHostKeyChecking yes"))
        #expect(!config.contains("PRIVATE KEY"))
        withExtendedLifetime(state) {}
    }
}
