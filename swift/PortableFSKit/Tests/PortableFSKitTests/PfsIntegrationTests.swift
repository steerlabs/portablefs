import Foundation
import Testing
@testable import PortableFSKit
import PortableFSKitMockDaemon
@preconcurrency import Darwin

private func bytes(_ string: String) -> Data {
    Data(string.utf8)
}

extension PfsLocalMockDaemonTests {
/// Every owning Item carries a positive handle and generation and a nonzero
/// 16-byte stable identity. An owning reply without one is a malformed frame,
/// and adoption leaves the item tables untouched. A file ID in the former
/// high-half partition is an ordinary daemon object.
@Test func owningItemsRequireTheirFullIdentity() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let before = await core.testingDebugState()

    func owning(itemID: UInt64, generation: UInt64, identity: Data, fileID: UInt64) -> PfsAttr {
        var attr = PfsAttr()
        attr.item.itemID = itemID
        attr.item.itemGeneration = generation
        attr.item.stableIdentity = identity
        attr.kind = .file
        attr.fileID = fileID
        return attr
    }
    let valid = Data(repeating: 0x7a, count: 16)
    for malformed in [
        owning(itemID: 0, generation: 1, identity: valid, fileID: 40),
        owning(itemID: 41, generation: 0, identity: valid, fileID: 41),
        owning(itemID: 42, generation: 1, identity: Data(), fileID: 42),
        owning(itemID: 43, generation: 1, identity: Data(repeating: 0, count: 16), fileID: 43),
        owning(itemID: 44, generation: 1, identity: Data(repeating: 0x7a, count: 15), fileID: 44),
        owning(itemID: 45, generation: 1, identity: valid, fileID: UInt64.max),
    ] {
        await #expect(throws: PfsLocalClientError.self) {
            _ = try await core.testingAdoptAttributes(malformed)
        }
    }
    #expect(await core.testingDebugState() == before)

    let high = try await core.testingAdoptAttributes(
        owning(itemID: 46, generation: 1, identity: valid, fileID: (UInt64(1) << 63) + 1)
    )
    #expect(high.fileID == (UInt64(1) << 63) + 1)
    await core.shutdown()
}

@Test func volumeCoreRoundTripsAgainstMockDaemon() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }

    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()

    let created = try await core.createFile(in: root, name: bytes("hello.txt"), mode: 0o644)
    let write = try await core.write(item: created.item, offset: 0, data: bytes("hello"))
    #expect(write.written == 5)
    #expect(try await core.read(item: created.item, offset: 0, length: 5) == bytes("hello"))

    try await daemon.seedXattr(named: "user.note", value: bytes("note"), on: created.item.identity)
    #expect(try await core.xattrGet(item: created.item, name: "user.note") == bytes("note"))
    #expect(try await core.xattrList(item: created.item).contains("user.note"))
    try await core.xattrRemove(item: created.item, name: "user.note")

    try await core.rename(
        item: created.item,
        from: root,
        sourceName: bytes("hello.txt"),
        to: root,
        destinationName: bytes("renamed.txt"),
        noReplace: false
    )
    let renamed = try await core.lookup(in: root, name: bytes("renamed.txt"))
    #expect(renamed.attr.size == 5)

    let link = try await core.hardLink(item: renamed.item, in: root, name: bytes("renamed.link"))
    #expect(link.canonicalName == bytes("renamed.link"))
    let linked = try await core.lookup(in: root, name: link.canonicalName)
    #expect(linked.item.identity == renamed.item.identity)
    #expect(linked.attr.nlink == 2)
    try await core.remove(item: renamed.item, named: bytes("renamed.txt"), from: root, isDirectory: false)
    let survivingLink = try await core.lookup(in: root, name: link.canonicalName)
    #expect(survivingLink.item.identity == renamed.item.identity)
    #expect(survivingLink.attr.nlink == 1)
    #expect(try await core.read(item: survivingLink.item, offset: 0, length: 5) == bytes("hello"))

    let symlink = try await core.symlink(in: root, name: bytes("sym"), target: link.canonicalName)
    #expect(try await core.readlink(item: symlink.item) == link.canonicalName)

    var names: [String] = []
    var cookie: UInt64 = 0
    repeat {
        let page = try await core.enumerate(directory: root, startingAt: cookie, wantAttributes: true)
        names.append(contentsOf: page.entries.compactMap { String(data: $0.name, encoding: .utf8) })
        cookie = page.nextCookie
    } while cookie != 0
    #expect(!names.contains("renamed.txt"))
    #expect(names.contains("renamed.link"))
    #expect(names.contains("sym"))

    let stat = try await core.statfs()
    #expect(stat.freeBlocks > 0)

    try await core.reclaim(item: symlink.item)
    do {
        _ = try await core.getattr(item: symlink.item)
        Issue.record("expected reclaimed item to be stale")
    } catch let error as PfsLocalClientError {
        #expect(error.posixErrno == ESTALE)
    }
}

@Test func readWriteChunkingRoundTripsTwentyMiBFile() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }

    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let created = try await core.createFile(in: root, name: bytes("large.bin"), mode: 0o644)
    await daemon.resetStats()

    let size = 20 * 1024 * 1024
    var payload = Data(count: size)
    payload.withUnsafeMutableBytes { rawBuffer in
        guard let base = rawBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
            return
        }
        for index in 0..<size {
            base[index] = UInt8(truncatingIfNeeded: index)
        }
    }

    let written = try await core.write(item: created.item, offset: 0, data: payload)
    #expect(written.written == UInt32(size))
    let readBack = try await core.read(item: created.item, offset: 0, length: UInt32(size))
    #expect(readBack == payload)

    let stats = await daemon.stats()
    #expect(stats.maxWriteLength <= 1_048_576)
    #expect(stats.maxReadLength <= 1_048_576)
}

@Test func volumeCoreGitConfigLockRenameOverRemainsReadable() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }

    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let repo = try await core.mkdir(in: root, name: bytes("repo"), mode: 0o755)
    let git = try await core.mkdir(in: repo.item, name: bytes(".git"), mode: 0o755)

    let oldContent = bytes("[core]\n\trepositoryformatversion = 0\n")
    let newContent = bytes("[core]\n\trepositoryformatversion = 0\n\tfilemode = true\n")

    let config = try await core.createFile(in: git.item, name: bytes("config"), mode: 0o644)
    _ = try await core.write(item: config.item, offset: 0, data: oldContent)
    try await core.close(item: config.item)

    let lock = try await core.createFile(in: git.item, name: bytes("config.lock"), mode: 0o644)
    _ = try await core.write(item: lock.item, offset: 0, data: newContent)
    try await core.close(item: lock.item)

    try await core.rename(
        item: lock.item,
        from: git.item,
        sourceName: bytes("config.lock"),
        to: git.item,
        destinationName: bytes("config"),
        noReplace: false
    )

    let replaced = try await core.lookup(in: git.item, name: bytes("config"))
    try await core.open(item: replaced.item, mode: .read)
    let readBack = try await core.read(item: replaced.item, offset: 0, length: UInt32(newContent.count))
    try await core.close(item: replaced.item)
    #expect(readBack == newContent)
}

@Test func clientMultiplexesOutOfOrderReplies() async throws {
    let daemon = try PfsLocalMockDaemon(configuration: .init(lookupDelaysNanoseconds: ["slow": 200_000_000]))
    defer { daemon.stop() }

    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    _ = try await core.createFile(in: root, name: bytes("slow"), mode: 0o644)
    _ = try await core.createFile(in: root, name: bytes("fast"), mode: 0o644)

    try await withThrowingTaskGroup(of: String.self) { group in
        group.addTask {
            _ = try await core.lookup(in: root, name: bytes("slow"))
            return "slow"
        }
        group.addTask {
            _ = try await core.lookup(in: root, name: bytes("fast"))
            return "fast"
        }
        let first = try await group.next()
        #expect(first == "fast")
        _ = try await group.next()
    }
}

@Test func detachingAttachStateMakesBoundClientFailWithENXIO() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }

    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    _ = try await core.subscribeEvents()

    daemon.emitAttachState(.detaching, detail: "detaching")
    try await Task.sleep(nanoseconds: 50_000_000)

    do {
        _ = try await core.statfs()
        Issue.record("expected detaching attach to fail future operations")
    } catch {
        #expect(PfsErrorMapper.fsKitError(for: error).code == Int(ENXIO))
    }
}

@Test func itemTableRejectsOwnershipHandleReuse() async throws {
    let core = VolumeCore(client: PfsLocalClient(socketPath: "/unused-identity-test"))
    var attr = PfsAttr()
    attr.item.itemID = 99
    attr.item.itemGeneration = 1
    attr.item.stableIdentity = Data(repeating: 0x63, count: 16)
    attr.fileID = 99
    attr.kind = .file
    let item = try await core.testingAdoptAttributes(attr)
    attr.item.itemGeneration = 2
    await #expect(throws: PfsLocalClientError.self) {
        try await core.testingAdoptAttributes(attr)
    }
    #expect(!item.reclaimed)
    await core.shutdown()
    #expect(item.reclaimed)
}

/// The chflags(2) path end to end: the extension always forwards the intent
/// and the daemon refuses the entire compound SetAttr before applying any of
/// it. A flags change can therefore never become a partial success.
@Test func flagChangesAreForwardedAndRefusedAtomicallyByTheDaemon() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }

    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let created = try await core.createFile(in: root, name: bytes("flagged.txt"), mode: 0o644)
    #expect(created.attr.flags == 0)

    for flags in [UInt32(UF_IMMUTABLE) | UInt32(UF_HIDDEN), 0] {
        do {
            _ = try await core.setattr(
                item: created.item,
                attributes: .init(mode: 0o600, flags: flags)
            )
            Issue.record("a flags change \(flags) succeeded")
        } catch let error as PfsLocalClientError {
            #expect(error.posixErrno == ENOTSUP)
            #expect(PfsErrorMapper.fsKitError(for: error).code == Int(ENOTSUP))
        }
    }
    // Nothing applied, the co-travelling mode change included.
    let after = try await core.getattr(item: created.item)
    #expect(after.mode == 0o644)
    #expect(after.flags == 0)
    // Both requests reached the daemon: the refusal is the daemon's.
    #expect(await daemon.stats().flagChangeRequests == 2)

    // Everything without a flags intent keeps working.
    let modeOnly = try await core.setattr(item: created.item, attributes: .init(mode: 0o600))
    #expect(modeOnly.mode == 0o600)
}
}
