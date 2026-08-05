import Foundation
import Testing
@testable import PortableFSKit
import PortableFSKitMockDaemon
@preconcurrency import Darwin

private func bytes(_ string: String) -> Data {
    Data(string.utf8)
}

private func strictV3Contract(
    policy: String = PfsMacOSCachePolicy.synchronousVFSRepairV1.rawValue
) -> PfsV3CoherenceContract {
    var contract = PfsV3CoherenceContract()
    contract.authorityProtocolMajor = 2
    contract.authorityEpoch = Data(repeating: 0xA1, count: 16)
    contract.sessionID = Data(repeating: 0xB2, count: 16)
    contract.cachePolicy = policy
    contract.repairBudgetMillis = 1_000
    return contract
}

@Test func volumeCoreSelectsOnlyTheDeclaredMacOS26CachePolicy() async throws {
    // The macOS 26 compatibility policy is the one declared policy this build
    // implements: resolve accepts it and records the terms the FSKit adapter
    // composes its coherence stack from.
    let strictDaemon = try PfsLocalMockDaemon(
        configuration: .init(v3Coherence: strictV3Contract())
    )
    defer { strictDaemon.stop() }
    let strict = try await VolumeCore.connect(
        socketPath: strictDaemon.socketPath,
        attachRef: "mock"
    )
    #expect(await strict.strictV3Contract?.cachePolicy == .synchronousVFSRepairV1)
    #expect(await strict.strictV3ResolveReply?.hasV3Coherence == true)
    await strict.shutdown()

    // The native macOS 27 policy stays gated on the final SDK, and an unknown
    // policy string is a contract this build cannot honor. Both fail closed
    // with the same close-first ENOTSUP discipline — never a silent fallback.
    for refusedPolicy in [
        PfsMacOSCachePolicy.nativeFSKitRevocationV1.rawValue,
        "automatic"
    ] {
        let refusingDaemon = try PfsLocalMockDaemon(
            configuration: .init(v3Coherence: strictV3Contract(policy: refusedPolicy))
        )
        defer { refusingDaemon.stop() }
        do {
            _ = try await VolumeCore.connect(
                socketPath: refusingDaemon.socketPath,
                attachRef: "mock"
            )
            Issue.record("expected policy \(refusedPolicy) to be refused")
        } catch let error as PfsLocalClientError {
            #expect(error == .v3CoherenceIntegrationUnavailable)
            #expect(error.posixErrno == ENOTSUP)
        }
    }

    // Legacy resolves continue through the exact same production entry point.
    let legacyDaemon = try PfsLocalMockDaemon()
    defer { legacyDaemon.stop() }
    let legacy = try await VolumeCore.connect(
        socketPath: legacyDaemon.socketPath,
        attachRef: "mock"
    )
    #expect(await legacy.resolvedVolume?.volumeID == "mock-volume")
    #expect(await legacy.strictV3Contract == nil)
}

@Test func clientRejectsDaemonWithoutAttrParentContract() async throws {
    let daemon = try PfsLocalMockDaemon(
        configuration: .init(protocolMinor: 4)
    )
    defer { daemon.stop() }

    do {
        _ = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
        Issue.record("expected protocol-minor mismatch")
    } catch let error as PfsLocalClientError {
        #expect(error == .protocolMismatch(major: 1, minor: 4))
    }
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

    try await core.xattrSet(item: created.item, name: "user.note", value: bytes("note"), createOnly: false, replaceOnly: false)
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

    let linkName = try await core.hardLink(item: renamed.item, in: root, name: bytes("renamed.link"))
    #expect(linkName == bytes("renamed.link"))
    let linked = try await core.lookup(in: root, name: linkName)
    #expect(linked.item.identity == renamed.item.identity)
    #expect(linked.attr.nlink == 2)
    try await core.remove(item: renamed.item, named: bytes("renamed.txt"), from: root, isDirectory: false)
    let survivingLink = try await core.lookup(in: root, name: linkName)
    #expect(survivingLink.item.identity == renamed.item.identity)
    #expect(survivingLink.attr.nlink == 1)
    #expect(try await core.read(item: survivingLink.item, offset: 0, length: 5) == bytes("hello"))

    let symlink = try await core.symlink(in: root, name: bytes("sym"), target: linkName)
    #expect(try await core.readlink(item: symlink.item) == linkName)

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

    let config = try await core.createFile(in: git.item, name: bytes("config"), mode: 0o644, exclusive: true)
    _ = try await core.write(item: config.item, offset: 0, data: oldContent)
    try await core.close(item: config.item)

    let lock = try await core.createFile(in: git.item, name: bytes("config.lock"), mode: 0o644, exclusive: true)
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

@Test func connectionDropFailsInflightAndNextOperationReconnects() async throws {
    let daemon = try PfsLocalMockDaemon(configuration: .init(lookupDelaysNanoseconds: ["slow": 500_000_000]))
    defer { daemon.stop() }

    let core = try await VolumeCore.connect(
        socketPath: daemon.socketPath,
        attachRef: "mock",
        configuration: .init(maxReconnectAttempts: 10, reconnectBaseDelayNanoseconds: 5_000_000)
    )
    let root = try await core.rootItem()
    _ = try await core.createFile(in: root, name: bytes("slow"), mode: 0o644)
    _ = try await core.createFile(in: root, name: bytes("fast"), mode: 0o644)

    let slowLookup = Task {
        try await core.lookup(in: root, name: bytes("slow"))
    }
    try await Task.sleep(nanoseconds: 50_000_000)
    daemon.dropConnections()

    do {
        _ = try await slowLookup.value
        Issue.record("expected in-flight lookup to fail on connection drop")
    } catch {
        #expect(PfsErrorMapper.fsKitError(for: error).code == Int(EIO))
    }

    let recovered = try await core.lookup(in: root, name: bytes("fast"))
    #expect(recovered.attr.item.itemID != 0)
}

@Test func eventsAreDeliveredAfterSubscribe() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }

    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let stream = try await core.subscribeEvents()
    var iterator = stream.makeAsyncIterator()

    let rootIdentity = await daemon.rootIdentity()
    daemon.emitInvalidation(item: rootIdentity.proto, contentVersion: 7)

    let event = await iterator.next()
    guard case let .invalidation(invalidation)? = event?.kind else {
        Issue.record("expected invalidation event")
        return
    }
    #expect(invalidation.item.itemID == rootIdentity.itemID)
    #expect(invalidation.contentVersion == 7)
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

@Test func itemTableDetectsGenerationMismatch() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }

    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let stale = await core.testingAdoptItem(identity: PfsItemIdentity(itemID: 99, generation: 1))
    _ = await core.testingAdoptItem(identity: PfsItemIdentity(itemID: 99, generation: 2))

    do {
        _ = try await core.getattr(item: stale)
        Issue.record("expected old generation to be rejected")
    } catch let error as PfsLocalClientError {
        #expect(error.posixErrno == ESTALE)
    }
}

/// The chflags(2) write path end to end: the extension forwards the intent and
/// the daemon — the only layer that knows the attached authority's features —
/// persists it. A zero word is a real "clear everything", not "no change".
@Test func flagChangesRoundTripThroughTheDaemonWhenTheAuthorityPersistsThem() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }

    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let capabilities = await core.resolvedVolume?.capabilities
    #expect(capabilities?.flagsSupported == true)
    #expect(capabilities?.flagsUnderstood == true)

    let root = try await core.rootItem()
    let created = try await core.createFile(in: root, name: bytes("flagged.txt"), mode: 0o644)
    #expect(created.attr.flags == 0)

    let immutable = UInt32(UF_IMMUTABLE) | UInt32(UF_HIDDEN)
    let set = try await core.setattr(item: created.item, attributes: .init(flags: immutable))
    #expect(set.flags == immutable)
    #expect(try await core.getattr(item: created.item).flags == immutable)

    // Clearing is a durable state of its own, and it must not disturb a
    // neighbouring group applied in the same request.
    let cleared = try await core.setattr(item: created.item, attributes: .init(mode: 0o600, flags: 0))
    #expect(cleared.flags == 0)
    #expect(cleared.mode == 0o600)

    // A setattr with no flags intent leaves the stored word alone rather than
    // resetting it to the proto default.
    _ = try await core.setattr(item: created.item, attributes: .init(flags: immutable))
    _ = try await core.setattr(item: created.item, attributes: .init(mtimeMilliseconds: 123_000))
    #expect(try await core.getattr(item: created.item).flags == immutable)
}

/// THE REGRESSION THIS PINS. `flagsSupported` describes the attached
/// AUTHORITY's durable flag storage; it is not a verdict on the volume. A
/// machine-local graft in the same namespace is backed by a real host inode,
/// so chflags(2) on it persists with no authority feature involved. A frontend
/// that gated forwarding on `flagsSupported` refused every flags change on
/// such a mount — including the graft ones that would have worked, and
/// including via a static capability that stopped the kernel before the
/// extension was even asked.
///
/// So: `flagsUnderstood` true with `flagsSupported` false means FORWARD, and
/// let the daemon answer per target.
@Test func flagChangesAreForwardedWhenTheDaemonUnderstandsThemEvenWithoutAuthorityPersistence() async throws {
    let daemon = try PfsLocalMockDaemon(configuration: .init(
        flagsSupported: false,
        flagsUnderstood: true,
        graftBackedNames: ["grafted.txt"]
    ))
    defer { daemon.stop() }

    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let capabilities = await core.resolvedVolume?.capabilities
    #expect(capabilities?.flagsSupported == false)
    #expect(capabilities?.flagsUnderstood == true)
    // The static capability must not declare blanket non-support: some objects
    // on this volume take a flag word. The kernel has to let the request
    // through so the per-object answer can be given.
    #expect(!PfsFSKitMapping.supportedCapabilities(
        from: capabilities ?? PfsCapabilities()
    ).doesNotSupportImmutableFiles)

    let root = try await core.rootItem()
    let grafted = try await core.createFile(in: root, name: bytes("grafted.txt"), mode: 0o644)

    // Graft-backed: the change is forwarded AND applied, with no authority
    // feature anywhere in the story.
    let immutable = UInt32(UF_IMMUTABLE) | UInt32(UF_HIDDEN)
    let set = try await core.setattr(item: grafted.item, attributes: .init(flags: immutable))
    #expect(set.flags == immutable)
    #expect(try await core.getattr(item: grafted.item).flags == immutable)

    // Authority-backed, same connection, same request shape: refused — and
    // refused by the DAEMON, which is the only layer that knows the backing.
    let remote = try await core.createFile(in: root, name: bytes("authority.txt"), mode: 0o644)
    do {
        _ = try await core.setattr(
            item: remote.item,
            attributes: .init(mode: 0o600, flags: immutable)
        )
        Issue.record("an authority without flag persistence accepted a chflags")
    } catch let error as PfsLocalClientError {
        #expect(error.posixErrno == ENOTSUP)
        #expect(PfsErrorMapper.fsKitError(for: error).code == Int(ENOTSUP))
    }
    // The refusal applied nothing, co-travelling groups included.
    #expect(try await core.getattr(item: remote.item).mode == 0o644)

    // Both requests REACHED the daemon. This is the assertion that fails when
    // the extension gates on `flagsSupported`: it would have refused locally
    // and the daemon would have seen no flags change at all.
    let stats = await daemon.stats()
    #expect(stats.flagChangeRequests == 2)
}

/// The rolling-upgrade case the daemon-side refusal cannot cover: a NEW
/// frontend against an OLD daemon at the SAME protocol minor. `set_flags` and
/// `flags` are appended fields, so that daemon proto3-discards them, applies
/// the rest of the setattr and answers OK — a chflags(2) that returns success
/// while nothing changed. It advertises neither `flagsSupported` nor
/// `flagsUnderstood` — it cannot set fields it does not know exist — so the
/// absent `flagsUnderstood` decodes false and the frontend's own gate refuses
/// instead of forwarding. Forwarding here is the bug; the mock deliberately
/// would NOT complain about it.
@Test func flagChangesAreNotForwardedToADaemonPredatingTheFlagFields() async throws {
    let daemon = try PfsLocalMockDaemon(configuration: .init(predatesFlagFields: true))
    defer { daemon.stop() }

    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let capabilities = await core.resolvedVolume?.capabilities
    #expect(capabilities?.flagsSupported == false)
    #expect(capabilities?.flagsUnderstood == false)
    // A daemon that cannot parse the request is the one case where a blanket
    // "no immutable files" is the truth.
    #expect(PfsFSKitMapping.supportedCapabilities(
        from: capabilities ?? PfsCapabilities()
    ).doesNotSupportImmutableFiles)

    let root = try await core.rootItem()
    let created = try await core.createFile(in: root, name: bytes("old-daemon.txt"), mode: 0o644)

    do {
        _ = try await core.setattr(
            item: created.item,
            attributes: .init(mode: 0o600, flags: UInt32(UF_IMMUTABLE))
        )
        Issue.record("a flags change was forwarded to a daemon that silently discards it")
    } catch let error as PfsLocalClientError {
        #expect(error.posixErrno == ENOTSUP)
    }

    // Proof the refusal was the frontend's: had it forwarded, this daemon
    // would have reported success with the flag word dropped and the mode
    // applied.
    let after = try await core.getattr(item: created.item)
    #expect(after.flags == 0)
    #expect(after.mode == 0o644)

    // Nothing was even sent: the refusal happened before the frame was built.
    #expect(await daemon.stats().flagChangeRequests == 0)

    // Everything an old daemon DOES understand keeps working.
    let modeOnly = try await core.setattr(item: created.item, attributes: .init(mode: 0o600))
    #expect(modeOnly.mode == 0o600)
}
