import Foundation
import Testing
@testable import PortableFSKit
import PortableFSKitMockDaemon

private func ownershipBytes(_ value: String) -> Data {
    Data(value.utf8)
}

private func createPeerFile(
    client: PfsLocalClient,
    root: PfsItem,
    name: String
) async throws -> PfsItem {
    var create = PfsCreateRequest()
    create.dir = root
    create.name = ownershipBytes(name)
    create.mode = 0o644
    create.exclusive = true
    let envelope = try await client.request(.create(create))
    guard case let .createReply(reply)? = envelope.body else {
        throw PfsLocalClientError.unexpectedReply(
            String(describing: envelope.body)
        )
    }

    var close = PfsCloseRequest()
    close.handle = reply.handle
    _ = try await client.request(.close(close))
    return reply.attr.item
}

private func waitForAcceptedItemCounts(
    _ expected: Int,
    daemon: PfsLocalMockDaemon
) async throws -> PfsLocalMockDaemon.Stats {
    let deadline = ContinuousClock.now + .seconds(2)
    var stats = await daemon.stats()
    while stats.resourceAcceptedItemCounts.count < expected,
          ContinuousClock.now < deadline {
        try await Task.sleep(for: .milliseconds(2))
        stats = await daemon.stats()
    }
    return stats
}

extension PfsLocalMockDaemonTests {
@Test func metadataOnlyEnumerationPreservesHardLinkFileIDs() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }

    // Populate through another frontend so the enumerating VolumeCore begins
    // with no canonical child object. Both names deliberately resolve to the
    // same file ID without transferring ownership of either occurrence.
    let peer = PfsLocalClient(socketPath: daemon.socketPath)
    let peerVolume = try await peer.resolve(attachRef: "mock")
    let source = try await createPeerFile(
        client: peer,
        root: peerVolume.root,
        name: "hard-link-a"
    )
    var link = PfsHardLinkRequest()
    link.item = source
    link.dir = peerVolume.root
    link.name = ownershipBytes("hard-link-b")
    _ = try await peer.request(.hardLink(link))

    let core = try await VolumeCore.connect(
        socketPath: daemon.socketPath,
        attachRef: "mock"
    )
    let root = try await core.rootItem()
    let client = await core.client
    await daemon.resetStats()

    try await client.withPublicationBoundary {
        let page = try await core.enumerate(
            directory: root,
            startingAt: 0,
            wantAttributes: true,
            maxEntries: 2
        )
        #expect(page.entries.count == 2)
        #expect(page.entries[0].attr.fileID == page.entries[1].attr.fileID)
        #expect(page.entries.allSatisfy { $0.attr.item == PfsItem() && $0.attr.parent == PfsItem() })
    }

    let stats = try await waitForAcceptedItemCounts(1, daemon: daemon)
    #expect(stats.resourceAcceptedItemCounts == [0])
    #expect(await core.testingDebugState().itemCount == 1)
}

@Test func multiPageEnumerationHasNoPageDispositions() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }

    let peer = PfsLocalClient(socketPath: daemon.socketPath)
    let peerVolume = try await peer.resolve(attachRef: "mock")
    for index in 0..<300 {
        _ = try await createPeerFile(
            client: peer,
            root: peerVolume.root,
            name: String(format: "page-%03d", index)
        )
    }

    let core = try await VolumeCore.connect(
        socketPath: daemon.socketPath,
        attachRef: "mock"
    )
    let root = try await core.rootItem()
    let client = await core.client
    await daemon.resetStats()

    try await client.withPublicationBoundary {
        var cookie: UInt64 = 0
        repeat {
            let page = try await core.enumerate(
                directory: root,
                startingAt: cookie,
                wantAttributes: true,
                maxEntries: 128
            )
            cookie = page.nextCookie
        } while cookie != 0
    }

    // Only the retained directory open needs a disposition. Pages transfer
    // no items, even when the walk crosses several reply boundaries.
    let stats = try await waitForAcceptedItemCounts(1, daemon: daemon)
    #expect(stats.enumerateRequests == 3)
    #expect(stats.resourceAcceptedItemCounts == [0])
    #expect(await core.testingDebugState().itemCount == 1)
}
}
