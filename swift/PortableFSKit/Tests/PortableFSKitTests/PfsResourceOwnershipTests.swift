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
@Test func partialEnumerationPrefixPreservesDuplicateHardLinkOccurrences() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }

    // Populate through another frontend so the enumerating VolumeCore begins
    // with no canonical child object. Both names deliberately resolve to the
    // same item identity: the disposition must count ordered occurrences, not
    // collapse them into a set of item IDs.
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
        #expect(
            page.entries.map(\.attr.item.stableIdentity).allSatisfy {
                $0 == page.entries[0].attr.item.stableIdentity
            }
        )

        let adopted = try await core.adoptEnumeratedItems(page.entries)
        #expect(adopted.count == 2)
        #expect(adopted[0] === adopted[1])
        client.acceptProvisionalItemPrefix(
            targetRequestID: page.resourceRequestID,
            count: 1
        )
    }

    let stats = try await waitForAcceptedItemCounts(2, daemon: daemon)
    #expect(stats.resourceAcceptedItemCounts.filter { $0 > 0 } == [1])
    #expect(await core.testingDebugState().itemCount == 2)
}

@Test func multiPageEnumerationSettlesEveryPageDisposition() async throws {
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
            let adopted = try await core.adoptEnumeratedItems(page.entries)
            #expect(adopted.count == page.entries.count)
            client.acceptProvisionalItemPrefix(
                targetRequestID: page.resourceRequestID,
                count: UInt32(clamping: page.entries.count)
            )
            cookie = page.nextCookie
        } while cookie != 0
    }

    // Resource tickets are independent and may be emitted in dictionary
    // iteration order. Their exact per-page occurrence counts are the proof;
    // no ordering between otherwise independent dispositions is required.
    let stats = try await waitForAcceptedItemCounts(4, daemon: daemon)
    #expect(stats.enumerateRequests == 3)
    #expect(stats.resourceAcceptedItemCounts.filter { $0 > 0 }.sorted() == [44, 128, 128])
    #expect(await core.testingDebugState().itemCount == 301)
}
}
