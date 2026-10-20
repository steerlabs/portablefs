import Foundation
import Testing
@testable import PortableFSKit
import PortableFSKitMockDaemon

extension PfsLocalMockDaemonTests {
/// A kernel teardown burst retires many objects at once. Every reclaim takes
/// the real Close/Reclaim path, and the identity, ownership-handle and
/// file-ID indexes return exactly to the root alone.
@Test func bulkReclaimRetiresEveryObject() async throws {
    let daemon = try PfsLocalMockDaemon()
    defer { daemon.stop() }
    let core = try await VolumeCore.connect(socketPath: daemon.socketPath, attachRef: "mock")
    let root = try await core.rootItem()
    let baseline = await core.testingDebugState()

    var items: [PortableFSItem] = []
    for index in 0..<512 {
        let created = try await core.createFile(
            in: root,
            name: Data("bulk-\(index)".utf8),
            mode: 0o644
        )
        items.append(created.item)
    }
    #expect(await core.testingDebugState().objectIdentityCount == baseline.objectIdentityCount + items.count)

    try await withThrowingTaskGroup(of: Void.self) { group in
        for item in items {
            group.addTask { try await core.reclaim(item: item) }
        }
        try await group.waitForAll()
    }
    let final = await core.testingDebugState()
    #expect(items.allSatisfy { $0.reclaimed })
    #expect(final == baseline)
    let stats = await daemon.stats()
    #expect(stats.reclaimRequests == items.count)
    #expect(stats.activeHandles == 0)
}
}
