import Foundation
import Testing
@testable import PortableFSKit

@Test func bulkReclaimRetiresEveryObject() async throws {
    let core = VolumeCore(client: PfsLocalClient(socketPath: "/unused-pure-identity-test"))
    var items: [PortableFSItem] = []
    for id in 2...10_001 {
        var attr = PfsAttr()
        attr.item.itemID = UInt64(id)
        attr.item.itemGeneration = 1
        attr.fileID = UInt64(id)
        attr.kind = .file
        items.append(try await core.testingAdoptAttributes(attr))
    }
    #expect(await core.testingDebugState().objectIdentityCount == items.count)
    for item in items { try await core.reclaimLocalRepairSource(item: item) }
    let final = await core.testingDebugState()
    #expect(items.allSatisfy { $0.reclaimed })
    #expect(final.itemCount == 0)
    #expect(final.objectIdentityCount == 0)
    #expect(final.openHandleCount == 0)
}
