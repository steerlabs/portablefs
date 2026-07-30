import Foundation
import Testing
@testable import PortableFSAppCore

@Test func cleanupIntentFieldsDecodeAndRemainDistinctFromLiveMounts() throws {
    let data = Data(
        #"""
        {
          "mountPath": "/Volumes/repo",
          "volumeId": "repo",
          "branch": "main",
          "health": "cleanup-required",
          "cleanupRequired": true,
          "operationPhase": "mount-published"
        }
        """#.utf8
    )
    let row = try JSONDecoder().decode(PortableFSMountInventoryRow.self, from: data)
    #expect(row.requiresCleanup)
    #expect(row.operationPhase == "mount-published")
    #expect(row.attachRef == nil)
}

@Test func olderLiveRowsDecodeWithAdditiveDefaults() throws {
    let data = Data(
        #"""
        {
          "mountPath": "/Volumes/repo",
          "volumeId": "repo",
          "branch": "main",
          "attachRef": "att_1",
          "health": "live"
        }
        """#.utf8
    )
    let row = try JSONDecoder().decode(PortableFSMountInventoryRow.self, from: data)
    #expect(!row.requiresCleanup)
    #expect(!row.cleanupRequired)
    #expect(row.operationPhase.isEmpty)
}
