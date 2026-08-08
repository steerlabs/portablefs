import Foundation
import Testing
@testable import PortableFSAppCore

@Test func cleanupIntentFieldsDecodeAndRemainDistinctFromLiveMounts() throws {
    let data = Data(
        #"""
        {
          "mountPath": "/Volumes/repo",
          "volumeId": "repo",
          "branch": "",
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
    #expect(row.attachState.isEmpty)
}

@Test func olderLiveRowsDecodeWithAdditiveDefaults() throws {
    let data = Data(
        #"""
        {
          "mountPath": "/Volumes/repo",
          "volumeId": "repo",
          "branch": "",
          "attachRef": "att_1",
          "health": "live"
        }
        """#.utf8
    )
    let row = try JSONDecoder().decode(PortableFSMountInventoryRow.self, from: data)
    #expect(!row.requiresCleanup)
    #expect(!row.cleanupRequired)
    #expect(row.operationPhase.isEmpty)
    #expect(row.attachState.isEmpty)
    #expect(row.attachError.isEmpty)
}

@Test func degradedAttachCarriesTheDaemonVerdictAndItsReason() throws {
    let data = Data(
        #"""
        {
          "mountPath": "/Volumes/repo",
          "volumeId": "repo",
          "branch": "",
          "attachRef": "att_1",
          "health": "live",
          "attachState": "degraded",
          "attachError": "v3 authority session is terminal"
        }
        """#.utf8
    )
    let row = try JSONDecoder().decode(PortableFSMountInventoryRow.self, from: data)
    #expect(row.attachState == "degraded")
    #expect(row.attachError == "v3 authority session is terminal")
    #expect(!row.requiresCleanup)
}
