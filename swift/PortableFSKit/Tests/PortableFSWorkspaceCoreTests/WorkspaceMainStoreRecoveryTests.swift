import Foundation
import Testing
import PortableFSWorkspaceCore
@testable import PortableFSWorkspaceVM

private func mainStoreDirectory() throws -> URL {
    let directory = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("pfs-main-recovery-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    return directory
}
private func mainJobPages() throws -> [Data] {
    var frame = try WorkspaceControl.decode(workspaceGolden("status_reply"))
    let mount = try #require(frame.statusReply.mounts.first?.mount)
    var status = frame.statusReply; status.mounts = []; status.jobs = []; status.retired = []
    return try (1...128).map { index in
        var job = WorkspaceMountJob(); job.mount = mount; job.requestID = UInt64(index)
        job.operation = index % 2 == 0 ? "mount" : "provision"; job.phase = "complete"
        var retired = WorkspaceRetiredOutcome(); retired.retirementSequence = UInt64(index); retired.job = job
        status.retired = [retired]; frame.statusReply = status
        return try WorkspaceControl.encode(frame)
    }
}
private func publishMainStore(_ directory: WorkspacePrivateDirectory, pages: [Data], sticky: Bool = false) throws -> Data {
    let object: [String: Any] = ["version": 2, "running": false, "volumes": [], "retained": pages.map { $0.base64EncodedString() }, "current": try #require(pages.last).base64EncodedString()]
    let raw = try JSONSerialization.data(withJSONObject: object)
    try directory.write("desired.json", data: raw)
    try directory.write("resources.present", data: Data((sticky ? "8\nunobserved\n" : "8\n").utf8))
    return raw
}
@Test func mainFullOrdinaryJobStoreRecoversWithoutKeepingHistory() throws {
    let url = try mainStoreDirectory(); defer { try? FileManager.default.removeItem(at: url) }
    let directory = try WorkspacePrivateDirectory(url)
    _ = try publishMainStore(directory, pages: mainJobPages())
    let store = try WorkspaceHostState(directory: url)
    #expect(store.value.version == 3); #expect(store.value.retained.isEmpty)
    #expect(!store.previousWriteOutcomeUnknown)
    try store.publishEmptyResources()
    #expect(try directory.read("resources.present") == nil)
    let persisted = try #require(try directory.read("desired.json"))
    #expect(try JSONDecoder().decode(WorkspaceDesiredState.self, from: persisted).retained.isEmpty)
}
@Test func mainFullStoreRecoveryKeepsLossAndStickyUnknownUntilExactDismiss() throws {
    let url = try mainStoreDirectory(); defer { try? FileManager.default.removeItem(at: url) }
    let directory = try WorkspacePrivateDirectory(url)
    var frame = try WorkspaceControl.decode(workspaceGolden("status_reply"))
    var mount = try #require(frame.statusReply.mounts.first)
    mount.state = "terminal"; mount.cleanup = "complete"; mount.renewal = WorkspaceRenewalReadiness(); mount.renewal.state = "pending"
    mount.outcome.durability = "lost"; mount.outcome.observation = "observed"; mount.outcome.release = "abandoned"; mount.outcome.cleanupDebt = 0
    var loss = WorkspaceLoss(); loss.sequence = 1; loss.acceptedEntries = 1; loss.acceptedBytes = 22; loss.reason = "accepted tail lost"
    mount.loss = [loss]; mount.reason = loss.reason
    var retired = WorkspaceRetiredOutcome(); retired.retirementSequence = 129; retired.mountStatus = mount
    frame.statusReply.mounts = []; frame.statusReply.jobs = []; frame.statusReply.retired = [retired]
    var pages = try mainJobPages(); pages[127] = try WorkspaceControl.encode(frame)
    _ = try publishMainStore(directory, pages: pages, sticky: true)
    let store = try WorkspaceHostState(directory: url)
    #expect(store.retainedOutcomes.count == 2)
    let lost = try #require(store.retainedOutcomes.first { $0.notice.someChangesWereNotSaved })
    let unknown = try #require(store.retainedOutcomes.first { $0.notice.previousWriteOutcomeUnknown })
    #expect(lost.notice.id != unknown.notice.id)
    #expect(throws: (any Error).self) { try store.publishEmptyResources() }
    try store.dismiss(lost.notice.id)
    #expect(store.previousWriteOutcomeUnknown)
    #expect(throws: (any Error).self) { try store.publishEmptyResources() }
    try store.dismiss(unknown.notice.id); try store.publishEmptyResources()
    #expect(store.retainedOutcomes.isEmpty)
}

// Recovery publication crash-cut controls.
@Test func mainRecoveryCrashPreservesUnknownBeforeRetiringStickyWitness() throws {
    enum Cut: Error { case crashed }
    let url = try mainStoreDirectory(); defer { try? FileManager.default.removeItem(at: url) }
    let directory = try WorkspacePrivateDirectory(url)
    _ = try publishMainStore(directory, pages: mainJobPages(), sticky: true)
    #expect(throws: Cut.self) { _ = try WorkspaceHostState(directory: url, afterRecoveryCommit: { throw Cut.crashed }) }
    let published = try #require(try directory.read("desired.json"))
    let committed = try JSONDecoder().decode(WorkspaceDesiredState.self, from: published)
    #expect(committed.retained.count == 1)
    #expect(try directory.read("resources.present") == Data("8\nunobserved\n".utf8))
    let store = try WorkspaceHostState(directory: url)
    #expect(store.retainedOutcomes.map(\.notice.id) == committed.retained.map(\.notice.id))
    #expect(try directory.read("resources.present") == Data("8\n".utf8))
    try store.dismiss(try #require(store.retainedOutcomes.first).notice.id)
    try store.publishEmptyResources()
}
@Test func damagedMainEvidenceRefusesWithoutChangingItsPublishedStore() throws {
    let url = try mainStoreDirectory(); defer { try? FileManager.default.removeItem(at: url) }
    let directory = try WorkspacePrivateDirectory(url)
    let raw = try publishMainStore(directory, pages: [Data("not a protocol-8 frame".utf8)], sticky: true)
    #expect(throws: (any Error).self) { _ = try WorkspaceHostState(directory: url) }
    #expect(try directory.read("desired.json") == raw)
    #expect(try directory.read("resources.present") == Data("8\nunobserved\n".utf8))
}

@Test func mainStoreRepairPreservesTheExactLiveExecutionReference() throws {
    let url = try mainStoreDirectory(); defer { try? FileManager.default.removeItem(at: url) }
    let directory = try WorkspacePrivateDirectory(url)
    var reference: WorkspaceFileLock? = try directory.lock("owner.lock")
    let identity = try #require(reference?.identity)
    var object = try #require(JSONSerialization.jsonObject(with: publishMainStore(directory, pages: mainJobPages())) as? [String: Any])
    let execution = WorkspaceExecution(hostBoot: "host", boot: Data(repeating: 8, count: 16), reference: identity)
    object["execution"] = try JSONSerialization.jsonObject(with: WorkspaceHostControl.encode(execution))
    try directory.write("desired.json", data: JSONSerialization.data(withJSONObject: object))
    let store = try WorkspaceHostState(directory: url)
    #expect(store.value.execution?.reference == identity)
    #expect(throws: (any Error).self) { try store.requirePriorExecutionAbsent(hostBoot: "host") }
    withExtendedLifetime(reference) {}; reference = nil
    _ = try store.requirePriorExecutionAbsent(hostBoot: "host")
    #expect(store.value.execution == nil); #expect(store.previousWriteOutcomeUnknown)
}
