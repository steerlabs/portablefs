import Darwin
import Foundation
import PortableFSAppCore
import PortableFSWorkspaceCore

public struct WorkspaceDesiredVolume: Codable, Sendable {
    public var connection: WorkspaceConnection
    public var intent: String
    public var reopenRequired = false
    public var cleanupComplete = false
    public var request: WorkspaceConnectionDocument?
    // A single-use initial grant is committed as consumed BEFORE dispatch.
    // Ambiguous delivery reconciles through Status, never by resubmission.
    public var authorizationConsumed = false
    public var lastJob: UInt64 = 0
    public var operation = "identity"
    public var message = WorkspaceHostControl.authorizationRequired
    public init(connection: WorkspaceConnection, intent: String) { self.connection = connection; self.intent = intent }
    public var reservation: WorkspaceReservation { WorkspaceReservation(authority: connection.authority, volume: connection.volumeId, owner: intent) }
}
public struct WorkspaceExecution: Codable, Sendable {
    public var hostBoot: String
    public var boot: Data
    public var reference: WorkspaceFileIdentity
    public init(hostBoot: String, boot: Data, reference: WorkspaceFileIdentity) { self.hostBoot = hostBoot; self.boot = boot; self.reference = reference }
}
public struct WorkspaceRetainedOutcome: Codable, Sendable {
    public var notice: PortableFSWorkspaceOutcome
    public var evidence: Data?
}
public struct WorkspaceDesiredState: Codable, Sendable {
    public var version = 3
    public var running = false
    public var execution: WorkspaceExecution?
    public var volumes: [WorkspaceDesiredVolume] = []
    public var retained: [WorkspaceRetainedOutcome] = []
    public var outcomeSequence: UInt64 = 0
    public var retirementThrough: UInt64 = 0
    public var current: Data?
    public init() {}
}
public final class WorkspaceHostState {
    public let directory: WorkspacePrivateDirectory
    private let singleton: WorkspaceFileLock
    public var previousWriteOutcomeUnknown: Bool { value.retained.contains { $0.notice.previousWriteOutcomeUnknown } }
    // Tests cut the transaction after its durable state publication, before
    // witness removal. A crash here must never resurrect a dismissed outcome.
    var afterDismissCommit: (() throws -> Void)?
    public private(set) var value: WorkspaceDesiredState
    public init(directory: URL) throws {
        self.directory = try WorkspacePrivateDirectory(directory)
        singleton = try self.directory.lock("service.lock")
        if let raw = try self.directory.read("desired.json", limit: 4 << 20) {
            try PortableFSDStrictJSON.validate(raw)
            _ = try WorkspaceHostControl.object(JSONSerialization.jsonObject(with: raw), keys: ["version", "running", "execution", "volumes", "retained", "current", "outcomeSequence", "retirementThrough"])
            value = try JSONDecoder().decode(WorkspaceDesiredState.self, from: raw)
        } else { value = WorkspaceDesiredState() }
        guard value.version == 3, value.volumes.count <= 64, value.retained.count <= 128,
              Set(value.volumes.map { $0.connection.volumeId }).count == value.volumes.count else { throw WorkspaceVMError("invalid workspace desired state") }
        for volume in value.volumes {
            try volume.connection.validate(); try volume.reservation.validate()
            if let request = volume.request { try request.validate(); guard request.connection == volume.connection, request.intent == volume.intent else { throw WorkspaceControlError.grammar } }
        }
        guard Set(value.retained.map { $0.notice.id }).count == value.retained.count else { throw WorkspaceControlError.grammar }
        for outcome in value.retained {
            guard PortableFSWorkspaceOutcome.validID(outcome.notice.id),
                  outcome.notice.someChangesWereNotSaved || outcome.notice.previousWriteOutcomeUnknown,
                  let sequence = UInt64(outcome.notice.id.split(separator: "/")[0]), sequence <= value.outcomeSequence else { throw WorkspaceControlError.grammar }
            if let raw = outcome.evidence { _ = try WorkspaceControl.decode(raw) }
        }
        if let raw = value.current { _ = try WorkspaceControl.decode(raw) }
        switch try self.directory.read("resources.present", limit: 64) {
        case nil, Data("8\n".utf8): break
        default: throw WorkspaceVMError("invalid workspace resource witness")
        }
    }
    public func commit(_ update: (inout WorkspaceDesiredState) throws -> Void) throws {
        var next = value; try update(&next)
        guard next.retained.count <= 128 else { throw WorkspaceVMError("workspace evidence capacity reached") }
        let raw = try WorkspaceHostControl.encode(next)
        guard raw.count <= 4 << 20 else { throw WorkspaceVMError("workspace evidence capacity reached") }
        // Presence precedes execution/state publication. desired.json is the
        // sole outcome decision; a stale witness after a crash is conservative.
        if next.execution != nil || Self.hasUnresolvedOutcome(next) { try directory.write("resources.present", data: Data("8\n".utf8)) }
        try directory.write("desired.json", data: raw); value = next
    }
    static func retain(_ status: WorkspaceMountStatus, evidence: Data, state: inout WorkspaceDesiredState) throws {
        let lost = !status.loss.isEmpty || status.outcome.durability == "lost"
        let unknown = status.outcome.durability == "unresolved" || status.outcome.observation == "unobserved" ||
            status.outcome.cleanupDebt != 0 || status.outcome.release == "unresolved"
        guard lost || unknown else { return }
        let authority = status.mount.authorityID.map { String(format: "%02x", $0) }.joined()
        let outcome = status.outcome
        let summary = "Durability: \(outcome.durability); observation: \(outcome.observation); release: \(outcome.release); cleanup debt: \(outcome.cleanupDebt)"
        let losses = status.loss.map { "Loss \($0.sequence): \($0.acceptedEntries) entries, \($0.acceptedBytes) bytes; " + $0.reason }
        let details = (["Authority: " + authority, "Volume: " + status.mount.volumeID, status.reason, summary] + losses).joined(separator: "\n")
        try retain(incarnation: status.mount.incarnation, volume: status.mount.volumeID, lost: lost, unknown: unknown, evidence: evidence, details: details, state: &state)
    }
    private static func retain(incarnation: Data, volume: String, lost: Bool, unknown: Bool, evidence: Data?, details: String = "Previous workspace execution ended without a final observed drain.", state: inout WorkspaceDesiredState) throws {
        guard state.outcomeSequence < UInt64.max, state.retained.count < 128 else { throw WorkspaceVMError("workspace evidence capacity reached; dismiss a previous outcome") }
        state.outcomeSequence += 1
        let id = String(state.outcomeSequence) + "/" + incarnation.map { String(format: "%02x", $0) }.joined() + "/" + volume
        state.retained.append(WorkspaceRetainedOutcome(notice: PortableFSWorkspaceOutcome(id: id, lost: lost, unknown: unknown, details: details), evidence: evidence))
    }
    public func retainUnobservedExecution() throws {
        guard let execution = value.execution else { throw WorkspaceVMError("workspace execution identity unavailable") }
        // Record the old execution and clear it in one transaction, so retrying
        // after owner death cannot duplicate it or forget its outcome.
        try commit { state in
            let frame = try state.current.map(WorkspaceControl.decode)
            let mounts = frame?.statusReply.mounts ?? []
            for mount in mounts {
                var unknown = mount; unknown.outcome.durability = "unresolved"; unknown.outcome.observation = "unobserved"; unknown.outcome.release = "unresolved"
                guard var page = frame else { throw WorkspaceControlError.grammar }; page.statusReply.mounts = [unknown]; page.statusReply.jobs = []; page.statusReply.retired = []
                try Self.retain(unknown, evidence: WorkspaceControl.encode(page), state: &state)
            }
            if mounts.isEmpty {
                try Self.retain(incarnation: execution.boot, volume: "-", lost: false, unknown: true, evidence: nil, state: &state)
            }
            state.current = nil; state.execution = nil
        }
    }
    public func dismiss(_ id: String) throws {
        guard PortableFSWorkspaceOutcome.validID(id) else { throw WorkspaceControlError.grammar }
        // Exact absent IDs are no-ops, including retries after a lost reply.
        // No tombstone list grows with clean runs or repeated dismissals.
        if value.retained.contains(where: { $0.notice.id == id }) {
            try commit { $0.retained.removeAll { $0.notice.id == id } }
            try afterDismissCommit?()
        }
    }
    public func publishEmptyResources() throws {
        guard value.execution == nil, !Self.hasUnresolvedOutcome(value) else { throw WorkspaceVMError("workspace outcome is unresolved") }
        try directory.remove("resources.present")
    }
    public static func hasUnresolvedOutcome(_ state: WorkspaceDesiredState) -> Bool {
        if !state.retained.isEmpty { return true }
        guard let raw = state.current else { return false }
        guard let frame = try? WorkspaceControl.decode(raw) else { return true }
        // Retired records have already transferred to retained notices (or
        // proved clean). Current membership still owns its cleanup resources.
        return frame.statusReply.mounts.contains { !$0.loss.isEmpty || $0.outcome.durability != "durable" || $0.outcome.observation != "observed" || !["released", "expired"].contains($0.outcome.release) || $0.outcome.cleanupDebt != 0 }
    }
    /// Each admitted key reserves room for its final exceptional outcome.
    /// Replacement cannot consume the predecessor's unacknowledged slot.
    public func requireOutcomeCapacity(replacing volume: String? = nil, coldStart: Bool = false) throws {
        let active = value.volumes.filter { desired in
            if desired.connection.volumeId == volume { return false }
            if coldStart { return true }
            guard let mount = try? desired.request?.guestIdentity().mount else { return true }
            let suffix = "/" + mount.incarnation.map { String(format: "%02x", $0) }.joined() + "/" + mount.volumeID
            return !value.retained.contains { $0.notice.id.hasSuffix(suffix) }
        }.count
        // The execution reserves one crash-without-status notice even when
        // its last volume has retired. Termination transfers that slot too.
        let needed = active + (coldStart || value.execution != nil ? 1 : 0) + (coldStart ? 0 : 1)
        guard value.retained.count + needed <= 128 else { throw WorkspaceVMError("Dismiss a previous write outcome before adding or replacing a volume") }
    }
    public func saveRequest(_ document: WorkspaceConnectionDocument) throws -> URL {
        let name = "authorization-" + document.connection.volumeId + ".pfsworkspace"
        try document.validate()
        try directory.write(name, data: WorkspaceHostControl.encode(document))
        return directory.url.appendingPathComponent(name)
    }
    /// A fresh description must acquire the VM's exact retained lock inode.
    /// Keep this reference through execution publication and give its handle to
    /// VZ; a service singleton, old PID or socket absence proves no VM absence.
    @discardableResult public func requirePriorExecutionAbsent(hostBoot: String) throws -> WorkspaceFileLock {
        guard !hostBoot.isEmpty else { throw WorkspaceVMError("host boot identity unavailable") }
        let reference = try directory.lock("owner.lock")
        if let old = value.execution {
            guard old.hostBoot != hostBoot || old.reference == reference.identity else { throw WorkspaceVMError("Cleanup required: previous VM execution reference was replaced") }
            try retainUnobservedExecution()
        }
        return reference
    }
    public static func hostBootIdentity() throws -> String {
        var size = 0
        guard sysctlbyname("kern.bootsessionuuid", nil, &size, nil, 0) == 0, size > 1, size < 256 else { throw WorkspaceVMError("host boot identity unavailable") }
        var bytes = [CChar](repeating: 0, count: size)
        guard sysctlbyname("kern.bootsessionuuid", &bytes, &size, nil, 0) == 0 else { throw WorkspaceVMError("host boot identity unavailable") }
        return String(decoding: bytes.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
}
