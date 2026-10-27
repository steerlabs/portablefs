import Darwin
import Foundation
import PortableFSAppCore
import PortableFSWorkspaceCore

public struct WorkspaceDesiredVolume: Codable, Sendable {
    public var connection: WorkspaceConnection
    public var intent: String
    public var reopenRequired = false
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
public struct WorkspaceDesiredState: Codable, Sendable {
    public var version = 2
    public var running = false
    public var execution: WorkspaceExecution?
    public var volumes: [WorkspaceDesiredVolume] = []
    public var retained: [Data] = []
    public var current: Data?
    public init() {}
}
public final class WorkspaceHostState {
    public let directory: WorkspacePrivateDirectory
    private let singleton: WorkspaceFileLock
    public private(set) var previousWriteOutcomeUnknown = false
    public private(set) var value: WorkspaceDesiredState
    public init(directory: URL) throws {
        self.directory = try WorkspacePrivateDirectory(directory)
        singleton = try self.directory.lock("service.lock")
        if let raw = try self.directory.read("desired.json", limit: 4 << 20) {
            try PortableFSDStrictJSON.validate(raw)
            _ = try WorkspaceHostControl.object(JSONSerialization.jsonObject(with: raw), keys: ["version", "running", "execution", "volumes", "retained", "current"])
            value = try JSONDecoder().decode(WorkspaceDesiredState.self, from: raw)
        } else { value = WorkspaceDesiredState() }
        guard value.version == 2, value.volumes.count <= 64, value.retained.count <= 128,
              Set(value.volumes.map { $0.connection.volumeId }).count == value.volumes.count else { throw WorkspaceVMError("invalid workspace desired state") }
        for volume in value.volumes {
            try volume.connection.validate(); try volume.reservation.validate()
            if let request = volume.request { try request.validate(); guard request.connection == volume.connection, request.intent == volume.intent else { throw WorkspaceControlError.grammar } }
        }
        for raw in value.retained { _ = try WorkspaceControl.decode(raw) }
        switch try self.directory.read("resources.present", limit: 64) {
        case nil, Data("8\n".utf8): break
        case Data("8\nunobserved\n".utf8): previousWriteOutcomeUnknown = true
        default: throw WorkspaceVMError("invalid workspace resource witness")
        }
    }
    public func commit(_ update: (inout WorkspaceDesiredState) throws -> Void) throws {
        var next = value; try update(&next)
        let raw = try WorkspaceHostControl.encode(next)
        guard raw.count <= 2 << 20 else { throw WorkspaceVMError("workspace evidence capacity reached") }
        // The absence of this name is the cross-release empty-resource proof.
        // Publish it before an execution can exist; retire it only after both
        // durable desired state and clean termination/loss evidence settle.
        let hasResources = next.execution != nil || Self.hasUnresolvedOutcome(next) || previousWriteOutcomeUnknown
        if hasResources { try directory.write("resources.present", data: Data((previousWriteOutcomeUnknown ? "8\nunobserved\n" : "8\n").utf8)) }
        try directory.write("desired.json", data: raw); value = next
    }
    public func retainUnobservedExecution() throws {
        try directory.write("resources.present", data: Data("8\nunobserved\n".utf8))
        previousWriteOutcomeUnknown = true
    }
    public func publishEmptyResources() throws {
        guard value.execution == nil, !previousWriteOutcomeUnknown, !Self.hasUnresolvedOutcome(value) else { throw WorkspaceVMError("workspace outcome is unresolved") }
        try directory.remove("resources.present")
    }
    public static func hasUnresolvedOutcome(_ state: WorkspaceDesiredState) -> Bool {
        for raw in state.retained + (state.current.map { [$0] } ?? []) {
            guard let frame = try? WorkspaceControl.decode(raw) else { return true }
            let statuses = frame.statusReply.mounts + frame.statusReply.retired.filter(\.hasMountStatus).map(\.mountStatus)
            if statuses.contains(where: { !$0.loss.isEmpty || $0.outcome.durability != "durable" || $0.outcome.observation != "observed" || !["released", "expired"].contains($0.outcome.release) || $0.outcome.cleanupDebt != 0 }) { return true }
        }
        return false
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

            try commit { $0.execution = nil }
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
