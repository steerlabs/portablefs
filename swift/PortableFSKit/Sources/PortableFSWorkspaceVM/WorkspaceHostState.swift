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
    }
    public func commit(_ update: (inout WorkspaceDesiredState) throws -> Void) throws {
        var next = value; try update(&next)
        let raw = try WorkspaceHostControl.encode(next)
        guard raw.count <= 2 << 20 else { throw WorkspaceVMError("workspace evidence capacity reached") }
        try directory.write("desired.json", data: raw); value = next
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
