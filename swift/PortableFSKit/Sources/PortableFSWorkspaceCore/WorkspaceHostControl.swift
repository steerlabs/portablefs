import CryptoKit
import Foundation
import PortableFSAppCore

public enum WorkspaceHostControl {
    public static let version = 1
    public static let maxFrame = 2 << 20
    public static let maxDocument = 512 << 10
    public static let starting = "Starting Linux Workspace…"
    public static let running = "Linux Workspace: Running"
    public static let authorizationRequired = "Authorization required"
    public static let busy = "Volume is in use. Close its terminals and editor windows, then try again."
    public static let macConflict = "This volume is mounted on your Mac. Unmount it there before using it in Linux."
    public static let linuxConflict = "This volume is in Linux. Remove it from Linux before mounting it on your Mac."
    public static func validVolume(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 128 && value != "." && value != ".." && value.utf8.allSatisfy {
            (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || [45, 46, 95].contains($0)
        }
    }
    public static func authorityIdentity(_ name: String) throws -> String {
        var canonical = name.lowercased()
        if canonical.hasSuffix(".") { canonical.removeLast() }
        guard !canonical.isEmpty, canonical.utf8.count <= 253,
              canonical.utf8.allSatisfy({ (33...126).contains($0) && ![47, 92].contains($0) }) else { throw WorkspaceControlError.grammar }
        return SHA256.hash(data: Data(("portablefs-authority-identity/8\0" + canonical).utf8)).map { String(format: "%02x", $0) }.joined()
    }
    public static func encode<T: Encodable>(_ value: T) throws -> Data {
        let encoder = JSONEncoder(); encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        let data = try encoder.encode(value)
        guard !data.isEmpty, data.count <= maxFrame else { throw WorkspaceControlError.grammar }
        return data
    }
    public static func object(_ value: Any?, keys: Set<String>) throws -> [String: Any] {
        guard let object = value as? [String: Any], Set(object.keys).isSubset(of: keys), !object.values.contains(where: { $0 is NSNull }) else { throw WorkspaceControlError.grammar }
        return object
    }
    public static func decodeRequest(_ data: Data) throws -> WorkspaceHostRequest {
        guard data.count <= maxFrame else { throw WorkspaceControlError.grammar }
        try PortableFSDStrictJSON.validate(data)
        let value = try object(JSONSerialization.jsonObject(with: data), keys: ["version", "operation", "document", "volumeId", "force"])
        if let document = value["document"] { try WorkspaceConnectionDocument.validateShape(document) }
        let request = try JSONDecoder().decode(WorkspaceHostRequest.self, from: data)
        try request.validate(); return request
    }
}
public struct WorkspaceHostRequest: Codable, Sendable {
    public var version: Int
    public var operation: String
    public var document: WorkspaceConnectionDocument?
    public var volumeId: String?
    public var force: Bool?
    public func validate() throws {
        guard version == 1 else { throw WorkspaceControlError.grammar }
        switch operation {
        case "start", "status": guard document == nil, volumeId == nil, force != true else { throw WorkspaceControlError.grammar }
        case "stop": guard document == nil, volumeId == nil else { throw WorkspaceControlError.grammar }
        case "mount": guard let document, volumeId == nil, force != true else { throw WorkspaceControlError.grammar }; try document.validate()
        case "umount": guard document == nil, let volumeId, WorkspaceHostControl.validVolume(volumeId) else { throw WorkspaceControlError.grammar }
        default: throw WorkspaceControlError.grammar
        }
    }
}
public struct WorkspaceHostReply: Codable, Sendable {
    public var version = 1
    public var state = "stopped"
    public var message = "Linux Workspace: Stopped"
    public var desiredRunning = false
    public var someChangesWereNotSaved = false
    public var previousWriteOutcomeUnknown = false
    public var volumes: [WorkspaceHostVolume] = []
    public init() {}
}
public struct WorkspaceHostVolume: Codable, Sendable {
    public var volumeId: String
    public var path: String
    public var state: String
    public var message: String
    public var evidence: Data?
    public var authorizationRequest: String?
    public init(volume: String, state: String, message: String) {
        volumeId = volume; path = "/workspaces/" + volume; self.state = state; self.message = message
    }
}
public struct WorkspaceConnection: Codable, Equatable, Sendable {
    public var authority: String
    public var volumeId: String
    public var endpoint: String
    public var serverName: String
    public var caCertificate: Data
    public var routesRevision: Data
    public var hosted: Bool
    public func validate() throws {
        guard authority == (try WorkspaceHostControl.authorityIdentity(serverName)), WorkspaceHostControl.validVolume(volumeId),
              !caCertificate.isEmpty, caCertificate.count <= 65_536, WorkspaceControl.digest(routesRevision),
              endpoint.utf8.count <= 4096,
              let url = URL(string: "tls://" + endpoint), url.user == nil, url.password == nil, url.path.isEmpty,
              let port = url.port, (1...65535).contains(port), let host = url.host,
              !["localhost", "127.0.0.1", "::1", "[::1]", "0.0.0.0", "::", "[::]"].contains(host.lowercased()) else { throw WorkspaceControlError.grammar }
    }
}
public struct WorkspaceConnectionDocument: Codable, Equatable, Sendable {
    public var version: Int
    public var kind: String
    public var connection: WorkspaceConnection
    public var intent: String?
    public var identity: Data?
    public var authorization: Data?
    public var renewalScope: String?
    public var renewalEpoch: String?
    public init(connection: WorkspaceConnection, intent: String, identity: WorkspaceIdentityReply) throws {
        version = 1; kind = "request"; self.connection = connection; self.intent = intent
        var frame = WorkspaceEnvelope(); frame.version = 8; frame.requestID = 1; frame.identityReply = identity
        self.identity = try WorkspaceControl.encode(frame)
        if connection.hosted {
            renewalScope = Self.scope(identity); renewalEpoch = String(identity.renewalEpoch)
        }
    }
    static func validateShape(_ value: Any) throws {
        let document = try WorkspaceHostControl.object(value, keys: ["version", "kind", "connection", "intent", "identity", "authorization", "renewalScope", "renewalEpoch"])
        _ = try WorkspaceHostControl.object(document["connection"], keys: ["authority", "volumeId", "endpoint", "serverName", "caCertificate", "routesRevision", "hosted"])
    }
    public func validate() throws {
        guard version == 1 else { throw WorkspaceControlError.grammar }
        try connection.validate()
        if kind == "connection" {
            guard intent == nil, identity == nil, authorization == nil, renewalScope == nil, renewalEpoch == nil else { throw WorkspaceControlError.grammar }; return
        }
        guard kind == "request" || kind == "authorization", let intent, intent.count == 32,
              intent.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }), intent.contains(where: { $0 != "0" }) else { throw WorkspaceControlError.grammar }
        let guest = try guestIdentity()
        if connection.hosted {
            guard renewalScope == Self.scope(guest), renewalEpoch == String(guest.renewalEpoch) else { throw WorkspaceControlError.grammar }
        } else { guard renewalScope == nil, renewalEpoch == nil else { throw WorkspaceControlError.grammar } }
        guard guest.mount.authorityID.map({ String(format: "%02x", $0) }).joined() == connection.authority,
              guest.mount.volumeID == connection.volumeId else { throw WorkspaceControlError.grammar }
        if kind == "request" { guard authorization == nil else { throw WorkspaceControlError.grammar }; return }
        let provision = try provision()
        guard provision.mount == guest.mount, provision.publicKey == guest.publicKey,
              provision.authorityEndpoint == connection.endpoint, provision.serverName == connection.serverName,
              provision.caCertificate == connection.caCertificate, provision.routesRevision == connection.routesRevision,
              provision.hasHostedEnrollment == connection.hosted else { throw WorkspaceControlError.grammar }
    }
    public func guestIdentity() throws -> WorkspaceIdentityReply {
        guard let identity else { throw WorkspaceControlError.grammar }
        let frame = try WorkspaceControl.decode(identity)
        guard frame.requestID == 1, case .identityReply(let reply) = frame.body else { throw WorkspaceControlError.grammar }
        return reply
    }
    public func provision() throws -> WorkspaceProvision {
        guard let authorization else { throw WorkspaceControlError.grammar }
        let frame = try WorkspaceControl.decode(authorization)
        guard frame.requestID == 1, case .provision(let provision) = frame.body else { throw WorkspaceControlError.grammar }
        return provision
    }
    private static func scope(_ identity: WorkspaceIdentityReply) -> String {
        func uuid(_ data: Data) -> String {
            let h = data.map { String(format: "%02x", $0) }.joined()
            return [String(h.prefix(8)), String(h.dropFirst(8).prefix(4)), String(h.dropFirst(12).prefix(4)), String(h.dropFirst(16).prefix(4)), String(h.dropFirst(20))].joined(separator: "-")
        }
        return "portablefs-linux-workspace/8/" + uuid(identity.guestUuid) + "/" + uuid(identity.identityIncarnation)
    }
    public func matchesRequest(_ request: Self) -> Bool {
        var a = self, b = request
        a.kind = "request"; a.authorization = nil; b.kind = "request"; b.authorization = nil
        return a == b
    }
}
