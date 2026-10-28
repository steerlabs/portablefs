import Darwin
import Foundation

public struct PortableFSWorkspaceOutcome: Codable, Equatable, Sendable, Identifiable {
    public var id: String
    public var someChangesWereNotSaved: Bool
    public var previousWriteOutcomeUnknown: Bool
    public var details: String
    public var volumeId: String? {
        guard let volume = id.split(separator: "/").last, volume != "-" else { return nil }
        return String(volume)
    }
    public var message: String {
        [someChangesWereNotSaved ? "Some changes were not saved" : nil,
         previousWriteOutcomeUnknown ? "Previous write outcome unknown" : nil].compactMap { $0 }.joined(separator: "; ")
    }
    public init(id: String, lost: Bool, unknown: Bool, details: String = "") {
        self.id = id; someChangesWereNotSaved = lost; previousWriteOutcomeUnknown = unknown; self.details = details
    }
    public static func validID(_ id: String) -> Bool {
        let fields = id.split(separator: "/", omittingEmptySubsequences: false)
        guard fields.count == 3, let sequence = UInt64(fields[0]), sequence > 0, String(sequence) == fields[0],
              PortableFSWorkspaceStatus.validIncarnation(String(fields[1])) else { return false }
        return fields[2] == "-" || PortableFSWorkspaceStatus.validVolume(String(fields[2]))
    }
}

public struct PortableFSWorkspaceStatus: Codable, Sendable {
    public var version = 1
    public var state = "stopped"
    public var message = "Linux Workspace: Stopped"
    public var desiredRunning = false
    public var someChangesWereNotSaved = false
    public var previousWriteOutcomeUnknown = false
    public var retainedEvidence: [Data] = []
    public var outcomes: [PortableFSWorkspaceOutcome] = []
    public var volumes: [PortableFSWorkspaceVolume] = []
    public init() {}
    public var canConnect: Bool { state == "running" }
    public var showsStop: Bool { desiredRunning || ["running", "starting", "reconnecting", "pending", "cleanup-required"].contains(state) }
    public var notices: [String] {
        (someChangesWereNotSaved ? ["Some changes were not saved"] : []) +
        (previousWriteOutcomeUnknown ? ["Previous write outcome unknown"] : [])
    }
    public static func decode(_ data: Data) throws -> Self {
        guard data.count <= 4 << 20 else { throw PortableFSWorkspaceError("Invalid workspace response") }
        try PortableFSDStrictJSON.validate(data)
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys).isSubset(of: ["version", "state", "message", "desiredRunning", "someChangesWereNotSaved", "previousWriteOutcomeUnknown", "retainedEvidence", "outcomes", "volumes"]),
              let outcomes = object["outcomes"] as? [[String: Any]],
              outcomes.allSatisfy({ Set($0.keys) == ["id", "someChangesWereNotSaved", "previousWriteOutcomeUnknown", "details"] && !$0.values.contains(where: { $0 is NSNull }) }),
              let rows = object["volumes"] as? [[String: Any]],
              rows.allSatisfy({ Set($0.keys).isSubset(of: ["volumeId", "path", "state", "message", "evidence", "authorizationRequest", "reopenId"]) && !$0.values.contains(where: { $0 is NSNull }) }),
              !object.values.contains(where: { $0 is NSNull }) else { throw PortableFSWorkspaceError("Invalid workspace response") }
        let value = try JSONDecoder().decode(Self.self, from: data)
        guard value.version == 1, ["stopped", "starting", "running", "pending", "reconnecting", "cleanup-required", "refused", "busy"].contains(value.state),
              value.outcomes.count <= 128, Set(value.outcomes.map(\.id)).count == value.outcomes.count,
              value.outcomes.allSatisfy({ PortableFSWorkspaceOutcome.validID($0.id) && ($0.someChangesWereNotSaved || $0.previousWriteOutcomeUnknown) && $0.details.utf8.count <= 32768 }),
              value.volumes.count <= 64, Set(value.volumes.map(\.volumeId)).count == value.volumes.count,
              value.volumes.allSatisfy({ ($0.reopenId == nil || validIncarnation($0.reopenId ?? "") && $0.state == "ready" && $0.requiresReopen) && $0.path == "/workspaces/" + $0.volumeId && validVolume($0.volumeId) && ["stopped", "authorization-required", "ready", "busy", "terminal", "pending"].contains($0.state) }) else { throw PortableFSWorkspaceError("Invalid workspace response") }
        return value
    }
    public static func validIncarnation(_ value: String) -> Bool {
        value.utf8.count == 32 && value.contains(where: { $0 != "0" }) &&
        value.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) }
    }
    public static func validVolume(_ value: String) -> Bool {
        !value.isEmpty && value.utf8.count <= 128 && value != "." && value != ".." && value.utf8.allSatisfy {
            (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || [45, 46, 95].contains($0)
        }
    }
}

public struct PortableFSWorkspaceVolume: Codable, Sendable, Identifiable {
    public var volumeId: String
    public var path: String
    public var state: String
    public var message: String
    public var evidence: Data?
    public var authorizationRequest: String?
    public var reopenId: String?
    public var id: String { volumeId }
    public var requiresAuthorization: Bool { state == "authorization-required" || state == "terminal" }
    public var requiresReopen: Bool { message == "Reconnect your editor and reopen this folder." }
    public var canOpen: Bool { state == "ready" || state == "busy" }
    public init(volume: String, state: String, message: String) {
        volumeId = volume; path = "/workspaces/" + volume; self.state = state; self.message = message
    }
}

/// The menu uses the same authenticated operational-v1 endpoint as the CLI.
/// Blocking connect/framing and signature checks stay off the presentation actor.
public struct PortableFSWorkspaceClient: Sendable {
    public enum Operation: String, Sendable {
        case start, status, mount, umount, stop, dismiss
        case dismissReopen = "dismiss-reopen"
    }
    private let bundleURL: URL
    public let home: URL
    public init(bundle: Bundle = .main, home: URL) { bundleURL = bundle.bundleURL; self.home = home }
    public func perform(_ operation: Operation, document: Data? = nil, volume: String? = nil, force: Bool = false, outcomeID: String? = nil, reopenID: String? = nil) async throws -> PortableFSWorkspaceStatus {
        try await Task.detached {
            var request: [String: Any] = ["version": 1, "operation": operation.rawValue]
            if let document {
                guard operation == .mount, document.count <= 512 << 10 else { throw PortableFSWorkspaceError("Invalid workspace document") }
                try PortableFSDStrictJSON.validate(document)
                request["document"] = try JSONSerialization.jsonObject(with: document)
            }
            if let volume {
                guard operation == .umount || operation == .dismissReopen, PortableFSWorkspaceStatus.validVolume(volume) else { throw PortableFSWorkspaceError("Invalid workspace volume") }
                request["volumeId"] = volume
            }
            if let outcomeID {
                guard operation == .dismiss, PortableFSWorkspaceOutcome.validID(outcomeID) else { throw PortableFSWorkspaceError("Invalid workspace outcome") }
                request["outcomeId"] = outcomeID
            }
            if let reopenID {
                guard operation == .dismissReopen, volume != nil, PortableFSWorkspaceStatus.validIncarnation(reopenID) else { throw PortableFSWorkspaceError("Invalid workspace reopen notice") }
                request["reopenId"] = reopenID
            }
            if force { guard operation == .stop || operation == .umount else { throw PortableFSWorkspaceError("Invalid workspace action") }; request["force"] = true }
            let path = home.appendingPathComponent(".local/state/portablefs/workspace/control.sock").path
            var info = stat()
            if operation == .status, lstat(path, &info) != 0, errno == ENOENT {
                let desired = home.appendingPathComponent(".local/state/portablefs/workspace/desired.json").path
                let noState = lstat(desired, &info) != 0 && errno == ENOENT
                guard try noState || WorkspaceRemoval.completed(home: home) else { throw PortableFSWorkspaceError("Cleanup required: Linux Workspace service is unavailable") }
                return PortableFSWorkspaceStatus()
            }
            let data = try JSONSerialization.data(withJSONObject: request, options: [.sortedKeys, .withoutEscapingSlashes])
            let deadline = ContinuousClock.now.advanced(by: .seconds(20))
            while true {
                do { return try PortableFSWorkspaceStatus.decode(exchange(data, path: path)) }
                catch {
                    // As in the CLI, only endpoint absence after registration
                    // permits a new dial. Identity/framing failures never retry.
                    guard operation == .start || operation == .mount,
                          lstat(path, &info) != 0, errno == ENOENT,
                          ContinuousClock.now < deadline else { throw error }
                    try await Task.sleep(for: .milliseconds(50))
                }
            }
        }.value
    }
    private func exchange(_ request: Data, path: String) throws -> Data {
        guard let bundle = Bundle(url: bundleURL) else { throw PortableFSSignedServiceError.invalidBundle }
        let release = try PortableFSSignedRelease(bundle: bundle)
        let service = release.bundleURL.appendingPathComponent("Contents/Library/LaunchAgents/PortableFSWorkspaceService.app/Contents/MacOS/portablefs-workspace-service")
        let hash = try PortableFSSignedRelease.codeHash(service)
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else { throw PortableFSWorkspaceError("Cannot connect to Linux Workspace") }
        let connection = PortableFSDUpdateConnection(descriptor: fd, peerPID: 0, frameLimit: 4 << 20)
        defer { connection.close() }
        guard fcntl(fd, F_SETFD, FD_CLOEXEC) == 0 else { throw PortableFSSignedServiceError.invalidIdentity }
        try PortableFSDUpdateListener.connectBounded(fd, to: path, timeoutMilliseconds: 2_000)
        let peer = try PortableFSDServiceCoordinator.captureDaemonPeer(fd)
        defer { peer.processWitness.close() }
        try PortableFSDServiceCoordinator.requireRunningImage(peer, expectedPath: service.path, expectedCDHash: hash)
        try connection.prepareBoundedIO()
        var frame = request; frame.append(10)
        try connection.writeFrame(frame)
        return try connection.readFrame().dropLast()
    }
    public func quiesce() async throws {
        try await Task.detached {
            let request = Data("{\"lifecycleVersion\":1,\"operation\":\"quiesce\"}".utf8)
            let data = try exchange(request, path: home.appendingPathComponent(".local/state/portablefs/workspace/control.sock").path)
            try PortableFSDStrictJSON.validate(data)
            guard let reply = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                  reply["lifecycleVersion"] as? Int == 1, reply["state"] as? String == "quiesced",
                  reply["executionPresent"] as? Bool == false, reply["desiredRunning"] as? Bool == false else { throw PortableFSWorkspaceError("Cleanup required") }
        }.value
    }
}
