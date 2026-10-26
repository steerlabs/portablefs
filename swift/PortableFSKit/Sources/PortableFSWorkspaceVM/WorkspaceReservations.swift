import Foundation
import PortableFSAppCore
import PortableFSWorkspaceCore

public struct WorkspaceReservation: Codable, Equatable {
    public var authority: String
    public var volume: String
    public var frontend: String
    public var owner: String
    public init(authority: String, volume: String, frontend: String = "workspace", owner: String) {
        self.authority = authority; self.volume = volume; self.frontend = frontend; self.owner = owner
    }
    func validate() throws {
        guard authority.count == 64, authority.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) }), authority.contains(where: { $0 != "0" }),
              WorkspaceHostControl.validVolume(volume), ["fskit", "workspace"].contains(frontend), !owner.isEmpty, owner.utf8.count <= 128,
              !owner.contains(where: { $0 == "\0" || $0 == "\r" || $0 == "\n" }) else { throw WorkspaceControlError.grammar }
    }
}
public final class WorkspaceReservations {
    private struct State: Codable { var version = 1; var reservations: [WorkspaceReservation] = [] }
    private let directory: WorkspacePrivateDirectory
    private let lock: WorkspaceFileLock
    private var state = State()
    public init(directory: URL) throws {
        self.directory = try WorkspacePrivateDirectory(directory)
        lock = try self.directory.lock("mount-transition.lock")
        if let raw = try self.directory.read("volume-reservations.json", limit: 1 << 20) {
            try PortableFSDStrictJSON.validate(raw)
            let root = try WorkspaceHostControl.object(JSONSerialization.jsonObject(with: raw), keys: ["version", "reservations"])
            guard let entries = root["reservations"] as? [[String: Any]] else { throw WorkspaceControlError.grammar }
            for entry in entries { _ = try WorkspaceHostControl.object(entry, keys: ["authority", "volume", "frontend", "owner"]) }
            state = try JSONDecoder().decode(State.self, from: raw)
        }
        guard state.version == 1, state.reservations.count <= 128 else { throw WorkspaceControlError.grammar }
        var seen = Set<String>()
        for entry in state.reservations {
            try entry.validate()
            guard seen.insert(entry.authority + "/" + entry.volume).inserted else { throw WorkspaceControlError.grammar }
        }
    }
    public var inventory: [WorkspaceReservation] { state.reservations }
    public func reserve(_ reservation: WorkspaceReservation) throws {
        try reservation.validate()
        for old in state.reservations where old.authority == reservation.authority && old.volume == reservation.volume || old.frontend == "workspace" && reservation.frontend == "workspace" && old.volume == reservation.volume {
            if old == reservation { return }
            if old.frontend != reservation.frontend { throw WorkspaceVMError(reservation.frontend == "workspace" ? WorkspaceHostControl.macConflict : WorkspaceHostControl.linuxConflict) }
            throw WorkspaceVMError("Cleanup required")
        }
        guard state.reservations.count < 128 else { throw WorkspaceVMError("reservation capacity reached") }
        state.reservations.append(reservation); try persist()
    }
    public func release(_ reservation: WorkspaceReservation) throws {
        try reservation.validate()
        if let old = state.reservations.first(where: { $0.authority == reservation.authority && $0.volume == reservation.volume }), old != reservation { throw WorkspaceVMError("reservation owner mismatch") }
        state.reservations.removeAll { $0 == reservation }; try persist()
    }
    private func persist() throws {
        state.reservations.sort { $0.authority + "/" + $0.volume < $1.authority + "/" + $1.volume }
        try directory.write("volume-reservations.json", data: WorkspaceHostControl.encode(state))
    }
}
