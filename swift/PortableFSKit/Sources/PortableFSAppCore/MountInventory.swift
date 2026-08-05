import Foundation

/// Presentation-safe row emitted by `portablefs mounts --json`.
///
/// The CLI intentionally omits credentials and other daemon persistence
/// details. `branch` is deliberately not read: a v3 volume is branchless, so
/// the field the CLI still emits is always empty and naming it in the UI would
/// promise a branch graph that does not exist. Additive fields decode with
/// conservative defaults so an older CLI remains readable while cleanup
/// intents are never mistaken for live mounts.
public struct PortableFSMountInventoryRow: Decodable, Sendable, Identifiable, Equatable {
    public let mountPath: String
    public let volumeId: String
    public let attachRef: String?
    public let health: String
    public let cleanupRequired: Bool
    public let operationPhase: String
    /// The daemon's own verdict for this attach, as the CLI read it from the
    /// control socket. `attachState` is empty when the daemon was not
    /// consulted (a FUSE mount, or a row that is only a cleanup intent);
    /// `attachError` names why a degraded attach is degraded, which prose in
    /// `health` alone never does.
    public let attachState: String
    public let attachError: String

    public var id: String {
        mountPath
    }

    public var requiresCleanup: Bool {
        cleanupRequired || health == "cleanup-required"
    }

    private enum CodingKeys: String, CodingKey {
        case mountPath
        case volumeId
        case attachRef
        case health
        case cleanupRequired
        case operationPhase
        case attachState
        case attachError
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        mountPath = try container.decode(String.self, forKey: .mountPath)
        volumeId = try container.decode(String.self, forKey: .volumeId)
        attachRef = try container.decodeIfPresent(String.self, forKey: .attachRef)
        health = try container.decode(String.self, forKey: .health)
        cleanupRequired = try container.decodeIfPresent(Bool.self, forKey: .cleanupRequired) ?? false
        operationPhase = try container.decodeIfPresent(String.self, forKey: .operationPhase) ?? ""
        attachState = try container.decodeIfPresent(String.self, forKey: .attachState) ?? ""
        attachError = try container.decodeIfPresent(String.self, forKey: .attachError) ?? ""
    }
}
