import Foundation

/// Presentation-safe row emitted by `portablefs mounts --json`.
///
/// The CLI intentionally omits credentials and other daemon persistence
/// details. Additive fields decode with conservative defaults so an older CLI
/// remains readable while cleanup intents are never mistaken for live mounts.
public struct PortableFSMountInventoryRow: Decodable, Sendable, Identifiable, Equatable {
    public let mountPath: String
    public let volumeId: String
    public let branch: String
    public let attachRef: String?
    public let health: String
    public let cleanupRequired: Bool
    public let operationPhase: String

    public var id: String {
        mountPath
    }

    public var requiresCleanup: Bool {
        cleanupRequired || health == "cleanup-required"
    }

    private enum CodingKeys: String, CodingKey {
        case mountPath
        case volumeId
        case branch
        case attachRef
        case health
        case cleanupRequired
        case operationPhase
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        mountPath = try container.decode(String.self, forKey: .mountPath)
        volumeId = try container.decode(String.self, forKey: .volumeId)
        branch = try container.decode(String.self, forKey: .branch)
        attachRef = try container.decodeIfPresent(String.self, forKey: .attachRef)
        health = try container.decode(String.self, forKey: .health)
        cleanupRequired = try container.decodeIfPresent(Bool.self, forKey: .cleanupRequired) ?? false
        operationPhase = try container.decodeIfPresent(String.self, forKey: .operationPhase) ?? ""
    }
}
