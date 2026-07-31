import Foundation
import FSKit
import Testing
@testable import PortableFSKit

@Test func liveRootResolveGetattrAndEnumeration() async throws {
    let environment = ProcessInfo.processInfo.environment
    guard
        let socketPath = environment["PFS_LIVE_SOCKET"],
        let attachRef = environment["PFS_LIVE_ATTACH_REF"]
    else {
        return
    }

    let core = try await VolumeCore.connect(
        socketPath: socketPath,
        attachRef: attachRef
    )
    let root = try await core.rootItem()
    let attributes = try await core.getattr(item: root)
    #expect(attributes.kind == .directory)
    #expect(attributes.item.itemID == root.identity.itemID)
    #expect(attributes.item.itemGeneration == root.identity.generation)

    if #available(macOS 26.0, *) {
        let expectedRootIdentifier = try PfsFSKitMapping.itemIdentifier(
            from: root.identity.itemID
        )
        #expect(expectedRootIdentifier == .rootDirectory)

        try await withThrowingTaskGroup(of: Void.self) { group in
            for _ in 0..<32 {
                group.addTask {
                    _ = try await core.getattr(item: root)
                }
            }
            try await group.waitForAll()
        }
        let volume = try await PortableFSVolume.make(
            core: core,
            attachRef: attachRef,
            moduleIdentity: PortableFSModuleIdentity(
                fileSystemTypeName: PortableFSIdentity.fileSystemTypeName,
                resourceScheme: PortableFSIdentity.resourceScheme
            )
        )
        let fetchRootAttributes: @Sendable () async throws -> Void = {
            let _: Void = try await withCheckedThrowingContinuation {
                continuation in
                volume.getAttributes(
                    FSItem.GetAttributesRequest(),
                    of: root
                ) { attributes, error in
                    if let error {
                        continuation.resume(throwing: error)
                    } else if let attributes,
                              attributes.isValid(.type),
                              attributes.isValid(.fileID),
                              attributes.type == .directory,
                              attributes.fileID == expectedRootIdentifier {
                        continuation.resume()
                    } else {
                        continuation.resume(
                            throwing: PfsLocalClientError.unexpectedReply(
                                "getAttributes returned invalid root attributes"
                            )
                        )
                    }
                }
            }
        }
        try await withThrowingTaskGroup(of: Void.self) { group in
            for _ in 0..<32 {
                group.addTask {
                    try await fetchRootAttributes()
                }
            }
            try await group.waitForAll()
        }
    }
}
