import FSKit
import Foundation
import PortableFSKit

/// Sendable ownership wrapper for the framework-managed `FSItem` retained by
/// the exact volume's live-object index. An equivalent path or newly-created
/// item is never accepted as a cache invalidation target.
public struct PfsFSKit27ItemReference: @unchecked Sendable {
    fileprivate let item: FSItem

    public init(item: FSItem) {
        self.item = item
    }
}

private final class PfsFSKit27WeakVolume<Volume>: @unchecked Sendable
where Volume: FSVolume, Volume: FSVolume.DataCacheHandler {
    weak var value: Volume?

    init(_ value: Volume) {
        self.value = value
    }
}

/// Concrete SDK-27 implementation of PortableFS's data-only native cache
/// boundary. `setCacheState` is synchronous; success means the kernel applied
/// the transition before this method returns. Namespace and attribute methods
/// are intentionally absent because SDK 27 exposes no such operation.
public final class PfsFSKit27DataCacheInvalidator:
    PfsFSKitNativeDataCacheInvalidator,
    @unchecked Sendable
{
    public typealias ItemResolver = @Sendable (
        PfsFSKitNativeDataInvalidation
    ) async throws -> PfsFSKit27ItemReference

    private let resolveItem: ItemResolver
    private let invalidate: @Sendable (FSItem) throws -> Void

    public init<Volume>(
        volume: Volume,
        resolveItem: @escaping ItemResolver
    ) where Volume: FSVolume, Volume: FSVolume.DataCacheHandler {
        let weakVolume = PfsFSKit27WeakVolume(volume)
        self.resolveItem = resolveItem
        self.invalidate = { item in
            guard let volume = weakVolume.value else {
                throw PfsMacOSCoherenceError.nativeRevocationUnavailable
            }
            if let error = volume.setCacheState(
                for: item,
                cacheMode: .none,
                coherencyType: .noCache,
                action: .invalidate
            ) {
                throw error
            }
        }
    }

    public func invalidate(
        _ target: PfsFSKitNativeDataInvalidation
    ) async throws {
        let reference = try await resolveItem(target)
        try invalidate(reference.item)
    }
}

@available(macOS 27.0, *)
private func pfsNativeCacheRequest(
    _ mode: FSVolume.DataCacheMode
) throws -> PfsFSKitNativeDataCacheRequest {
    switch mode {
    case .none:
        .none
    case .readWithCache:
        .read
    case .readWriteWithCache:
        .readWrite
    @unknown default:
        throw PfsMacOSCoherenceError.nativeRevocationUnavailable
    }
}

@available(macOS 27.0, *)
private func pfsKernelCacheGrant(
    _ grant: PfsFSKitNativeDataCacheGrant
) -> FSVolume.KernelCacheCoherencyType {
    switch grant {
    case .noCache:
        .noCache
    case .readCache:
        .readCache
    case .writeThrough:
        .writeThrough
    }
}

@available(macOS 27.0, *)
extension PortableFSVolume: @retroactive FSVolume.DataCacheHandler {
    public var isDataCacheInhibited: Bool { false }

    public func open(
        _ item: FSItem,
        modes: FSVolume.OpenModes,
        cacheMode: FSVolume.DataCacheMode,
        context _: FSContext,
        replyHandler reply: @escaping @Sendable (
            FSOpenItemResult?, (any Error)?
        ) -> Void
    ) {
        // Validate the kernel's requested cache shape before acquiring an
        // authority handle. An unknown future enum case must not turn a
        // successfully opened remote descriptor into a leaked handle when the
        // cache negotiation is subsequently refused.
        let grant: PfsFSKitNativeDataCacheGrant
        do {
            let request = try pfsNativeCacheRequest(cacheMode)
            grant = PfsFSKitNativeDataCachePolicy.grant(for: request)
        } catch {
            reply(nil, PfsErrorMapper.fsKitError(for: error))
            return
        }
        // `openItem` owns callback ingress and invokes this closure as its
        // framework reply. Calling DataCacheHandler's real reply from inside
        // it makes the shared barrier publish only after FSKit has received
        // the granted cache state; a Swift continuation cannot prove that edge.
        openItem(item, modes: modes) { error in
            if let error {
                reply(nil, error)
            } else {
                // FSKit result objects are not Sendable. Construct one only
                // at the actual framework reply edge rather than carrying it
                // through callback publication admission.
                reply(
                    FSOpenItemResult(
                        grantedCoherency: pfsKernelCacheGrant(grant)
                    ),
                    nil
                )
            }
        }
    }

    public func close(
        _ item: FSItem,
        context _: FSContext,
        replyHandler reply: @escaping @Sendable () -> Void
    ) {
        // This shared wrapper awaits terminal shutdown on authority-close
        // failure and invokes the real no-error FSKit reply at the outer
        // publication edge.
        closeNativeDataCacheItem(item, replyHandler: reply)
    }

    public func upgrade(
        _ item: FSItem,
        cacheMode: FSVolume.DataCacheMode,
        context _: FSContext,
        replyHandler reply: @escaping @Sendable (
            FSUpgradeItemResult?, (any Error)?
        ) -> Void
    ) {
        let grant: PfsFSKitNativeDataCacheGrant
        do {
            let request = try pfsNativeCacheRequest(cacheMode)
            grant = PfsFSKitNativeDataCachePolicy.grant(for: request)
        } catch {
            reply(nil, PfsErrorMapper.fsKitError(for: error))
            return
        }
        admitNativeDataCacheUpgrade(item) { error in
            if let error {
                reply(nil, error)
            } else {
                // The Sendable value crosses admission; the framework-owned
                // non-Sendable result does not.
                reply(
                    FSUpgradeItemResult(
                        grantedCoherency: pfsKernelCacheGrant(grant)
                    ),
                    nil
                )
            }
        }
    }
}

/// SDK-27 composition root. Resource routing and filesystem operations remain
/// shared with macOS 26; only the declared native policy, cache driver, and
/// exact native coherence backend are selected here.
@available(macOS 27.0, *)
public enum PortableFSKitMacOS27Adapter {
    public static func makeFileSystem(
        resolverFactory: @escaping @Sendable () -> PfsSocketPathResolver = {
            PfsSocketPathResolver(bundle: .main)
        }
    ) -> PortableFSFileSystem {
        PortableFSFileSystem(
            resolverFactory: resolverFactory,
            volumeFactory: makeVolume
        )
    }

    public static func makeVolume(
        socketPath: String,
        attachRef: String,
        moduleIdentity: PortableFSModuleIdentity
    ) async throws -> PortableFSVolume {
        let core = try await VolumeCore.connect(
            socketPath: socketPath,
            attachRef: attachRef,
            supportedCachePolicies: [.nativeFSKitRevocationV1]
        )
        let volume = try await PortableFSVolume.makeNative(
            core: core,
            attachRef: attachRef,
            moduleIdentity: moduleIdentity
        )
        do {
            let invalidator = PfsFSKit27DataCacheInvalidator(
                volume: volume,
                resolveItem: { target in
                    PfsFSKit27ItemReference(
                        item: try await volume.nativeDataItem(for: target)
                    )
                }
            )
            try await volume.startNativeCoherence(with: invalidator)
            return volume
        } catch {
            await volume.shutdown()
            throw error
        }
    }
}
