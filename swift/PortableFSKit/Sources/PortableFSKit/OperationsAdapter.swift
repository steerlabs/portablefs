import Foundation
import FSKit
import CryptoKit
import OSLog
import os
@preconcurrency import Darwin
@preconcurrency import Dispatch

private struct PfsFSKitCallbackTrace: Sendable {
    private static let signposter = OSSignposter(
        subsystem: "dev.portablefs.fskit",
        category: "CallbackLifecycle"
    )

    let kind: String
    let ingressUptimeNanoseconds: UInt64
    private let interval: (OSSignpostID, OSSignpostIntervalState)?

    init(
        kind: StaticString,
        scope: PfsMacOSCallbackScope
    ) {
        let kindDescription = String(describing: kind)
        self.kind = kindDescription
        ingressUptimeNanoseconds = DispatchTime.now().uptimeNanoseconds
        guard Self.signposter.isEnabled else {
            interval = nil
            return
        }
        let id = Self.signposter.makeSignpostID()
        let state = Self.signposter.beginInterval(
            "FSKitCallback",
            id: id,
            "kind=\(kindDescription, privacy: .public) scope=\(scope.diagnosticSummary, privacy: .public)"
        )
        interval = (id, state)
    }

    func emit(_ name: StaticString, detail: String = "") {
        guard let (id, _) = interval else { return }
        Self.signposter.emitEvent(
            name,
            id: id,
            "kind=\(kind, privacy: .public) \(detail, privacy: .public)"
        )
    }

    func finish(outcome: String) {
        guard let (_, state) = interval else { return }
        Self.signposter.endInterval(
            "FSKitCallback",
            state,
            "kind=\(kind, privacy: .public) outcome=\(outcome, privacy: .public)"
        )
    }
}

private final class PfsUncheckedSendableBox<Value>: @unchecked Sendable {
    let value: Value

    init(_ value: Value) {
        self.value = value
    }
}

private extension Result {
    var pfsIsSuccess: Bool {
        if case .success = self { return true }
        return false
    }
}

/// Carries an attribute-refresh admission decision into the callback body. The
/// admission closure always runs before the body, but they may cross executor
/// hops; keeping the attested snapshot here makes the decision immutable.
private actor PfsAttributeRefreshCallbackPreflight {
    private var attributes: PfsAttr?

    func record(_ attributes: PfsAttr) {
        self.attributes = attributes
    }

    func take() -> PfsAttr? {
        defer { attributes = nil }
        return attributes
    }
}

struct PfsSyntheticDirectoryEntry: Sendable, Equatable {
    var name: Data
    var nextCookie: UInt64
    /// `".."` must be packed with the parent's identifier, not the enumerated
    /// directory's own. The name is the only thing distinguishing them, so the
    /// planner records the distinction rather than making the packer re-parse.
    var isParentEntry: Bool = false
}

enum PfsEnumerationCookies {
    static let daemonPageSize: UInt32 = 256
    private static let dotCookie: UInt64 = 0
    static let dotDotCookie: UInt64 = 1
    static let entriesStartCookie: UInt64 = 2
    static let daemonCookieMarker: UInt64 = 1 << 63
    static let terminalCookie = UInt64.max
    /// `FSDirectoryVerifierInitial`, the value FSKit passes on a fresh walk.
    @available(macOS 26.0, *)
    static var initialVerifier: UInt64 { FSDirectoryVerifier.initial.rawValue }

    /// FSKit enumeration cookie state machine.
    ///
    /// The daemon owns all real enumeration cookies. They are opaque to this adapter
    /// and must be passed through unchanged; the daemon-side encoding guarantees
    /// every real cookie has `daemonCookieMarker` set, so real cookies cannot collide
    /// with the adapter's synthetic positions 0, 1, and 2. `terminalCookie` is the
    /// adapter-only end-of-directory sentinel and is guarded before high-bit dispatch.
    ///
    /// For attribute-free enumerations, cookie 0 emits "." then "..", cookie 1 emits
    /// only "..", and cookie 2 skips synthetics and starts daemon enumeration at 0.
    /// Attribute-requesting enumerations do not emit synthetics, so only cookie 0 or
    /// an opaque high-bit daemon cookie is valid. Daemon entry cookie 0 means EOF and
    /// is translated to `terminalCookie`; every other daemon cookie is returned to
    /// FSKit verbatim.
    static func daemonCookie(for cookie: UInt64, attributesRequested: Bool) throws -> UInt64 {
        if isTerminal(cookie) {
            throw PfsLocalClientError.daemon(errno: EINVAL, message: "terminal directory cookie has no daemon position")
        }
        if cookie == dotCookie {
            return 0
        }
        if !attributesRequested, cookie == dotDotCookie || cookie == entriesStartCookie {
            return 0
        }
        if isDaemonCookie(cookie) {
            return cookie
        }
        throw PfsLocalClientError.daemon(errno: ESTALE, message: "invalid directory cookie")
    }

    /// FSKit's `enumerateDirectory` documentation is explicit that `"."` and
    /// `".."` belong to attribute-free enumerations only: "Don't pack `.` and
    /// `..` if `attributes` isn't `nil`." Readdir-plus therefore stays
    /// synthetic-free and FSKit supplies the two entries itself.
    static func syntheticEntries(for cookie: UInt64, attributesRequested: Bool) throws -> [PfsSyntheticDirectoryEntry] {
        guard !attributesRequested else {
            return []
        }
        switch cookie {
        case dotCookie:
            return [
                PfsSyntheticDirectoryEntry(name: Data(".".utf8), nextCookie: dotDotCookie),
                PfsSyntheticDirectoryEntry(
                    name: Data("..".utf8), nextCookie: entriesStartCookie, isParentEntry: true
                )
            ]
        case dotDotCookie:
            return [
                PfsSyntheticDirectoryEntry(
                    name: Data("..".utf8), nextCookie: entriesStartCookie, isParentEntry: true
                )
            ]
        case entriesStartCookie:
            return []
        default:
            return []
        }
    }

    /// A fresh walk is identified by `FSDirectoryVerifierInitial`, not by its
    /// cookie alone. FSKit can restart at cookie zero while retaining the
    /// verifier from an earlier walk. Returning a newly minted verifier in
    /// that case makes the framework reject the packed page with `EAGAIN`, and
    /// it can repeat that same zero-cookie/old-verifier request forever. The
    /// synthetic "." and ".." positions still carry the initial verifier, so
    /// they remain part of the one walk that must mint a verifier.
    @available(macOS 26.0, *)
    static func isFreshStart(cookie: UInt64, verifier: UInt64) -> Bool {
        verifier == initialVerifier
    }

    static func fskitCookie(for daemonCookie: UInt64, attributesRequested _: Bool) throws -> UInt64 {
        if daemonCookie == 0 {
            return terminalCookie
        }
        guard isDaemonCookie(daemonCookie) else {
            throw PfsLocalClientError.daemon(errno: EPROTO, message: "daemon returned non-opaque directory cookie")
        }
        return daemonCookie
    }

    static func isTerminal(_ cookie: UInt64) -> Bool {
        cookie == terminalCookie
    }

    static func isDaemonCookie(_ cookie: UInt64) -> Bool {
        cookie != terminalCookie && (cookie & daemonCookieMarker) != 0
    }
}

/// macOS 26 FSKit entry point backed by `VolumeCore`.
@available(macOS 26.0, *)
public final class PortableFSFileSystem: FSUnaryFileSystem, FSUnaryFileSystemOperations, @unchecked Sendable {
    private let logger = Logger(subsystem: "dev.portablefs.fskit", category: "PortableFSFileSystem")
    private let volumeLock = NSLock()
    private var volumes: [String: PortableFSVolume] = [:]
    private let moduleIdentity: PortableFSModuleIdentity
    private let resolverFactory: @Sendable () -> PfsSocketPathResolver

    public override convenience init() {
        self.init(moduleIdentity: Self.mainBundleIdentity())
    }

    /// Source-compatible initializer for embedders that customize only
    /// daemon socket discovery. Identity still comes from the running
    /// extension's signed metadata; there is no OSS-identity assumption.
    public convenience init(
        resolverFactory: @escaping @Sendable () -> PfsSocketPathResolver
    ) {
        self.init(
            moduleIdentity: Self.mainBundleIdentity(),
            resolverFactory: resolverFactory
        )
    }

    public init(
        moduleIdentity: PortableFSModuleIdentity,
        resolverFactory: @escaping @Sendable () -> PfsSocketPathResolver = {
            PfsSocketPathResolver(bundle: .main)
        }
    ) {
        self.moduleIdentity = moduleIdentity
        self.resolverFactory = resolverFactory
        super.init()
    }

    public func probeResource(
        resource: FSResource,
        replyHandler: @escaping (FSProbeResult?, (any Error)?) -> Void
    ) {
        do {
            let attachRef = try attachRef(from: resource)
            let result = FSProbeResult.usable(
                name: "PortableFS",
                containerID: FSContainerIdentifier(
                    uuid: Self.stableEntityUUID(
                        kind: "container",
                        stableID: attachRef,
                        moduleIdentity: moduleIdentity
                    )
                )
            )
            replyHandler(result, nil)
        } catch {
            logger.debug("probeResource rejected resource: \(String(describing: error), privacy: .public)")
            replyHandler(.notRecognized, nil)
        }
    }

    public func loadResource(
        resource: FSResource,
        options: FSTaskOptions,
        replyHandler: @escaping (FSVolume?, (any Error)?) -> Void
    ) {
        let reply = PfsLoadResourceReply(replyHandler)
        do {
            let attachRef = try attachRef(from: resource)
            Task(priority: .userInitiated) {
                do {
                    let socketPath = try resolverFactory().resolve()
                    logger.info("loadResource resolving via socket \(socketPath, privacy: .public) for ref \(attachRef, privacy: .public)")
                    let core = try await VolumeCore.connect(socketPath: socketPath, attachRef: attachRef)
                    let volume = try await PortableFSVolume.make(
                        core: core,
                        attachRef: attachRef,
                        moduleIdentity: moduleIdentity
                    )
                    storeVolume(volume, attachRef: attachRef)
                    containerStatus = .ready
                    reply.call(volume, nil)
                } catch {
                    logger.error("loadResource failed: \(String(describing: error), privacy: .public)")
                    reply.call(nil, PfsErrorMapper.fsKitError(for: error))
                }
            }
        } catch {
            reply.call(nil, PfsErrorMapper.fsKitError(for: error))
        }
    }

    public func unloadResource(
        resource: FSResource,
        options: FSTaskOptions,
        replyHandler reply: @escaping ((any Error)?) -> Void
    ) {
        let reply = PfsUnloadResourceReply(reply)
        do {
            let attachRef = try attachRef(from: resource)
            if let volume = removeVolume(attachRef: attachRef) {
                Task(priority: .userInitiated) {
                    await volume.shutdown()
                    reply.call(nil)
                }
            } else {
                reply.call(nil)
            }
        } catch {
            reply.call(PfsErrorMapper.fsKitError(for: error))
        }
    }

    public func didFinishLoading() {
        containerStatus = .ready
    }

    private func storeVolume(_ volume: PortableFSVolume, attachRef: String) {
        volumeLock.lock()
        volumes[attachRef] = volume
        volumeLock.unlock()
    }

    private func removeVolume(attachRef: String) -> PortableFSVolume? {
        volumeLock.lock()
        let volume = volumes.removeValue(forKey: attachRef)
        volumeLock.unlock()
        return volume
    }

    private final class PfsLoadResourceReply: @unchecked Sendable {
        private let reply: (FSVolume?, (any Error)?) -> Void

        init(_ reply: @escaping (FSVolume?, (any Error)?) -> Void) {
            self.reply = reply
        }

        func call(_ volume: FSVolume?, _ error: (any Error)?) {
            reply(volume, error)
        }
    }

    private final class PfsUnloadResourceReply: @unchecked Sendable {
        private let reply: ((any Error)?) -> Void

        init(_ reply: @escaping ((any Error)?) -> Void) {
            self.reply = reply
        }

        func call(_ error: (any Error)?) {
            reply(error)
        }
    }

    private static func mainBundleIdentity() -> PortableFSModuleIdentity {
        do {
            return try PortableFSModuleIdentity(bundle: .main)
        } catch {
            fatalError("invalid FSKit module identity: \(error.localizedDescription)")
        }
    }

    private func attachRef(from resource: FSResource) throws -> String {
        guard let urlResource = resource as? FSGenericURLResource else {
            throw PfsLocalClientError.daemon(errno: ENXIO, message: "resource is not a generic URL")
        }
        let url = urlResource.url
        guard url.scheme?.lowercased() == moduleIdentity.resourceScheme else {
            throw PfsLocalClientError.daemon(
                errno: ENXIO,
                message: "resource scheme is not \(moduleIdentity.resourceScheme)"
            )
        }
        if let host = url.host, !host.isEmpty {
            return host
        }
        let prefix = moduleIdentity.resourcePrefix
        let absolute = url.absoluteString
        guard absolute.hasPrefix(prefix), absolute.count > prefix.count else {
            throw PfsLocalClientError.daemon(errno: ENXIO, message: "missing attachRef")
        }
        return String(absolute.dropFirst(prefix.count))
    }

    /// Derives a deterministic UUIDv8 while preserving the global FSKit
    /// namespace boundary between products that embed this shared adapter.
    ///
    /// FSKit requires each container and volume identifier to uniquely
    /// identify that entity. Backend identifiers are only unique inside one
    /// PortableFS product, so hashing one without the signed module identity
    /// lets two installed products alias the same LiveFS settings entry.
    static func stableEntityUUID(
        kind: String,
        stableID: String,
        moduleIdentity: PortableFSModuleIdentity
    ) -> UUID {
        var input = Data()
        for component in [
            "portablefs-fskit-entity-v1",
            moduleIdentity.fileSystemTypeName,
            moduleIdentity.resourceScheme,
            kind,
            stableID
        ] {
            let data = Data(component.utf8)
            var byteCount = UInt64(data.count).bigEndian
            withUnsafeBytes(of: &byteCount) { input.append(contentsOf: $0) }
            input.append(data)
        }
        var bytes = Array(SHA256.hash(data: input).prefix(16))
        // RFC 9562 UUIDv8: application-defined payload plus the RFC variant.
        bytes[6] = (bytes[6] & 0x0f) | 0x80
        bytes[8] = (bytes[8] & 0x3f) | 0x80
        return UUID(uuid: (
            bytes[0], bytes[1], bytes[2], bytes[3],
            bytes[4], bytes[5], bytes[6], bytes[7],
            bytes[8], bytes[9], bytes[10], bytes[11],
            bytes[12], bytes[13], bytes[14], bytes[15]
        ))
    }
}

@available(macOS 26.0, *)
public final class PortableFSVolume: FSVolume, FSVolume.Operations, FSVolume.OpenCloseOperations, FSVolume.ReadWriteOperations, FSVolume.XattrOperations, FSVolume.PathConfOperations, @unchecked Sendable {
    public let core: VolumeCore
    public let capabilities: PfsCapabilities
    private let logger = Logger(subsystem: "dev.portablefs.fskit", category: "PortableFSVolume")
    private let fileSystemTypeName: String
    private let statLock = NSLock()
    private var cachedStatistics: FSStatFSResult
    /// The macOS 26 repair gate, when one is installed.
    ///
    /// `nil` — the legacy (non-v3) configuration — does not disable the
    /// reserved-namespace check; it makes it absolute. Every reserved name is
    /// then refused with EPERM, which is the fail-closed end of the contract:
    /// no repair can run, and no user file can occupy a name the repair
    /// machinery would later claim.
    private let repairGate: (any PfsMacOS26RepairGate)?
    /// The composed strict-v3 coherence stack, installed exactly when the
    /// resolve contract declared the macOS 26 compatibility cache policy.
    /// With it installed, every cache-producing callback passes publication
    /// admission and populates the namespace/live-object indexes; without it,
    /// the volume is a legacy mount and records nothing. Internal so the
    /// offline suite can witness what a composed mount installed.
    let coherence: PfsMacOSV3VolumeCoherence?
    private let attachRef: String
    private let mountRootHandoffSocket: String

    private struct PendingBindingPublication {
        let reservation: PfsMacOSNamespaceIndex.RecordReservation
        let parentIdentity: PfsMacOSStableIdentity
        let name: Data
        let itemKind: PfsMacOSCachedItemKind
    }

    private struct PendingBindingForget {
        let reservation: PfsMacOSNamespaceIndex.ForgetReservation
    }

    private struct PendingBindingMove {
        let reservation: PfsMacOSNamespaceIndex.MoveReservation
    }

    private struct PendingLiveObject {
        let reservation: PfsMacOSLiveObjectIndex.Reservation
    }

    public static func make(
        core: VolumeCore,
        attachRef: String,
        moduleIdentity: PortableFSModuleIdentity = PortableFSIdentity.moduleIdentity,
        repairGate: (any PfsMacOS26RepairGate)? = nil,
        coherence: PfsMacOSV3VolumeCoherence? = nil
    ) async throws -> PortableFSVolume {
        guard let resolved = await core.resolvedVolume else {
            throw PfsLocalClientError.unexpectedReply("volume has not been resolved")
        }
        var installedCoherence = coherence
        if installedCoherence == nil,
           let strictReply = await core.strictV3ResolveReply,
           let strictContract = await core.strictV3Contract {
            do {
                installedCoherence = try await PfsMacOSV3VolumeCoherence.compose(
                    client: core.client,
                    resolved: strictReply,
                    rootItem: resolved.root,
                    contract: strictContract,
                    daemonActuation: (
                        socketPath: PfsMountRootHandoff.socketPath(
                            besideFrontendSocket: try await core.client.currentSocketPath()
                        ),
                        attachRef: attachRef
                    )
                )
            } catch {
                // The resolve accepted a policy this adapter then failed to
                // install. Serving without the stack it promised would ignore
                // every visibility event, so the mount fails closed instead.
                await core.shutdown()
                throw error
            }
        }
        let statReply = try await core.statfs()
        // The daemon socket's directory hosts the mount-root handoff socket;
        // resolve it now so the synchronous actuator locator needs no async
        // hop when the first repair arrives.
        let handoffSocket = try await PfsMountRootHandoff.socketPath(
            besideFrontendSocket: core.client.currentSocketPath()
        )
        return PortableFSVolume(
            core: core,
            attachRef: attachRef,
            resolved: resolved,
            statReply: statReply,
            moduleIdentity: moduleIdentity,
            repairGate: installedCoherence?.repairGate ?? repairGate,
            coherence: installedCoherence,
            mountRootHandoffSocket: handoffSocket
        )
    }

    private init(
        core: VolumeCore,
        attachRef: String,
        resolved: PfsResolvedVolume,
        statReply: PfsStatfsReply,
        moduleIdentity: PortableFSModuleIdentity,
        repairGate: (any PfsMacOS26RepairGate)?,
        coherence: PfsMacOSV3VolumeCoherence?,
        mountRootHandoffSocket: String
    ) {
        self.core = core
        self.capabilities = resolved.capabilities
        self.repairGate = repairGate
        self.coherence = coherence
        self.mountRootHandoffSocket = mountRootHandoffSocket
        self.attachRef = attachRef
        self.fileSystemTypeName = moduleIdentity.fileSystemTypeName
        self.cachedStatistics = PfsFSKitMapping.statfs(
            from: statReply,
            capabilities: resolved.capabilities,
            fileSystemTypeName: moduleIdentity.fileSystemTypeName
        )
        // The FSKit volume identity is scoped to the ATTACH, not the backend
        // volume, exactly like the container identity above. A v3 mount is one
        // incarnation: a fenced or abnormally-ended incarnation never comes
        // back, and its successor registers as a new one. Deriving this UUID
        // from the backend volume ID gave every incarnation the same FSKit
        // identity, so a volume record left in fskitd by an incarnation that
        // died before completing deactivateVolume collided with every future
        // mount of that volume — "a file with the same name already exists"
        // at the final mount step, curable only by restarting fskitd. fskitd's
        // record of a dead incarnation must never be able to name a live one.
        let volumeID = FSVolume.Identifier(
            uuid: PortableFSFileSystem.stableEntityUUID(
                kind: "volume",
                stableID: attachRef,
                moduleIdentity: moduleIdentity
            )
        )
        let volumeName = FSFileName(string: resolved.volumeName)
        super.init(volumeID: volumeID, volumeName: volumeName)
    }

    public var maximumLinkCount: Int {
        Int(Int32.max)
    }

    public var maximumNameLength: Int {
        let value = capabilities.maxNameBytes
        return value == 0 ? 255 : Int(value)
    }

    public var restrictsOwnershipChanges: Bool {
        true
    }

    public var truncatesLongNames: Bool {
        false
    }

    public var maximumXattrSize: Int {
        // xfsstore applies the same 64 KiB ceiling to one user-xattr value and
        // to a list result. FSKit has one maximum-size property, so advertise
        // the exact production substrate bound rather than a larger value a
        // future writable-xattr backend could not honor.
        64 * 1024
    }

    public var maximumFileSize: UInt64 {
        capabilities.maxFileSize == 0 ? UInt64.max : capabilities.maxFileSize
    }

    public var supportedVolumeCapabilities: FSVolume.SupportedCapabilities {
        PfsFSKitMapping.supportedCapabilities(from: capabilities)
    }

    public var volumeStatistics: FSStatFSResult {
        statLock.lock()
        let statistics = cachedStatistics
        statLock.unlock()
        return statistics
    }

    public func activate(options: FSTaskOptions) async throws -> FSItem {
        do {
            return try await pinRootForCoherence()
        } catch {
            throw PfsErrorMapper.fsKitError(for: error)
        }
    }

    /// Installs the otherwise-pathless root vnode in the exact live-object
    /// repair index. Both FSKit activation entry points call this idempotently;
    /// it is internal so production-wiring tests can pin the invariant without
    /// constructing the framework-owned `FSTaskOptions` class.
    func pinRootForCoherence() async throws -> PortableFSItem {
        let root = try await core.rootItem()
        try await recordLiveObject(root)
        return root
    }

    public func deactivate(options: FSDeactivateOptions = []) async throws {
        coherence?.shutdown()
        await core.shutdown()
    }

    public func mount(options: FSTaskOptions) async throws {
        do {
            _ = try await pinRootForCoherence()
        } catch {
            throw PfsErrorMapper.fsKitError(for: error)
        }
    }

    public func unmount() async {
        coherence?.shutdown()
        await core.shutdown()
    }

    public func synchronize(flags: FSSyncFlags) async throws {
        do {
            // The v3 authority durability barrier. No client or daemon
            // write-back tail exists: mutations are synchronous authority
            // calls against raw XFS. This waits for the authority's `syncfs`
            // cut after all prior ordered operations. Cache-visible mutations
            // retain their separate two-phase repair boundary. An unreachable,
            // slow, or fenced authority throws; there is never a silent
            // local-only outcome.
            try await core.syncVolume()
            if let stat = try? await core.statfs() {
                setCachedStatistics(PfsFSKitMapping.statfs(
                    from: stat,
                    capabilities: capabilities,
                    fileSystemTypeName: fileSystemTypeName
                ))
            }
        } catch {
            throw PfsErrorMapper.fsKitError(for: error)
        }
    }

    /// Whether one callback passes the strict publication-admission gate or is
    /// routed around it. Only two things may bypass a closed gate: the repair
    /// machinery's own re-entrant callbacks (reserved operand names, the local
    /// scratch item, or the armed data-invalidation source item), which the
    /// closed gate exists to serve, and nothing else. The initiating mutation
    /// callback is NOT an exemption here — it is admitted normally before the
    /// barrier closes and exempted from the drain by its operation ID.
    private func admissionExemption(
        reservedNames: [Data] = [],
        repairSources: [(name: Data, directory: FSItem)] = [],
        repairSourceItems: [FSItem?] = [],
        repairParentItems: [FSItem?] = [],
        items: [FSItem?] = [],
        includeAttributeRefreshItems: Bool = true
    ) -> @Sendable () async -> Bool {
        let items = PfsUncheckedSendableBox(items)
        let repairSources = PfsUncheckedSendableBox(repairSources)
        let repairSourceItems = PfsUncheckedSendableBox(repairSourceItems)
        let repairParentItems = PfsUncheckedSendableBox(repairParentItems)
        return { [weak self] in
            guard let self else { return true }
            for name in reservedNames where PfsMacOS26RepairAuthenticator.isReserved(name) {
                return true
            }
            for case let portable as PortableFSItem in items.value.compactMap({ $0 }) {
                if await self.core.isLocalRepairItem(portable) {
                    return true
                }
                if let repairGate = self.repairGate,
                   await repairGate.isArmedTruncateItem(
                       itemIdentity: portable.identity.stableIdentity
                   ) {
                    return true
                }
                if includeAttributeRefreshItems,
                   let repairGate = self.repairGate,
                   await repairGate.isArmedAttributeRefreshItem(
                       itemIdentity: portable.identity.stableIdentity
                   ) {
                    return true
                }
            }
            if let repairGate = self.repairGate {
                for case let portable as PortableFSItem in repairSourceItems.value.compactMap({ $0 }) {
                    if await repairGate.isArmedRepairSourceItem(
                        itemIdentity: portable.identity.stableIdentity
                    ) {
                        return true
                    }
                }
                for case let portable as PortableFSItem in repairParentItems.value.compactMap({ $0 }) {
                    if await repairGate.isArmedRepairParentItem(
                        itemIdentity: portable.identity.stableIdentity
                    ) {
                        return true
                    }
                    if await repairGate.isArmedRepairTraversalItem(
                        itemIdentity: portable.identity.stableIdentity
                    ) {
                        return true
                    }
                }
                for source in repairSources.value {
                    guard let directory = source.directory as? PortableFSItem else {
                        continue
                    }
                    if await repairGate.isArmedRepairSource(
                        parentIdentity: directory.identity.stableIdentity,
                        name: source.name
                    ) {
                        return true
                    }
                    if await repairGate.isArmedRepairTraversal(
                        parentIdentity: directory.identity.stableIdentity,
                        name: source.name
                    ) {
                        return true
                    }
                }
            }
            return false
        }
    }

    /// Builds one immutable, typed callback scope before crossing into an
    /// asynchronous task. Namespace coordinates retain their parent identity;
    /// directory selectors are used only for whole-directory snapshots or
    /// namespace mutations that can hold the parent's FSKit callback lane.
    /// Any unknown FSItem makes the entire scope conservative.
    private func admissionScope(
        namespace: [(directory: FSItem, name: Data)] = [],
        directories: [FSItem?] = [],
        items: [FSItem?] = [],
        orderedMutation: Bool = false
    ) -> PfsMacOSCallbackScope {
        var selectors: Set<PfsMacOSAdmissionSelector> = []
        if orderedMutation { selectors.insert(.orderedMutation) }
        for coordinate in namespace {
            guard let directory = coordinate.directory as? PortableFSItem,
                  let identity = try? PfsMacOSStableIdentity(
                      directory.identity.stableIdentity
                  ) else {
                return .conservative(orderedMutation: orderedMutation)
            }
            selectors.insert(.namespace(PfsMacOSNamespaceCoordinate(
                parentIdentity: identity,
                name: coordinate.name
            )))
        }
        for item in directories {
            guard let item else { continue }
            guard let portable = item as? PortableFSItem,
                  let identity = try? PfsMacOSStableIdentity(
                      portable.identity.stableIdentity
                  ) else {
                return .conservative(orderedMutation: orderedMutation)
            }
            selectors.insert(.directory(identity))
        }
        for item in items {
            guard let item else { continue }
            guard let portable = item as? PortableFSItem,
                  let identity = try? PfsMacOSStableIdentity(
                      portable.identity.stableIdentity
                  ) else {
                return .conservative(orderedMutation: orderedMutation)
            }
            selectors.insert(.item(identity))
        }
        return PfsMacOSCallbackScope(selectors: selectors)
    }

    private func publishAfterReply<Value>(
        callbackKind: StaticString = #function,
        preflight: @escaping @Sendable () async throws -> Void = {},
        exemptFromAdmission: @escaping @Sendable () async -> Bool = { false },
        admissionScope: PfsMacOSCallbackScope = .conservative,
        _ operation: @escaping () async throws -> Value,
        reply: @escaping (Result<Value, Error>) -> Void
    ) {
        let trace = PfsFSKitCallbackTrace(
            kind: callbackKind,
            scope: admissionScope
        )
        let ingressReservation = coherence?.barrier.reserveCallbackIngress(
            scope: admissionScope,
            callbackKind: trace.kind,
            ingressUptimeNanoseconds: trace.ingressUptimeNanoseconds
        )
        let operation = PfsUncheckedSendableBox(operation)
        let reply = PfsUncheckedSendableBox(reply)
        Task(priority: .userInitiated) {
            trace.emit("TaskStarted")
            // The kernel mount-table entry exists once any callback is being
            // served, including one that will be refused by a capability
            // preflight. Bind the deferred actuator before any early return so
            // a first-callback EOPNOTSUPP cannot postpone mount supervision.
            if self.coherence != nil {
                self.scheduleRepairRootInstall()
            }
            // Capability-local refusals that cannot publish cache state belong
            // before PREPARE admission. A synchronous ingress reservation is
            // accounting only, so this precedence remains unchanged.
            do {
                try await preflight()
                trace.emit("PreflightFinished")
            } catch {
                let mapped = PfsErrorMapper.fsKitError(for: error)
                reply.value(.failure(mapped))
                trace.emit("FrameworkReplyReturned", detail: "stage=preflight")
                if let ingressReservation, let coherence = self.coherence {
                    await coherence.barrier.callbackReplyReturned(ingressReservation)
                }
                trace.finish(outcome: "preflight-refused")
                return
            }

            // Resolve the pre-Task reservation only after authenticated repair
            // exemption is known. PREPARE may already have adopted its ticket;
            // in that case the existing ticket request rules decide whether the
            // callback drains, parks, or is refused.
            var ticket: PfsMacOSAdmittedCallbackTicket?
            var bypassedAdmission = false
            if let coherence = self.coherence {
                bypassedAdmission = await exemptFromAdmission()
                do {
                    if let ingressReservation {
                        ticket = try await coherence.barrier.resolveAdmission(
                            for: ingressReservation,
                            exemptFromAdmission: bypassedAdmission
                        )
                    } else if !bypassedAdmission {
                        ticket = try await coherence.barrier.admit(
                            scope: admissionScope,
                            callbackKind: trace.kind,
                            ingressUptimeNanoseconds: trace.ingressUptimeNanoseconds
                        )
                    }
                } catch {
                    let nsError = error as NSError
                    self.logger.error(
                        "callback admission failed before operation; kind=\(trace.kind, privacy: .public) ordered=\(admissionScope.canSubmitOrderedMutation) domain=\(nsError.domain, privacy: .public) code=\(nsError.code)"
                    )
                    reply.value(.failure(PfsErrorMapper.fsKitError(for: error)))
                    trace.emit("FrameworkReplyReturned", detail: "stage=admission-refused")
                    if let ingressReservation {
                        await coherence.barrier.callbackReplyReturned(ingressReservation)
                    }
                    trace.finish(outcome: "admission-refused")
                    return
                }
            }
            trace.emit(
                "AdmissionFinished",
                detail: "result=\(bypassedAdmission ? "exempt" : "admitted") ticket=\(ticket?.diagnosticID ?? 0)"
            )

            let (result, complete) = await PfsMacOSCallbackAdmission.$ticket.withValue(ticket) {
                await core.client.withDeferredPublication {
                    try await operation.value()
                }
            }
            trace.emit(
                "OperationFinished",
                detail: "result=\(result.pfsIsSuccess ? "success" : "failure")"
            )

            // FSKit's reply is the publication boundary. A crossed success must
            // never install values that PREPARE already withdrew.
            var verdict = result
            if let ticket, ticket.isCrossed(), case .success = verdict {
                self.logger.error(
                    "callback success crossed PREPARE publication and was refused; kind=\(trace.kind, privacy: .public) ticket=\(ticket.diagnosticID)"
                )
                verdict = .failure(PfsErrorMapper.fsKitError(
                    for: ticket.admissionRefusalError()
                ))
            }
            if case let .failure(error) = verdict {
                let nsError = error as NSError
                self.logger.error(
                    "callback operation failed before framework reply; kind=\(trace.kind, privacy: .public) ticket=\(ticket?.diagnosticID ?? 0) ordered=\(admissionScope.canSubmitOrderedMutation) domain=\(nsError.domain, privacy: .public) code=\(nsError.code)"
                )
            }
            reply.value(verdict.mapError { PfsErrorMapper.fsKitError(for: $0) as Error })
            trace.emit("FrameworkReplyReturned")

            if let coherence = self.coherence {
                if let ingressReservation {
                    await coherence.barrier.callbackReplyReturned(ingressReservation)
                } else if let ticket {
                    await coherence.barrier.published(ticket)
                }
                trace.emit("BarrierPublished")
            }
            if case .success = verdict {
                await complete(true)
            } else {
                await complete(false)
            }
            trace.emit("Settled")
            trace.finish(outcome: verdict.pfsIsSuccess ? "success" : "failure")
            if bypassedAdmission {
                self.logger.debug(
                    "repair-exempt publication completion returned; kind=\(trace.kind, privacy: .public)"
                )
            }
        }
    }

    /// Internal deterministic boundary used by the race suite to suspend the
    /// callback task after synchronous ingress reservation. Production FSKit
    /// entry points all use the same helper directly.
    func testOnlyPublishAfterReply(
        preflight: @escaping @Sendable () async throws -> Void,
        admissionScope: PfsMacOSCallbackScope,
        operation: @escaping () async throws -> Void,
        reply: @escaping (Result<Void, Error>) -> Void
    ) {
        publishAfterReply(
            callbackKind: "testOnlyCallback",
            preflight: preflight,
            admissionScope: admissionScope,
            operation,
            reply: reply
        )
    }

    @nonobjc
    public func attributes(_ desiredAttributes: FSItem.GetAttributesRequest, of item: FSItem) async throws -> FSItem.Attributes {
        if let portable = item as? PortableFSItem,
           let attributes = await core.localRepairAttributes(portable) {
            return try PfsFSKitMapping.localRepairAttributes(
                from: attributes,
                requested: desiredAttributes.wantedAttributes
            )
        }
        return try await core.client.withPublicationBoundary {
            do {
                let attr = try await core.getattr(item: try portableItem(item))
                return try PfsFSKitMapping.attributes(
                    from: attr,
                    requested: desiredAttributes.wantedAttributes
                )
            } catch {
                throw PfsErrorMapper.fsKitError(for: error)
            }
        }
    }

    public func getAttributes(
        _ desiredAttributes: FSItem.GetAttributesRequest,
        of item: FSItem,
        replyHandler reply: @escaping (FSItem.Attributes?, Error?) -> Void
    ) {
        publishAfterReply(exemptFromAdmission: admissionExemption(
            repairSourceItems: [item],
            repairParentItems: [item],
            items: [item]
        ), admissionScope: admissionScope(items: [item]), {
            try await self.attributes(desiredAttributes, of: item)
        }, reply: { result in
            switch result {
            case let .success(attributes):
                reply(attributes, nil)
            case let .failure(error):
                reply(nil, error)
            }
        })
    }

    /// Match and consume a mode-only callback on the exact item of an armed
    /// attribute refresh. Returning `PfsAttr` freezes the authority snapshot
    /// used for the reply. FSKit provides no caller or repair token, so the
    /// requested mode itself cannot safely distinguish the actuator from a
    /// racing user callback during this bounded window.
    private func consumeArmedAttributeRefresh(
        _ newAttributes: FSItem.SetAttributesRequest,
        on item: FSItem
    ) async throws -> PfsAttr? {
        guard let repairGate,
              let portable = item as? PortableFSItem,
              newAttributes.isValid(.mode),
              !newAttributes.isValid(.size),
              !newAttributes.isValid(.uid),
              !newAttributes.isValid(.gid),
              !newAttributes.isValid(.flags),
              !newAttributes.isValid(.modifyTime),
              !newAttributes.isValid(.accessTime),
              await repairGate.isArmedAttributeRefreshItem(
                  itemIdentity: portable.identity.stableIdentity
              ) else {
            return nil
        }
        let attributes = try await core.getattr(item: portable)
        guard attributes.item.stableIdentity == portable.identity.stableIdentity else {
            throw PfsMacOSCoherenceError.invalidRepairOperand
        }
        guard let consumed = await repairGate.consumeArmedAttributeRefresh(
            itemIdentity: portable.identity.stableIdentity
        ), try PfsFSKitMapping.itemIdentifier(
            from: attributes.item.itemID
        ).rawValue == consumed.expectedVFSFileID else {
            throw PfsMacOSCoherenceError.invalidRepairOperand
        }
        return attributes
    }

    private func finishArmedAttributeRefresh(
        _ attributes: PfsAttr,
        consuming newAttributes: FSItem.SetAttributesRequest
    ) throws -> FSItem.Attributes {
        newAttributes.consumedAttributes.insert(.mode)
        return try PfsFSKitMapping.attributes(from: attributes)
    }

    @nonobjc
    public func setAttributes(_ newAttributes: FSItem.SetAttributesRequest, on item: FSItem) async throws -> FSItem.Attributes {
        // A setattr carries an item and a value but no name, so it carries no
        // repair token; the scratch item refuses them outright rather than
        // offering a nameless mutation channel.
        if let portable = item as? PortableFSItem, await core.isLocalRepairItem(portable) {
            throw Self.reservedNamespaceError()
        }
        // Attribute refresh deliberately issues fchmod with the vnode's
        // existing mode. Direct async callers preflight here; FSKit's callback overload does
        // the same check before admission and passes its immutable snapshot to
        // the callback body instead.
        do {
            if let attributes = try await consumeArmedAttributeRefresh(
                newAttributes,
                on: item
            ) {
                return try finishArmedAttributeRefresh(
                    attributes,
                    consuming: newAttributes
                )
            }
        } catch {
            throw PfsErrorMapper.fsKitError(for: error)
        }


        // The armed-truncate table is the declared macOS 26 provenance channel
        // for the one nameless callback a data-invalidation repair needs. A
        // size change is consumed locally exactly when every coordinate the
        // platform can bind matches an armed data-repair window: the item's
        // stable identity, the authoritative post-repair size, and the window
        // itself — which starts at the exact kernel-only source removal and
        // ends at the event lease boundary, never on a clock. Everything
        // else — any other size, any other item, any request that also
        // carries ownership/mode/flag changes, any moment outside the window —
        // flows through to the daemon unchanged.
        //
        // The exact residual race, accepted by the declared policy: a process
        // that already holds the same vnode and, during the repair window,
        // truncates it to exactly the authoritative post-state size has its
        // metadata-only effect coalesced with the repair. The file was about
        // to hold precisely that size and XFS already does, so nothing
        // diverges — but the process observed success for a syscall the
        // authority never saw, which is why macOS 26 is a compatibility
        // policy rather than the exact contract.
        if let repairGate,
           let portable = item as? PortableFSItem,
           newAttributes.isValid(.size),
           !newAttributes.isValid(.mode),
           !newAttributes.isValid(.uid),
           !newAttributes.isValid(.gid),
           !newAttributes.isValid(.flags),
           let consumed = await repairGate.consumeArmedTruncate(
               itemIdentity: portable.identity.stableIdentity,
               size: newAttributes.size
           ) {
            newAttributes.consumedAttributes.insert(.size)
            if newAttributes.isValid(.modifyTime) {
                newAttributes.consumedAttributes.insert(.modifyTime)
            }
            if newAttributes.isValid(.accessTime) {
                newAttributes.consumedAttributes.insert(.accessTime)
            }
            do {
                // COMPLETE is delivered only after XFS apply and the authority
                // releases its in-flight coordinates at that exact boundary.
                // Fetching here therefore cannot read the old value or wait on
                // this repair. It gives FSKit one complete, truthful snapshot
                // instead of inventing mode, link count, allocation, or times
                // from the truncate plan's intentionally narrow coordinates.
                let attributes = try await core.getattr(item: portable)
                guard attributes.item.stableIdentity == portable.identity.stableIdentity,
                      attributes.size == consumed.size,
                      try PfsFSKitMapping.itemIdentifier(
                          from: attributes.item.itemID
                      ).rawValue == consumed.expectedVFSFileID else {
                    throw PfsMacOSCoherenceError.invalidRepairOperand
                }
                return try PfsFSKitMapping.attributes(from: attributes)
            } catch {
                throw PfsErrorMapper.fsKitError(for: error)
            }
        }
        return try await core.client.withPublicationBoundary {
            do {
                let request = try PfsFSKitMapping.setAttributes(
                    from: newAttributes,
                    flagsUnderstood: capabilities.flagsUnderstood
                )
                let attr = try await core.setattr(item: try portableItem(item), attributes: request)
                return try PfsFSKitMapping.attributes(from: attr)
            } catch {
                throw PfsErrorMapper.fsKitError(for: error)
            }
        }
    }

    @nonobjc
    public func lookupItem(named name: FSFileName, inDirectory directory: FSItem) async throws -> (FSItem, FSFileName) {
        if PfsMacOS26RepairAuthenticator.isReserved(name.data) {
            // Reserved names are not part of the user namespace, and every
            // other callback already refuses them locally; forwarding a lookup
            // would leak the control namespace to the daemon and let a probe
            // observe it. Positive/data repair never publishes a hidden name;
            // only the negative-cache scratch object can legally resolve here.
            // A negative-cache repair creates one process-local scratch
            // binding. unlinkat(2) may ask FSKit to resolve that binding again
            // before it emits removeItem; answer exactly the object minted by
            // the authenticated create callback, never a daemon object.
            if let parent = directory as? PortableFSItem,
               let scratch = await core.localRepairItem(in: parent, named: name.data) {
                return (scratch, name)
            }
            throw PfsErrorMapper.fsKitError(
                for: PfsLocalClientError.daemon(
                    errno: ENOENT,
                    message: "the reserved repair namespace is not part of the user namespace"
                )
            )
        }
        return try await core.client.withPublicationBoundary {
            do {
                let result = try await core.lookup(in: try portableItem(directory), name: name.data)
                try await recordPublishedBinding(
                    parent: directory,
                    name: result.canonicalName,
                    child: result.item,
                    itemKind: result.attr.kind
                )
                return (result.item, PfsFSKitMapping.fileName(from: result.canonicalName))
            } catch {
                throw PfsErrorMapper.fsKitError(for: error)
            }
        }
    }

    @nonobjc
    public func reclaimItem(_ item: FSItem) async throws {
        if let portable = item as? PortableFSItem, await core.isLocalRepairItem(portable) {
            await core.releaseLocalRepairItem(portable)
            return
        }
        if let repairGate,
           let portable = item as? PortableFSItem,
           await repairGate.isArmedRepairSourceItem(
               itemIdentity: portable.identity.stableIdentity
           ) {
            // The local unlink is retiring a kernel cache object, not the XFS
            // object. Sending Reclaim to the authority here would both lie
            // about ownership and wait behind the COMPLETE event that is
            // waiting for this unlink to finish. Retire only this FSItem so a
            // later authority lookup mints a fresh local object.
            try await core.reclaimLocalRepairSource(item: portable)
            await forgetLiveObject(portable)
            return
        }
        return try await core.client.withPublicationBoundary {
            do {
                let portable = try portableItem(item)
                // Reclaim is the kernel dropping its last object reference —
                // the one boundary that retires a live-object obligation, and
                // it retires it whatever the daemon answers, because the index
                // mirrors KERNEL state and the kernel's reference is already
                // gone. The namespace records stay: dropping a coordinate on
                // reclaim would be an unproven inference about the name cache,
                // and an extra exact record is only ever an extra local repair.
                await forgetLiveObject(portable)
                try await core.reclaim(item: portable)
            } catch {
                throw PfsErrorMapper.fsKitError(for: error)
            }
        }
    }

    @nonobjc
    public func readSymbolicLink(_ item: FSItem) async throws -> FSFileName {
        try await core.client.withPublicationBoundary {
            do {
                let target = try await core.readlink(item: try portableItem(item))
                return PfsFSKitMapping.fileName(from: target)
            } catch {
                logger.error("readlink failed: \(String(describing: error), privacy: .private)")
                throw PfsErrorMapper.fsKitError(for: error)
            }
        }
    }

    @nonobjc
    public func createItem(
        named name: FSFileName,
        type: FSItem.ItemType,
        inDirectory directory: FSItem,
        attributes newAttributes: FSItem.SetAttributesRequest
    ) async throws -> (FSItem, FSFileName) {
        if PfsMacOS26RepairAuthenticator.isReserved(name.data) {
            // Deliberately outside `withPublicationBoundary`: a consumed repair
            // callback is local by construction, so it must not enter the
            // daemon's publication gate — the barrier it belongs to is the one
            // holding that gate closed.
            guard type == .file else { throw Self.reservedNamespaceError() }
            try await consumeRepairCallback(
                .createScratch,
                operand: name.data,
                directory: directory
            )
            guard let parent = directory as? PortableFSItem else {
                throw Self.reservedNamespaceError()
            }
            let mode = newAttributes.isValid(.mode) ? newAttributes.mode : 0o600
            let item = try await core.mintLocalRepairItem(
                parent: parent,
                name: name.data,
                mode: mode,
                uid: getuid(),
                gid: getgid()
            )
            do {
                guard let repairGate else { throw Self.reservedNamespaceError() }
                try await repairGate.adoptLocalRepairScratch(
                    operand: name.data,
                    item: item,
                    retireBinding: { [core] scratch in
                        await core.retireLocalRepairBinding(scratch)
                    }
                )
            } catch {
                await core.releaseLocalRepairItem(item)
                throw error
            }
            return (item, name)
        }
        return try await core.client.withPublicationBoundary {
          do {
            let mode = newAttributes.isValid(.mode) ? newAttributes.mode : 0o644
            let parent = try portableItem(directory)
            let cachedKind: PfsMacOSCachedItemKind
            switch type {
            case .file: cachedKind = .file
            case .directory: cachedKind = .directory
            default:
                throw PfsLocalClientError.daemon(errno: ENOTSUP, message: "unsupported create item type")
            }
            let binding = try await reserveBindingPublication(
                parent: directory,
                name: name.data,
                itemKind: cachedKind
            )
            let live: PendingLiveObject?
            do {
                live = type == .file ? try await reserveLiveObject() : nil
            } catch {
                await cancelBindingPublication(binding)
                throw error
            }
            let result: PfsCreateResult
            do {
                switch type {
                case .file:
                    result = try await core.createFile(in: parent, name: name.data, mode: mode)
                case .directory:
                    result = try await core.mkdir(in: parent, name: name.data, mode: mode == 0o644 ? 0o755 : mode)
                default:
                    throw PfsLocalClientError.daemon(errno: ENOTSUP, message: "unsupported create item type")
                }
            } catch {
                await cancelBindingPublication(binding)
                await cancelLiveObject(live)
                throw error
            }
            try await commitBindingPublication(binding, child: result.item)
            if type == .file {
                // A create hands the kernel a live object as well as a name.
                try await commitLiveObject(live, item: result.item)
            }
            return (result.item, PfsFSKitMapping.fileName(from: result.canonicalName))
          } catch {
              throw PfsErrorMapper.fsKitError(for: error)
          }
        }
    }

    @nonobjc
    public func createSymbolicLink(
        named name: FSFileName,
        inDirectory directory: FSItem,
        attributes newAttributes: FSItem.SetAttributesRequest,
        linkContents contents: FSFileName
    ) async throws -> (FSItem, FSFileName) {
        // No repair plan creates a symlink, so the reserved form is always a
        // user operation here and is always refused.
        guard !PfsMacOS26RepairAuthenticator.isReserved(name.data) else {
            throw Self.reservedNamespaceError()
        }
        return try await core.client.withPublicationBoundary {
          do {
            let targetBytes = PfsFSKitMapping.bytes(from: contents)
            let parent = try portableItem(directory)
            let binding = try await reserveBindingPublication(
                parent: directory,
                name: name.data,
                itemKind: .symlink
            )
            let result: PfsCreateResult
            do {
                result = try await core.symlink(
                    in: parent,
                    name: name.data,
                    target: targetBytes
                )
            } catch {
                await cancelBindingPublication(binding)
                throw error
            }
            try await commitBindingPublication(binding, child: result.item)
            return (result.item, PfsFSKitMapping.fileName(from: result.canonicalName))
          } catch {
              logger.error("symlink create failed: \(String(describing: error), privacy: .private)")
              throw PfsErrorMapper.fsKitError(for: error)
          }
        }
    }

    @nonobjc
    public func createLink(to item: FSItem, named name: FSFileName, inDirectory directory: FSItem) async throws -> FSFileName {
        // Likewise: a hard link is never a repair step, so a reserved name here
        // could only be a user process trying to occupy the control namespace.
        guard !PfsMacOS26RepairAuthenticator.isReserved(name.data) else {
            throw Self.reservedNamespaceError()
        }
        return try await core.client.withPublicationBoundary {
            do {
                let portable = try portableItem(item)
                let parent = try portableItem(directory)
                let kind = try PfsMacOSCachedItemKind(
                    try await core.getattr(item: portable).kind
                )
                let binding = try await reserveBindingPublication(
                    parent: directory,
                    name: name.data,
                    itemKind: kind
                )
                let result: PfsHardLinkResult
                do {
                    result = try await core.hardLink(
                        item: portable,
                        in: parent,
                        name: name.data
                    )
                } catch {
                    await cancelBindingPublication(binding)
                    throw error
                }
                // Every hard-link alias the kernel learns is a distinct
                // cache obligation; the reverse index keeps them all.
                try await commitBindingPublication(binding, child: portable)
                return PfsFSKitMapping.fileName(from: result.canonicalName)
            } catch {
                throw PfsErrorMapper.fsKitError(for: error)
            }
        }
    }

    @nonobjc
    public func removeItem(_ item: FSItem, named name: FSFileName, fromDirectory directory: FSItem) async throws {
        if PfsMacOS26RepairAuthenticator.isReserved(name.data) {
            try await consumeRepairCallback(
                .removeOperand,
                operand: name.data,
                directory: directory
            )
            if let portable = item as? PortableFSItem {
                // unlink removes the process-local name, but FSKit may still
                // issue vnode teardown before the actuator syscall returns.
                // Event ownership releases the synthetic object at the lease
                // boundary (or reclaim does so earlier).
                await core.retireLocalRepairBinding(portable)
            }
            return
        }
        if let repairGate,
           let portable = item as? PortableFSItem,
           let parent = directory as? PortableFSItem {
            let consumed = try await repairGate.consumeArmedSourceRemoval(
               parentIdentity: parent.identity.stableIdentity,
               name: name.data,
               item: portable
            )
            if let consumed {
                // This is a kernel-cache actuator, not an authority mutation.
                // Only data invalidation preserves an attested authority
                // binding of this item at the exact coordinate. Positive
                // eviction accompanies a namespace target; retaining its old
                // item/coordinate pair could manufacture a stale pathname that
                // a later attribute repair cannot attest.
                switch consumed {
                case .positiveEviction:
                    try await forgetPublishedBinding(parent: directory, name: name.data)
                case .dataInvalidation:
                    try await retainDataRepairLocator(
                        parent: directory,
                        name: name.data,
                        child: portable
                    )
                }
                return
            }
        }
        return try await core.client.withPublicationBoundary {
          do {
            let portable = try portableItem(item)
            let attr = try await core.getattr(item: portable)
            let parent = try portableItem(directory)
            let forgetting = try await reserveBindingForget(
                parent: directory,
                name: name.data,
                child: portable
            )
            do {
                try await core.remove(
                    item: portable,
                    named: name.data,
                    from: parent,
                    isDirectory: attr.kind == .directory
                )
            } catch {
                await cancelBindingForget(forgetting)
                throw error
            }
            // Unlink retires exactly this coordinate. The live-object record
            // survives: an open-but-unlinked vnode is precisely what the
            // separate index exists to keep addressable.
            await commitBindingForget(forgetting)
          } catch {
              throw PfsErrorMapper.fsKitError(for: error)
          }
        }
    }

    @nonobjc
    public func renameItem(
        _ item: FSItem,
        inDirectory sourceDirectory: FSItem,
        named sourceName: FSFileName,
        to destinationName: FSFileName,
        inDirectory destinationDirectory: FSItem,
        overItem: FSItem?
    ) async throws -> FSFileName {
        if PfsMacOS26RepairAuthenticator.isReserved(sourceName.data)
            || PfsMacOS26RepairAuthenticator.isReserved(destinationName.data) {
            // No current repair moves a user binding through the reserved
            // namespace. Refuse every such rename locally and unconditionally.
            throw Self.reservedNamespaceError()
        }
        return try await core.client.withPublicationBoundary {
          do {
            let sourceItem = try portableItem(item)
            let sourceParent = try portableItem(sourceDirectory)
            let destinationParent = try portableItem(destinationDirectory)
            if let overItem, let replacedItem = overItem as? PortableFSItem, replacedItem !== sourceItem {
                // Identity validation belongs before the authority mutation;
                // afterward this local bookkeeping step is infallible.
                try await core.recordRenameReplacement(replacedItem: replacedItem)
            }
            let moving = try await reserveBindingMove(
                from: sourceDirectory,
                name: sourceName.data,
                to: destinationDirectory,
                name: destinationName.data,
                child: sourceItem
            )
            do {
                try await core.rename(
                    item: sourceItem,
                    from: sourceParent,
                    sourceName: sourceName.data,
                    to: destinationParent,
                    destinationName: destinationName.data,
                    noReplace: false
                )
            } catch {
                await cancelBindingMove(moving)
                throw error
            }
            // Both edges of the rename are published coordinates: the source
            // binding is retired, the destination binding (replacing any
            // rename-over victim at that exact coordinate) is published.
            await commitBindingMove(moving)
            return destinationName
          } catch {
              throw PfsErrorMapper.fsKitError(for: error)
          }
        }
    }

    @nonobjc
    public func enumerateDirectory(
        _ directory: FSItem,
        startingAt cookie: FSDirectoryCookie,
        verifier: FSDirectoryVerifier,
        attributes: FSItem.GetAttributesRequest?,
        packer: FSDirectoryEntryPacker
    ) async throws -> FSDirectoryVerifier {
        return try await core.client.withPublicationBoundary {
          do {
            let portableDirectory = try portableItem(directory)
            let attributesRequested = attributes != nil
            logger.debug("enumerate dir=\(portableDirectory.identity.itemID) cookie=\(cookie.rawValue) verifier=\(verifier.rawValue) attrs=\(attributesRequested)")
            if PfsEnumerationCookies.isTerminal(cookie.rawValue) {
                return verifier
            }
            var daemonCookie = try PfsEnumerationCookies.daemonCookie(
                for: cookie.rawValue,
                attributesRequested: attributesRequested
            )
            var result = try await core.enumerate(
                directory: portableDirectory,
                startingAt: daemonCookie,
                wantAttributes: attributesRequested,
                maxEntries: PfsEnumerationCookies.daemonPageSize
            )
            // The verifier must change only when a genuine restart is required.
            // Daemon cookies are name-keyed resumption points, so a directory
            // that gains or loses entries between pages is still resumable
            // exactly where the last page stopped. Reporting the directory's
            // current version on every page would instead tell FSKit the
            // directory changed underneath a live walk — the invitation to
            // abandon or restart it, which is how a several-hundred-entry
            // listing comes back silently short under concurrent mutation.
            // A continuation therefore echoes the verifier FSKit handed us and
            // only the initial verifier mints one. Cookie zero with a nonzero
            // verifier is a framework restart of an existing walk, not a new
            // verifier epoch.
            let currentVerifier: FSDirectoryVerifier
            if PfsEnumerationCookies.isFreshStart(cookie: cookie.rawValue, verifier: verifier.rawValue) {
                currentVerifier = try PfsFSKitMapping.directoryVerifier(
                    from: result.verifier
                )
            } else {
                currentVerifier = verifier
            }

            let synthetics = try PfsEnumerationCookies.syntheticEntries(
                for: cookie.rawValue,
                attributesRequested: attributesRequested
            )
            let selfIdentifier = try PfsFSKitMapping.itemIdentifier(
                from: portableDirectory.identity.itemID
            )
            var parentIdentifier = selfIdentifier
            if synthetics.contains(where: { $0.isParentEntry }),
               let directoryAttr = try? await core.getattr(item: portableDirectory) {
                // A retained-but-unlinked directory still enumerates through
                // its open reference but has no live parent to name; POSIX
                // offers no better answer than itself, so a failed lookup
                // must not fail the enumeration.
                parentIdentifier = try PfsFSKitMapping.parentDirectoryIdentifier(
                    from: directoryAttr
                )
            }
            for entry in synthetics {
                let packed = packer.packEntry(
                    name: PfsFSKitMapping.fileName(from: entry.name),
                    itemType: .directory,
                    itemID: entry.isParentEntry ? parentIdentifier : selfIdentifier,
                    nextCookie: FSDirectoryCookie(entry.nextCookie),
                    attributes: nil
                )
                if !packed {
                    return currentVerifier
                }
            }

            var packedEntries: [PfsDirectoryEntry] = []
            var acceptedPagePrefixes: [(requestID: UInt64, count: UInt32)] = []

            func commitPackedEntries() async throws {
                let adopted = try await core.adoptEnumeratedItems(packedEntries)
                do {
                    for (entry, child) in zip(packedEntries, adopted) {
                        // Only an entry the packer accepted can become a kernel
                        // binding. Recording after `packEntry == true` keeps an
                        // unpacked suffix out of both the namespace repair index
                        // and VolumeCore's canonical item tables.
                        try await recordPublishedBinding(
                            parent: directory,
                            name: entry.name,
                            child: child,
                            itemKind: entry.attr.kind
                        )
                    }
                } catch {
                    // The packer has accepted this batch but local ownership
                    // installation could not be completed. Continuing would
                    // leave the kernel and repair index disagreeing, so retire
                    // the strict mount instead of publishing a partial cache.
                    await core.shutdown()
                    throw PfsLocalClientError.connectionClosed
                }
                for prefix in acceptedPagePrefixes {
                    core.client.acceptProvisionalItemPrefix(
                        targetRequestID: prefix.requestID,
                        count: prefix.count
                    )
                }
            }

            while true {
                for (entryIndex, entry) in result.entries.enumerated() {
                    let packed = packer.packEntry(
                        name: PfsFSKitMapping.fileName(from: entry.name),
                        itemType: PfsFSKitMapping.itemType(from: entry.attr.kind),
                        itemID: try PfsFSKitMapping.itemIdentifier(
                            from: entry.attr.item.itemID
                        ),
                        nextCookie: FSDirectoryCookie(
                            try PfsEnumerationCookies.fskitCookie(
                                for: entry.nextCookie,
                                attributesRequested: attributesRequested
                            )
                        ),
                        attributes: attributes == nil
                            ? nil
                            : try PfsFSKitMapping.attributes(
                                from: entry.attr,
                                requested: attributes?.wantedAttributes
                            )
                    )
                    if !packed {
                        acceptedPagePrefixes.append(
                            (
                                requestID: result.resourceRequestID,
                                count: UInt32(clamping: entryIndex)
                            )
                        )
                        try await commitPackedEntries()
                        return currentVerifier
                    }
                    packedEntries.append(entry)
                }

                acceptedPagePrefixes.append(
                    (
                        requestID: result.resourceRequestID,
                        count: UInt32(clamping: result.entries.count)
                    )
                )

                daemonCookie = result.nextCookie
                if daemonCookie == 0 {
                    break
                }
                result = try await core.enumerate(
                    directory: portableDirectory,
                    startingAt: daemonCookie,
                    wantAttributes: attributesRequested,
                    maxEntries: PfsEnumerationCookies.daemonPageSize
                )
            }
            try await commitPackedEntries()
            return currentVerifier
          } catch let error as PfsLocalClientError where error.posixErrno == ESTALE {
            // The daemon signals an unknown/expired/pre-restart enumeration cookie with
            // ESTALE (its documented fail-safe). Surface FSKit's invalid-directory-cookie
            // error so the kernel restarts the enumeration from scratch instead of
            // bubbling a raw POSIX ESTALE to readdir callers.
            throw PfsErrorMapper.invalidDirectoryCookieError()
          } catch {
              throw PfsErrorMapper.fsKitError(for: error)
          }
        }
    }

    @nonobjc
    public func openItem(_ item: FSItem, modes: FSVolume.OpenModes) async throws {
        if let portable = item as? PortableFSItem, await core.isLocalRepairItem(portable) {
            return
        }
        if let repairGate,
           let portable = item as? PortableFSItem,
           await repairGate.isArmedRepairSourceOpenItem(
               itemIdentity: portable.identity.stableIdentity
           ) {
            // macOS may open the exact source vnode while preparing unlinkat,
            // even for a metadata-only binding eviction. That open belongs to
            // the kernel-cache actuator: forwarding it would enter the
            // authority publication gate that this same COMPLETE repair holds
            // closed and deadlock the plan against itself. Keep the descriptor
            // lifecycle local for every armed source, not only data plans.
            // The kernel still holds a live object either way.
            try await recordLiveObject(portable)
            return
        }
        return try await core.client.withPublicationBoundary {
            do {
                let portable = try portableItem(item)
                try await core.open(item: portable, mode: PfsFSKitMapping.openMode(from: modes))
                try await recordLiveObject(portable)
            } catch {
                throw PfsErrorMapper.fsKitError(for: error)
            }
        }
    }

    @nonobjc
    public func closeItem(_ item: FSItem, modes: FSVolume.OpenModes) async throws {
        if let portable = item as? PortableFSItem, await core.isLocalRepairItem(portable) {
            return
        }
        if let repairGate,
           let portable = item as? PortableFSItem,
           await repairGate.isArmedRepairSourceItem(
               itemIdentity: portable.identity.stableIdentity
           ) {
            // Mirror of the repair-owned local open above. Any daemon
            // descriptors a user opened before the repair remain owned by
            // `VolumeCore` and are retired at reclaim; the live-object record
            // persists until reclaim regardless of close.
            return
        }
        return try await core.client.withPublicationBoundary {
            do {
                try await core.close(
                    item: try portableItem(item),
                    retainingModes: PfsFSKitMapping.openMode(from: modes)
                )
            } catch {
                throw PfsErrorMapper.fsKitError(for: error)
            }
        }
    }

    @nonobjc
    public func read(from item: FSItem, at offset: off_t, length: Int, into buffer: FSMutableFileDataBuffer) async throws -> Int {
        if let portable = item as? PortableFSItem, await core.isLocalRepairItem(portable) {
            throw Self.reservedNamespaceError()
        }
        return try await core.client.withPublicationBoundary {
          do {
            let pit = try portableItem(item)
            let data = try await core.read(item: pit, offset: UInt64(offset), length: UInt32(clamping: length))
            let copied = min(data.count, buffer.length)
            data.withUnsafeBytes { source in
                buffer.withUnsafeMutableBytes { destination in
                    if let src = source.baseAddress, let dst = destination.baseAddress {
                        memcpy(dst, src, copied)
                    }
                }
            }
            return copied
          } catch {
              throw PfsErrorMapper.fsKitError(for: error)
          }
        }
    }

    @nonobjc
    public func write(contents: Data, to item: FSItem, at offset: off_t) async throws -> Int {
        if let portable = item as? PortableFSItem, await core.isLocalRepairItem(portable) {
            throw Self.reservedNamespaceError()
        }
        return try await core.client.withPublicationBoundary {
            do {
                let result = try await core.write(item: try portableItem(item), offset: UInt64(offset), data: contents)
                return Int(result.written)
            } catch {
                throw PfsErrorMapper.fsKitError(for: error)
            }
        }
    }

    @nonobjc
    public func xattr(named name: FSFileName, of item: FSItem) async throws -> Data {
        // The repair scratch item exists only to make the kernel invalidate a
        // directory entry. FSKit probes xattrs while finishing create(2), but
        // that synthetic item has no daemon identity and no extended
        // attributes. Answer the probe locally: forwarding it would park on
        // the authority mutation whose COMPLETE is waiting for this repair.
        if let portable = item as? PortableFSItem {
            let xattrName = try PfsFSKitMapping.xattrName(from: name)
            if let local = await core.localRepairXattr(named: xattrName, of: portable) {
                guard let value = local else {
                    throw PfsErrorMapper.fsKitError(
                        for: PfsLocalClientError.daemon(
                            errno: ENOATTR,
                            message: "xattr not found"
                        )
                    )
                }
                return value
            }
        }
        return try await core.client.withPublicationBoundary {
            do {
                return try await core.xattrGet(item: try portableItem(item), name: try PfsFSKitMapping.xattrName(from: name))
            } catch {
                throw PfsErrorMapper.fsKitXattrError(for: error)
            }
        }
    }

    @nonobjc
    public func setXattr(named name: FSFileName, to value: Data?, on item: FSItem, policy: FSVolume.SetXattrPolicy) async throws {
        let xattrName: String
        let setModes: (createOnly: Bool, replaceOnly: Bool)?
        do {
            // Grammar and policy are request properties. Validate them before
            // item lifecycle or negotiated capability so EINVAL wins for a
            // malformed request even when its item is also reclaimed.
            xattrName = try PfsFSKitMapping.xattrName(from: name)
            setModes = try Self.xattrSetModes(for: policy)
        } catch {
            throw PfsErrorMapper.fsKitXattrError(for: error)
        }

        if let portable = item as? PortableFSItem {
            do {
                let isLocalRepairItem = await core.isLocalRepairItem(portable)
                if let setModes, !isLocalRepairItem {
                    // Revalidate the callback preflight at execution so a
                    // future writable-xattr capability cannot drift around the
                    // exact name/item/policy contract.
                    try await core.preflightXattrSet(
                        item: portable,
                        name: xattrName,
                        createOnly: setModes.createOnly,
                        replaceOnly: setModes.replaceOnly
                    )
                }
                if !isLocalRepairItem,
                   let repairGate,
                   await repairGate.isArmedRepairSourceItem(
                       itemIdentity: portable.identity.stableIdentity
                   ) {
                    // openat(O_RDWR) can issue bookkeeping xattr callbacks while
                    // COMPLETE owns the source. They must not enter the daemon
                    // gate; after full validation, refuse them locally.
                    throw PfsLocalClientError.daemon(
                        errno: EOPNOTSUPP,
                        message: "repair-source bookkeeping xattrs are unsupported"
                    )
                }

                let handled: Bool
                switch policy {
                case .delete:
                    handled = try await core.updateLocalRepairXattr(
                        named: xattrName, value: nil, on: portable,
                        createOnly: false, replaceOnly: false, remove: true
                    )
                case .mustCreate:
                    handled = try await core.updateLocalRepairXattr(
                        named: xattrName, value: value, on: portable,
                        createOnly: true, replaceOnly: false, remove: false
                    )
                case .mustReplace:
                    handled = try await core.updateLocalRepairXattr(
                        named: xattrName, value: value, on: portable,
                        createOnly: false, replaceOnly: true, remove: false
                    )
                case .alwaysSet:
                    handled = try await core.updateLocalRepairXattr(
                        named: xattrName, value: value, on: portable,
                        createOnly: false, replaceOnly: false, remove: false
                    )
                @unknown default:
                    throw PfsLocalClientError.daemon(errno: EINVAL, message: "unknown xattr policy")
                }
                if handled { return }
            } catch {
                throw PfsErrorMapper.fsKitXattrError(for: error)
            }
        }
        try await core.client.withPublicationBoundary {
          do {
            let portable = try portableItem(item)
            switch policy {
            case .delete:
                try await core.xattrRemove(item: portable, name: xattrName)
            case .mustCreate:
                try await core.xattrSet(item: portable, name: xattrName, value: value ?? Data(), createOnly: true, replaceOnly: false)
            case .mustReplace:
                try await core.xattrSet(item: portable, name: xattrName, value: value ?? Data(), createOnly: false, replaceOnly: true)
            case .alwaysSet:
                try await core.xattrSet(item: portable, name: xattrName, value: value ?? Data(), createOnly: false, replaceOnly: false)
            @unknown default:
                throw PfsLocalClientError.daemon(errno: EINVAL, message: "unknown xattr policy")
            }
          } catch {
              throw PfsErrorMapper.fsKitXattrError(for: error)
          }
        }
    }

    @nonobjc
    public func xattrs(of item: FSItem) async throws -> [FSFileName] {
        if let portable = item as? PortableFSItem,
           let names = await core.localRepairXattrs(of: portable) {
            return names.map { FSFileName(string: $0) }
        }
        return try await core.client.withPublicationBoundary {
            do {
                let names = try await core.xattrList(item: try portableItem(item))
                return names.map { FSFileName(string: $0) }
            } catch {
                throw PfsErrorMapper.fsKitXattrError(for: error)
            }
        }
    }

    public func setAttributes(
        _ newAttributes: FSItem.SetAttributesRequest,
        on item: FSItem,
        replyHandler reply: @escaping (FSItem.Attributes?, Error?) -> Void
    ) {
        let preflight = PfsAttributeRefreshCallbackPreflight()
        let itemBox = PfsUncheckedSendableBox(item)
        let attributesBox = PfsUncheckedSendableBox(newAttributes)
        let ordinaryExemption = admissionExemption(
            items: [item],
            includeAttributeRefreshItems: false
        )
        publishAfterReply(exemptFromAdmission: { [weak self] in
            guard let self else { return true }
            do {
                if let attributes = try await self.consumeArmedAttributeRefresh(
                    attributesBox.value,
                    on: itemBox.value
                ) {
                    await preflight.record(attributes)
                    return true
                }
            } catch {
                // Fail closed through ordinary admission. If this is the
                // actuator callback, its syscall fails and the event fences;
                // no unvalidated setattr may cross the COMPLETE boundary.
            }
            return await ordinaryExemption()
        }, admissionScope: admissionScope(
            items: [item], orderedMutation: true
        ), {
            if let attributes = await preflight.take() {
                do {
                    return try self.finishArmedAttributeRefresh(
                        attributes,
                        consuming: attributesBox.value
                    )
                } catch {
                    throw PfsErrorMapper.fsKitError(for: error)
                }
            }
            return try await self.setAttributes(attributesBox.value, on: itemBox.value)
        }, reply: { result in
            switch result {
            case let .success(attributes): reply(attributes, nil)
            case let .failure(error): reply(nil, error)
            }
        })
    }

    public func lookupItem(
        named name: FSFileName,
        inDirectory directory: FSItem,
        replyHandler reply: @escaping (FSItem?, FSFileName?, Error?) -> Void
    ) {
        // The lookup is THE repair-resolution path: the actuator's own VFS
        // syscalls resolve ancestor components through this callback, so a
        // closed gate that held every lookup deadlocked the repair against
        // itself. The gate authorizes only the source coordinate or an exact
        // ancestor coordinate captured from the namespace index at event arm.
        publishAfterReply(exemptFromAdmission: admissionExemption(
            reservedNames: [name.data],
            repairSources: [(name.data, directory)]
        ), admissionScope: admissionScope(
            namespace: [(directory, name.data)]
        ), {
            try await self.lookupItem(named: name, inDirectory: directory)
        }, reply: { result in
            switch result {
            case let .success((item, canonicalName)): reply(item, canonicalName, nil)
            case let .failure(error): reply(nil, nil, error)
            }
        })
    }

    public func reclaimItem(
        _ item: FSItem,
        replyHandler reply: @escaping (Error?) -> Void
    ) {
        publishAfterReply(exemptFromAdmission: admissionExemption(
            repairSourceItems: [item],
            items: [item]
        ), admissionScope: admissionScope(items: [item]), {
            try await self.reclaimItem(item)
        }, reply: { result in
            switch result {
            case .success: reply(nil)
            case let .failure(error): reply(error)
            }
        })
    }

    public func readSymbolicLink(
        _ item: FSItem,
        replyHandler reply: @escaping (FSFileName?, Error?) -> Void
    ) {
        publishAfterReply(admissionScope: admissionScope(items: [item]), {
            try await self.readSymbolicLink(item)
        }, reply: { result in
            switch result {
            case let .success(contents): reply(contents, nil)
            case let .failure(error): reply(nil, error)
            }
        })
    }

    public func createItem(
        named name: FSFileName,
        type: FSItem.ItemType,
        inDirectory directory: FSItem,
        attributes newAttributes: FSItem.SetAttributesRequest,
        replyHandler reply: @escaping (FSItem?, FSFileName?, Error?) -> Void
    ) {
        publishAfterReply(
            exemptFromAdmission: admissionExemption(reservedNames: [name.data]),
            admissionScope: admissionScope(
                namespace: [(directory, name.data)],
                directories: [directory],
                orderedMutation: true
            ),
            {
            try await self.createItem(
                named: name,
                type: type,
                inDirectory: directory,
                attributes: newAttributes
            )
        }, reply: { result in
            switch result {
            case let .success((item, canonicalName)): reply(item, canonicalName, nil)
            case let .failure(error): reply(nil, nil, error)
            }
        })
    }

    public func createSymbolicLink(
        named name: FSFileName,
        inDirectory directory: FSItem,
        attributes newAttributes: FSItem.SetAttributesRequest,
        linkContents contents: FSFileName,
        replyHandler reply: @escaping (FSItem?, FSFileName?, Error?) -> Void
    ) {
        publishAfterReply(
            exemptFromAdmission: admissionExemption(reservedNames: [name.data]),
            admissionScope: admissionScope(
                namespace: [(directory, name.data)],
                directories: [directory],
                orderedMutation: true
            ),
            {
            try await self.createSymbolicLink(
                named: name,
                inDirectory: directory,
                attributes: newAttributes,
                linkContents: contents
            )
        }, reply: { result in
            switch result {
            case let .success((item, canonicalName)): reply(item, canonicalName, nil)
            case let .failure(error): reply(nil, nil, error)
            }
        })
    }

    public func createLink(
        to item: FSItem,
        named name: FSFileName,
        inDirectory directory: FSItem,
        replyHandler reply: @escaping (FSFileName?, Error?) -> Void
    ) {
        publishAfterReply(
            exemptFromAdmission: admissionExemption(reservedNames: [name.data]),
            admissionScope: admissionScope(
                namespace: [(directory, name.data)],
                directories: [directory],
                items: [item],
                orderedMutation: true
            ),
            {
            try await self.createLink(to: item, named: name, inDirectory: directory)
        }, reply: { result in
            switch result {
            case let .success(canonicalName): reply(canonicalName, nil)
            case let .failure(error): reply(nil, error)
            }
        })
    }

    public func removeItem(
        _ item: FSItem,
        named name: FSFileName,
        fromDirectory directory: FSItem,
        replyHandler reply: @escaping (Error?) -> Void
    ) {
        publishAfterReply(exemptFromAdmission: admissionExemption(
            reservedNames: [name.data],
            repairSources: [(name.data, directory)],
            repairSourceItems: [item],
            items: [item]
        ), admissionScope: admissionScope(
            namespace: [(directory, name.data)],
            directories: [directory],
            items: [item],
            orderedMutation: true
        ), {
            try await self.removeItem(item, named: name, fromDirectory: directory)
        }, reply: { result in
            switch result {
            case .success: reply(nil)
            case let .failure(error): reply(error)
            }
        })
    }

    public func renameItem(
        _ item: FSItem,
        inDirectory sourceDirectory: FSItem,
        named sourceName: FSFileName,
        to destinationName: FSFileName,
        inDirectory destinationDirectory: FSItem,
        overItem: FSItem?,
        replyHandler reply: @escaping (FSFileName?, Error?) -> Void
    ) {
        publishAfterReply(
            exemptFromAdmission: admissionExemption(
                reservedNames: [sourceName.data, destinationName.data]
            ),
            admissionScope: admissionScope(
                namespace: [
                    (sourceDirectory, sourceName.data),
                    (destinationDirectory, destinationName.data),
                ],
                directories: [sourceDirectory, destinationDirectory],
                items: [item, overItem],
                orderedMutation: true
            ),
            {
            try await self.renameItem(
                item,
                inDirectory: sourceDirectory,
                named: sourceName,
                to: destinationName,
                inDirectory: destinationDirectory,
                overItem: overItem
            )
        }, reply: { result in
            switch result {
            case let .success(canonicalName): reply(canonicalName, nil)
            case let .failure(error): reply(nil, error)
            }
        })
    }

    public func enumerateDirectory(
        _ directory: FSItem,
        startingAt cookie: FSDirectoryCookie,
        verifier: FSDirectoryVerifier,
        attributes: FSItem.GetAttributesRequest?,
        packer: FSDirectoryEntryPacker,
        replyHandler reply: @escaping (FSDirectoryVerifier, Error?) -> Void
    ) {
        publishAfterReply(admissionScope: admissionScope(
            directories: [directory],
            items: [directory]
        ), {
            try await self.enumerateDirectory(
                directory,
                startingAt: cookie,
                verifier: verifier,
                attributes: attributes,
                packer: packer
            )
        }, reply: { result in
            switch result {
            case let .success(currentVerifier): reply(currentVerifier, nil)
            case let .failure(error): reply(.initial, error)
            }
        })
    }

    public func openItem(
        _ item: FSItem,
        modes: FSVolume.OpenModes,
        replyHandler reply: @escaping (Error?) -> Void
    ) {
        publishAfterReply(exemptFromAdmission: admissionExemption(
            repairSourceItems: [item],
            repairParentItems: [item],
            items: [item]
        ), admissionScope: admissionScope(items: [item]), {
            try await self.openItem(item, modes: modes)
        }, reply: { result in
            switch result {
            case .success: reply(nil)
            case let .failure(error): reply(error)
            }
        })
    }

    public func closeItem(
        _ item: FSItem,
        modes: FSVolume.OpenModes,
        replyHandler reply: @escaping (Error?) -> Void
    ) {
        publishAfterReply(exemptFromAdmission: admissionExemption(
            repairSourceItems: [item],
            repairParentItems: [item],
            items: [item]
        ), admissionScope: admissionScope(items: [item]), {
            try await self.closeItem(item, modes: modes)
        }, reply: { result in
            switch result {
            case .success: reply(nil)
            case let .failure(error): reply(error)
            }
        })
    }

    public func read(
        from item: FSItem,
        at offset: off_t,
        length: Int,
        into buffer: FSMutableFileDataBuffer,
        replyHandler reply: @escaping (Int, Error?) -> Void
    ) {
        publishAfterReply(exemptFromAdmission: admissionExemption(items: [item]), admissionScope: admissionScope(items: [item]), {
            try await self.read(from: item, at: offset, length: length, into: buffer)
        }, reply: { result in
            switch result {
            case let .success(count): reply(count, nil)
            case let .failure(error): reply(0, error)
            }
        })
    }

    public func write(
        contents: Data,
        to item: FSItem,
        at offset: off_t,
        replyHandler reply: @escaping (Int, Error?) -> Void
    ) {
        publishAfterReply(exemptFromAdmission: admissionExemption(items: [item]), admissionScope: admissionScope(
            items: [item], orderedMutation: true
        ), {
            try await self.write(contents: contents, to: item, at: offset)
        }, reply: { result in
            switch result {
            case let .success(count): reply(count, nil)
            case let .failure(error): reply(0, error)
            }
        })
    }

    public func getXattr(
        named name: FSFileName,
        of item: FSItem,
        replyHandler reply: @escaping (Data?, Error?) -> Void
    ) {
        publishAfterReply(exemptFromAdmission: admissionExemption(
            repairSourceItems: [item],
            items: [item]
        ), admissionScope: admissionScope(items: [item]), {
            try await self.xattr(named: name, of: item)
        }, reply: { result in
            switch result {
            case let .success(value): reply(value, nil)
            case let .failure(error): reply(nil, error)
            }
        })
    }

    public func setXattr(
        named name: FSFileName,
        to value: Data?,
        on item: FSItem,
        policy: FSVolume.SetXattrPolicy,
        replyHandler reply: @escaping (Error?) -> Void
    ) {
        let preflightItem = PfsUncheckedSendableBox(item)
        let preflightName = PfsUncheckedSendableBox(name)
        publishAfterReply(preflight: {
            guard let modes = try Self.xattrSetModes(for: policy) else { return }
            let xattrName = try PfsFSKitMapping.xattrName(from: preflightName.value)
            let portable = try self.portableItem(preflightItem.value)
            if await self.core.isLocalRepairItem(portable) { return }
            do {
                try await self.core.preflightXattrSet(
                    item: portable,
                    name: xattrName,
                    createOnly: modes.createOnly,
                    replaceOnly: modes.replaceOnly
                )
            } catch {
                throw PfsErrorMapper.fsKitXattrError(for: error)
            }
        }, exemptFromAdmission: admissionExemption(
            repairSourceItems: [item],
            items: [item]
        ), admissionScope: admissionScope(
            items: [item], orderedMutation: true
        ), {
            try await self.setXattr(named: name, to: value, on: item, policy: policy)
        }, reply: { result in
            switch result {
            case .success: reply(nil)
            case let .failure(error): reply(error)
            }
        })
    }

    public func listXattrs(
        of item: FSItem,
        replyHandler reply: @escaping ([FSFileName]?, Error?) -> Void
    ) {
        publishAfterReply(exemptFromAdmission: admissionExemption(
            repairSourceItems: [item],
            items: [item]
        ), admissionScope: admissionScope(items: [item]), {
            try await self.xattrs(of: item)
        }, reply: { result in
            switch result {
            case let .success(names): reply(names, nil)
            case let .failure(error): reply(nil, error)
            }
        })
    }

    public func shutdown() async {
        coherence?.shutdown()
        await core.shutdown()
    }

    private func setCachedStatistics(_ statistics: FSStatFSResult) {
        statLock.lock()
        cachedStatistics = statistics
        statLock.unlock()
    }

    private func portableItem(_ item: FSItem) throws -> PortableFSItem {
        guard let portable = item as? PortableFSItem else {
            throw PfsLocalClientError.daemon(errno: ESTALE, message: "unknown FSItem")
        }
        return portable
    }

    /// Converts FSKit's write policy before item lookup or capability checks so
    /// malformed policy/name input keeps EINVAL precedence over ESTALE and the
    /// production EOPNOTSUPP refusal. Delete is the separately supported
    /// xattr-remove operation and therefore has no set modes.
    private static func xattrSetModes(
        for policy: FSVolume.SetXattrPolicy
    ) throws -> (createOnly: Bool, replaceOnly: Bool)? {
        switch policy {
        case .mustCreate:
            return (true, false)
        case .mustReplace:
            return (false, true)
        case .alwaysSet:
            return (false, false)
        case .delete:
            return nil
        @unknown default:
            throw PfsLocalClientError.daemon(
                errno: EINVAL,
                message: "unknown xattr policy"
            )
        }
    }

    // MARK: - Strict-v3 index population

    /// Attempts to bind the deferred repair actuator to the live kernel mount,
    /// once. Failure stays loud at repair time: an uninstalled actuator fails
    /// every repair closed and the barrier reports the cursor blocked.
    private func scheduleRepairRootInstall() {
        guard let coherence else { return }
        let typeName = fileSystemTypeName
        let attachRef = attachRef
        let handoffSocket = mountRootHandoffSocket
        coherence.scheduleActuatorInstall {
            // The root is authority item 1, projected through the platform
            // identifier offset like every other inode this mount reports.
            let expected = try PfsFSKitMapping.itemIdentifier(from: 1).rawValue
            do {
                // The daemon hands the descriptor across the sandbox boundary:
                // the sandbox hides this extension's own mount from getfsstat,
                // so in-process location cannot work (proven live — the first
                // peer repair scanned fifteen mounts and found every volume on
                // the machine except its own).
                return try PfsMountRootHandoff.openRoot(
                    handoffSocketPath: handoffSocket,
                    attachRef: attachRef,
                    expectedRootFileID: expected
                )
            } catch {
                pfsClientLogger.error(
                    "mount-root handoff failed (\(String(describing: error), privacy: .public)); falling back to the in-process mount scan"
                )
                return try PfsMacOSMountRootLocator.openMountRoot(
                    fileSystemTypeName: typeName,
                    attachRef: attachRef,
                    expectedRootFileID: expected
                )
            }
        }
    }

    /// The stable identity a strict mount must have for every item a repair
    /// could ever address. A strict daemon always supplies it; an item without
    /// one cannot be indexed, so publishing it would break the "absent from
    /// the index means provably uncached" claim. Fail the callback closed
    /// instead of publishing an untracked binding.
    private func strictStableIdentity(of item: PortableFSItem) throws -> PfsMacOSStableIdentity {
        do {
            return try PfsMacOSStableIdentity(item.identity.stableIdentity)
        } catch {
            throw PfsLocalClientError.daemon(
                errno: EIO,
                message: "strict-v3 item carries no stable identity"
            )
        }
    }

    private func reserveBindingPublication(
        parent: FSItem,
        name: Data,
        itemKind: PfsMacOSCachedItemKind
    ) async throws -> PendingBindingPublication? {
        guard let coherence else { return nil }
        let parentIdentity = try strictStableIdentity(of: try portableItem(parent))
        guard let reservation = try await coherence.namespaceIndex.reserveRecord(
            parentIdentity: parentIdentity,
            name: name,
            capacity: coherence.namespaceCapacity
        ) else {
            throw PfsLocalClientError.daemon(
                errno: EIO,
                message: "strict-v3 namespace index is at capacity"
            )
        }
        return PendingBindingPublication(
            reservation: reservation,
            parentIdentity: parentIdentity,
            name: name,
            itemKind: itemKind
        )
    }

    private func commitBindingPublication(
        _ pending: PendingBindingPublication?,
        child: PortableFSItem
    ) async throws {
        guard let coherence, let pending else { return }
        do {
            let childIdentity = try strictStableIdentity(of: child)
            let vfsFileID = try PfsFSKitMapping.itemIdentifier(
                from: child.identity.itemID
            ).rawValue
            await coherence.namespaceIndex.commitRecord(
                pending.reservation,
                identity: childIdentity,
                entry: .init(
                    parentIdentity: pending.parentIdentity,
                    name: pending.name,
                    vfsFileID: vfsFileID,
                    itemKind: pending.itemKind
                )
            )
            // Binding publication is the authoritative point at which this
            // mount learns the immutable vnode kind. It must precede a later
            // live-object reservation commit so a locally created file remains
            // representable after its last published coordinate is evicted.
            await coherence.liveObjects.recordItemKind(
                identity: childIdentity,
                itemKind: pending.itemKind
            )
        } catch {
            await coherence.namespaceIndex.cancel(pending.reservation)
            // The authority has already reported success. A malformed item at
            // this point is an unrecoverable publication-coherence failure,
            // never an ordinary syscall result that may be retried.
            await core.shutdown()
            throw PfsLocalClientError.connectionClosed
        }
    }

    private func cancelBindingPublication(_ pending: PendingBindingPublication?) async {
        guard let coherence, let pending else { return }
        await coherence.namespaceIndex.cancel(pending.reservation)
    }

    private func reserveBindingForget(
        parent: FSItem,
        name: Data,
        child: PortableFSItem
    ) async throws -> PendingBindingForget? {
        guard let coherence else { return nil }
        let reservation = try await coherence.namespaceIndex.reserveForget(
            parentIdentity: try strictStableIdentity(of: try portableItem(parent)),
            name: name,
            expectedIdentity: try strictStableIdentity(of: child)
        )
        return PendingBindingForget(reservation: reservation)
    }

    private func commitBindingForget(_ pending: PendingBindingForget?) async {
        guard let coherence, let pending else { return }
        await coherence.namespaceIndex.commitForget(pending.reservation)
    }

    private func cancelBindingForget(_ pending: PendingBindingForget?) async {
        guard let coherence, let pending else { return }
        await coherence.namespaceIndex.cancel(pending.reservation)
    }

    private func reserveBindingMove(
        from sourceParent: FSItem,
        name sourceName: Data,
        to destinationParent: FSItem,
        name destinationName: Data,
        child: PortableFSItem
    ) async throws -> PendingBindingMove? {
        guard let coherence else { return nil }
        let reservation = try await coherence.namespaceIndex.reserveMove(
            parentIdentity: try strictStableIdentity(of: try portableItem(sourceParent)),
            name: sourceName,
            toParentIdentity: try strictStableIdentity(of: try portableItem(destinationParent)),
            toName: destinationName,
            expectedIdentity: try strictStableIdentity(of: child)
        )
        return PendingBindingMove(reservation: reservation)
    }

    private func commitBindingMove(_ pending: PendingBindingMove?) async {
        guard let coherence, let pending else { return }
        await coherence.namespaceIndex.commitMove(pending.reservation)
    }

    private func cancelBindingMove(_ pending: PendingBindingMove?) async {
        guard let coherence, let pending else { return }
        await coherence.namespaceIndex.cancel(pending.reservation)
    }

    private func reserveLiveObject() async throws -> PendingLiveObject? {
        guard let coherence else { return nil }
        guard let reservation = await coherence.liveObjects.reserve(
            capacity: coherence.liveObjectCapacity
        ) else {
            throw PfsLocalClientError.daemon(
                errno: EIO,
                message: "strict-v3 live-object index is at capacity"
            )
        }
        return PendingLiveObject(reservation: reservation)
    }

    private func commitLiveObject(
        _ pending: PendingLiveObject?,
        item: PortableFSItem
    ) async throws {
        guard let coherence, let pending else { return }
        do {
            let identity = try strictStableIdentity(of: item)
            let vfsFileID = try PfsFSKitMapping.itemIdentifier(
                from: item.identity.itemID
            ).rawValue
            await coherence.liveObjects.commit(
                pending.reservation,
                item: item,
                identity: identity,
                vfsFileID: vfsFileID
            )
        } catch {
            await coherence.liveObjects.cancel(pending.reservation)
            await core.shutdown()
            throw PfsLocalClientError.connectionClosed
        }
    }

    private func cancelLiveObject(_ pending: PendingLiveObject?) async {
        guard let coherence, let pending else { return }
        await coherence.liveObjects.cancel(pending.reservation)
    }

    /// Records one published namespace binding. Every callback that returns a
    /// (parent, name) -> item binding to the kernel must pass through here
    /// before its reply publishes, or "unknown" stops meaning "uncached".
    /// The capacity bound refuses NEW bindings rather than dropping old ones:
    /// macOS 26 has no synchronous revocation to make an eviction sound, and
    /// a silently LRU-dropped record is a kernel cache entry this mount can no
    /// longer repair.
    private func recordPublishedBinding(
        parent: FSItem,
        name: Data,
        child: PortableFSItem,
        itemKind: PfsItemKind? = nil
    ) async throws {
        guard let coherence else { return }
        let parentIdentity = try strictStableIdentity(of: try portableItem(parent))
        let childIdentity = try strictStableIdentity(of: child)
        let cachedItemKind: PfsMacOSCachedItemKind
        if let itemKind {
            cachedItemKind = try PfsMacOSCachedItemKind(itemKind)
        } else {
            cachedItemKind = try PfsMacOSCachedItemKind(
                try await core.getattr(item: child).kind
            )
        }
        let vfsFileID = try PfsFSKitMapping.itemIdentifier(from: child.identity.itemID).rawValue
        guard await coherence.namespaceIndex.record(
            identity: childIdentity,
            entry: .init(
                parentIdentity: parentIdentity,
                name: name,
                vfsFileID: vfsFileID,
                itemKind: cachedItemKind
            ),
            capacity: coherence.namespaceCapacity
        ) else {
            throw PfsLocalClientError.daemon(
                errno: EIO,
                message: "strict-v3 namespace index is at capacity"
            )
        }
        await coherence.liveObjects.recordItemKind(
            identity: childIdentity,
            itemKind: cachedItemKind
        )
    }

    private func movePublishedBinding(
        from sourceParent: FSItem,
        name sourceName: Data,
        to destinationParent: FSItem,
        name destinationName: Data,
        child: PortableFSItem
    ) async throws {
        guard let coherence else { return }
        try await coherence.namespaceIndex.move(
            parentIdentity: try strictStableIdentity(of: try portableItem(sourceParent)),
            name: sourceName,
            toParentIdentity: try strictStableIdentity(of: try portableItem(destinationParent)),
            toName: destinationName,
            expectedIdentity: try strictStableIdentity(of: child)
        )
    }

    private func retainDataRepairLocator(
        parent: FSItem,
        name: Data,
        child: PortableFSItem
    ) async throws {
        guard let coherence else { return }
        try await coherence.namespaceIndex.retainDataRepairLocator(
            parentIdentity: try strictStableIdentity(of: try portableItem(parent)),
            name: name,
            expectedIdentity: try strictStableIdentity(of: child)
        )
    }

    private func forgetPublishedBinding(parent: FSItem, name: Data) async throws {
        guard let coherence else { return }
        let parentIdentity = try strictStableIdentity(of: try portableItem(parent))
        await coherence.namespaceIndex.forget(parentIdentity: parentIdentity, name: name)
    }

    /// Records one kernel object with live open state. Unlink retires the
    /// namespace coordinate but never this record; only reclaim does.
    private func recordLiveObject(_ item: PortableFSItem) async throws {
        guard let coherence else { return }
        _ = try strictStableIdentity(of: item)
        let vfsFileID = try PfsFSKitMapping.itemIdentifier(from: item.identity.itemID).rawValue
        do {
            guard try await coherence.liveObjects.record(
                item: item,
                vfsFileID: vfsFileID,
                capacity: coherence.liveObjectCapacity
            ) else {
                throw PfsLocalClientError.daemon(
                    errno: EIO,
                    message: "strict-v3 live-object index is at capacity"
                )
            }
        } catch let error as PfsLocalClientError {
            throw error
        } catch {
            throw PfsLocalClientError.daemon(
                errno: EIO,
                message: "strict-v3 live-object record failed"
            )
        }
    }

    private func forgetLiveObject(_ item: PortableFSItem) async {
        guard let coherence else { return }
        await coherence.liveObjects.forget(item: item)
    }

    /// The single decision point for every reserved name this adapter is
    /// handed. Without a gate, or with a gate that does not hold a live
    /// authorization for exactly this callback on exactly this operand, the
    /// operation is refused and never becomes a pfslocal request.
    private func consumeRepairCallback(
        _ callback: PfsMacOS26RepairCallback,
        operand: Data,
        directory: FSItem
    ) async throws {
        guard let repairGate else { throw Self.reservedNamespaceError() }
        do {
            try await repairGate.consume(
                callback: callback,
                operand: operand,
                // The plan's HMAC binds a parent identity; handing the gate
                // the directory THIS callback actually names is what stops a
                // same-basename callback in a different directory from being
                // swallowed as repair.
                parentIdentity: (directory as? PortableFSItem)?.identity.stableIdentity
            )
        } catch {
            logger.error(
                "refused reserved-namespace callback: \(String(describing: error), privacy: .public)"
            )
            throw Self.reservedNamespaceError()
        }
    }

    static func reservedNamespaceError() -> Error {
        PfsErrorMapper.fsKitError(
            for: PfsLocalClientError.daemon(
                errno: EPERM,
                message: "the reserved repair namespace is not part of the user namespace"
            )
        )
    }

}
