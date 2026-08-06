import Foundation
@preconcurrency import Darwin

// MARK: - Callback admission

/// One ordinary cache-producing FSKit callback, from admission until its
/// reply crosses the framework publication boundary.
///
/// The ticket is the barrier's unit of accounting and the pfslocal client's
/// reporting channel: `PfsLocalClient` stamps the callback's logical operation
/// ID onto the current task's ticket the moment it allocates one, which is
/// what lets a PREPARE barrier exempt exactly the initiating callback rather
/// than guessing from paths.
public final class PfsMacOSAdmittedCallbackTicket: @unchecked Sendable {
    private let lock = NSLock()
    private var operationID: UInt64?
    private var published = false
    private var orderedMutationsInFlight = 0
    private var publicationWaiters: [CheckedContinuation<Void, Never>] = []
    private var drainWaiters: [CheckedContinuation<Void, Never>] = []

    public init() {}

    /// Records the pfslocal logical operation ID once. A callback owns at most
    /// one logical operation; later stamps for the same operation are no-ops.
    public func noteOperationID(_ id: UInt64) {
        lock.lock()
        if operationID == nil {
            operationID = id
        }
        lock.unlock()
    }

    func currentOperationID() -> UInt64? {
        lock.lock()
        defer { lock.unlock() }
        return operationID
    }

    /// Marks an authority-ordered mutation of this callback in flight. The
    /// authority orders it strictly after any barrier it did not initiate, so
    /// from this instant the callback is parked outside that barrier's
    /// critical section and a PREPARE drain must release it (see
    /// `waitUntilPublishedOrParked`).
    public func orderedMutationSubmitted() {
        lock.lock()
        orderedMutationsInFlight += 1
        let waiters = drainWaiters
        drainWaiters.removeAll()
        lock.unlock()
        for waiter in waiters {
            waiter.resume()
        }
    }

    public func orderedMutationSettled() {
        lock.lock()
        orderedMutationsInFlight -= 1
        lock.unlock()
    }

    func markPublished() {
        lock.lock()
        published = true
        let waiters = publicationWaiters + drainWaiters
        publicationWaiters.removeAll()
        drainWaiters.removeAll()
        lock.unlock()
        for waiter in waiters {
            waiter.resume()
        }
    }

    func waitUntilPublished() async {
        await withCheckedContinuation { continuation in
            lock.lock()
            if published {
                lock.unlock()
                continuation.resume()
                return
            }
            publicationWaiters.append(continuation)
            lock.unlock()
        }
    }

    /// The PREPARE drain wait: returns when the callback's reply has crossed
    /// the framework publication boundary, OR the moment the callback parks an
    /// authority-ordered mutation. Waiting past that moment would be the
    /// two-writer drain deadlock the coherence design forbids — the mutation's
    /// reply needs the barrier to complete, and the barrier would be waiting
    /// for the reply's publication.
    func waitUntilPublishedOrParked() async {
        await withCheckedContinuation { continuation in
            lock.lock()
            if published || orderedMutationsInFlight > 0 {
                lock.unlock()
                continuation.resume()
                return
            }
            drainWaiters.append(continuation)
            lock.unlock()
        }
    }
}

/// Task-local bridge from the FSKit callback that admitted itself to the
/// pfslocal client that allocates its logical operation ID. Task locals flow
/// across actor hops within one task, so the client sees exactly the callback
/// it is working for and no other.
public enum PfsMacOSCallbackAdmission {
    @TaskLocal public static var ticket: PfsMacOSAdmittedCallbackTicket?
}

/// The production `PfsMacOSCallbackPublicationBarrier`.
///
/// PREPARE closes ordinary callback-publication admission and drains every
/// already-admitted cache-producing callback through its framework reply,
/// exempting exactly the initiating callback named by the event's pfslocal
/// operation ID. The gate stays closed through COMPLETE: a peer COMPLETE
/// reopens after the backend's repairs finished; this mount's own COMPLETE
/// first waits for the initiating callback's ordinary reply to cross the
/// publication boundary — the deferred source COMPLETE — and only then
/// reopens. The repair actuator's re-entrant callbacks never enter admission
/// at all: they carry the armed reserved-name operands (or address the armed
/// isolation item) and the adapter routes them around this gate, which is the
/// only reason a repair can make progress while the gate it serves is closed.
public actor PfsMacOSFSKitPublicationBarrier: PfsMacOSCallbackPublicationBarrier {
    private let localAuthoritySessionID: Data
    private var closed = false
    private var terminal: Error?
    private var admitted: [ObjectIdentifier: PfsMacOSAdmittedCallbackTicket] = [:]
    private var admissionWaiters: [CheckedContinuation<Void, Error>] = []

    public init(localAuthoritySessionID: Data) throws {
        guard localAuthoritySessionID.count == 16 else {
            throw PfsMacOSCoherenceError.invalidSessionIDLength(localAuthoritySessionID.count)
        }
        self.localAuthoritySessionID = localAuthoritySessionID
    }

    /// Admits one ordinary cache-producing callback, waiting while the gate is
    /// closed. Throws once the barrier has failed terminally: a mount whose
    /// coherence session is over must not publish anything further.
    public func admit() async throws -> PfsMacOSAdmittedCallbackTicket {
        while true {
            if let terminal { throw terminal }
            if !closed {
                let ticket = PfsMacOSAdmittedCallbackTicket()
                admitted[ObjectIdentifier(ticket)] = ticket
                return ticket
            }
            try await withCheckedThrowingContinuation { continuation in
                admissionWaiters.append(continuation)
            }
        }
    }

    /// Marks the callback's reply as having crossed the framework publication
    /// boundary. This — not the async method's return — is the drain point
    /// PREPARE waits for.
    public func published(_ ticket: PfsMacOSAdmittedCallbackTicket) {
        admitted.removeValue(forKey: ObjectIdentifier(ticket))
        ticket.markPublished()
    }

    public func admittedCallbackCount() -> Int { admitted.count }
    public func isAdmissionClosed() -> Bool { closed }

    public func prepare(_ event: PfsMacOSCoherenceEvent) async throws {
        if let terminal { throw terminal }
        closed = true
        let exemptOperationID = event.initiator.sessionID == localAuthoritySessionID
            ? event.initiator.localOperationID
            : nil
        // Snapshot before waiting: callbacks admitted later are held at the
        // gate and are not this barrier's obligation. The initiating callback
        // must not be waited on — it is waiting for the authority reply that
        // this very barrier gates — and its operation ID was stamped when its
        // mutation request was sent, strictly before the authority could have
        // begun this barrier.
        //
        // The drain waits for a callback only while it is PUBLISHING — its
        // reply is crossing the framework boundary, bounded local work. A
        // callback that has parked an authority-ordered mutation is released
        // immediately, and one that parks a mutation mid-drain is released at
        // that instant: the authority orders that mutation strictly after
        // this barrier, so its reply — and therefore its publication — cannot
        // happen until this barrier completes, and waiting for it is the
        // two-writer drain deadlock the coherence design forbids. Concurrent
        // mutations (a `git init` copying hook templates) made this barrier
        // wait on exactly that, and the mount died at its repair budget. The
        // exempted callback's eventual publication reflects state the
        // authority ordered after this barrier, so releasing it early
        // publishes newer truth, never stale truth.
        let drain = admitted.values.filter { ticket in
            guard let exemptOperationID else { return true }
            return ticket.currentOperationID() != exemptOperationID
        }
        for ticket in drain {
            await ticket.waitUntilPublishedOrParked()
        }
    }

    public func resume(_ event: PfsMacOSCoherenceEvent) async throws {
        if let terminal { throw terminal }
        if event.initiator.sessionID == localAuthoritySessionID,
           let operationID = event.initiator.localOperationID {
            // The deferred source COMPLETE: acknowledged only after the exact
            // initiating callback published its ordinary FSKit reply. If no
            // admitted ticket carries the ID, the callback has already
            // published — a ticket leaves `admitted` only through `published`,
            // and the daemon names only operations it observed on a request.
            if let ticket = admitted.values.first(
                where: { $0.currentOperationID() == operationID }
            ) {
                await ticket.waitUntilPublished()
            }
        }
        closed = false
        let waiters = admissionWaiters
        admissionWaiters.removeAll()
        for waiter in waiters {
            waiter.resume()
        }
    }

    /// Terminal failure: the coherence session is over. Every waiting and
    /// future admission throws instead of hanging on a gate nobody will ever
    /// reopen; the pfslocal client is closed by the transport on the same
    /// path, so the refusals here are the ordering guarantee, not the only
    /// defense.
    public func fail(_ error: Error) {
        guard terminal == nil else { return }
        terminal = error
        closed = false
        let waiters = admissionWaiters
        admissionWaiters.removeAll()
        for waiter in waiters {
            waiter.resume(throwing: error)
        }
    }
}

// MARK: - Deferred mount-root actuator

/// A `PfsMacOS26RepairActuator` whose mount-root descriptor arrives after
/// construction. The coherence stack is composed at resolve time, before FSKit
/// has mounted anything; the kernel mount that repairs must be actuated
/// through exists only later. Until a root is installed every apply fails
/// closed — the barrier reports the cursor blocked rather than acknowledging a
/// repair that never touched the kernel.
public final class PfsMacOS26DeferredMountActuator: PfsMacOS26RepairActuator, @unchecked Sendable {
    private let lock = NSLock()
    private var inner: PfsMacOS26POSIXActuator?
    private var locator: (@Sendable () throws -> Int32)?

    public init(locator: (@Sendable () throws -> Int32)? = nil) {
        self.locator = locator
    }

    public var isInstalled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return inner != nil
    }

    /// Installs the attested mount-root descriptor. The descriptor is
    /// duplicated by the POSIX actuator; the caller keeps ownership of `fd`.
    public func installRoot(fileDescriptor: Int32) throws {
        let actuator = try PfsMacOS26POSIXActuator(rootFileDescriptor: fileDescriptor)
        lock.lock()
        if inner == nil {
            inner = actuator
        }
        lock.unlock()
    }

    public func apply(_ plan: PfsMacOS26RepairPlan) async throws {
        let actuator = try resolveActuator()
        try await actuator.apply(plan)
    }

    private func resolveActuator() throws -> PfsMacOS26POSIXActuator {
        lock.lock()
        let installed = inner
        let locate = installed == nil ? locator : nil
        lock.unlock()
        if let installed {
            return installed
        }
        if let locate {
            let fd = try locate()
            defer { close(fd) }
            try installRoot(fileDescriptor: fd)
            lock.lock()
            let resolved = inner
            lock.unlock()
            if let resolved {
                return resolved
            }
        }
        throw PfsMacOSCoherenceError.posix(operation: "locate repair mount root", errno: ENXIO)
    }
}

/// Locates this exact FSKit kernel mount in the mount table so the actuator
/// can address it. Matching is deliberately narrow: the filesystem type name
/// must be this module's, the mount source must name this attach, and the
/// opened root must project the root file identifier this adapter mints.
/// Anything else is refused rather than guessed at — actuating repairs against
/// the wrong mount is namespace surgery on someone else's files.
public enum PfsMacOSMountRootLocator {
    /// `statfs` names both the Darwin struct and the syscall; the alias keeps
    /// the struct usable in expression position.
    private typealias MountTableEntry = statfs

    public static func openMountRoot(
        fileSystemTypeName: String,
        attachRef: String,
        expectedRootFileID: UInt64
    ) throws -> Int32 {
        let count = getfsstat(nil, 0, MNT_NOWAIT)
        guard count > 0 else {
            throw PfsMacOSCoherenceError.posix(operation: "count mounted filesystems", errno: errno)
        }
        var entries = [MountTableEntry](repeating: MountTableEntry(), count: Int(count))
        let size = Int32(MemoryLayout<MountTableEntry>.stride * entries.count)
        let filled = entries.withUnsafeMutableBufferPointer { buffer in
            getfsstat(buffer.baseAddress, size, MNT_NOWAIT)
        }
        guard filled > 0 else {
            throw PfsMacOSCoherenceError.posix(operation: "read mount table", errno: errno)
        }

        for index in 0..<Int(min(filled, count)) {
            var entry = entries[index]
            let typeName = withUnsafeBytes(of: &entry.f_fstypename) { raw in
                String(decoding: raw.prefix(while: { $0 != 0 }), as: UTF8.self)
            }
            guard typeName == fileSystemTypeName else { continue }
            let source = withUnsafeBytes(of: &entry.f_mntfromname) { raw in
                String(decoding: raw.prefix(while: { $0 != 0 }), as: UTF8.self)
            }
            guard source.contains(attachRef) else { continue }
            let mountPath = withUnsafeBytes(of: &entry.f_mntonname) { raw in
                String(decoding: raw.prefix(while: { $0 != 0 }), as: UTF8.self)
            }
            let fd = mountPath.withCString { path in
                open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
            }
            guard fd >= 0 else {
                throw PfsMacOSCoherenceError.posix(operation: "open repair mount root", errno: errno)
            }
            var status = stat()
            guard fstat(fd, &status) == 0, status.st_ino == expectedRootFileID else {
                close(fd)
                throw PfsMacOSCoherenceError.posix(operation: "attest repair mount root", errno: ENXIO)
            }
            return fd
        }
        throw PfsMacOSCoherenceError.posix(operation: "locate repair mount root", errno: ENXIO)
    }
}

// MARK: - Composed strict-v3 volume coherence

/// Everything the macOS 26 compatibility cache policy installs into one strict
/// FSKit volume: the namespace and live-object indexes the planner derives
/// repairs from, the callback publication barrier, the repair gate, and the
/// running coherence session. Constructed only when the resolve contract's
/// cache policy names `macos26-synchronous-vfs-repair-v1` — the policy is a
/// declared selection, never an inference.
public final class PfsMacOSV3VolumeCoherence: @unchecked Sendable {
    /// Default hard bound for exact records. Bindings past the bound fail the
    /// publishing callback closed; records are never dropped by silent LRU,
    /// because a dropped record is a kernel cache entry this mount can no
    /// longer prove absent.
    public static let defaultNamespaceCapacity = 1 << 22
    public static let defaultLiveObjectCapacity = 1 << 20

    public let contract: PfsMacOSV3LocalContract?
    public let namespaceIndex: PfsMacOSNamespaceIndex
    public let liveObjects: PfsMacOSLiveObjectIndex
    public let barrier: PfsMacOSFSKitPublicationBarrier
    public let repairGate: any PfsMacOS26RepairGate
    public let namespaceCapacity: Int
    public let liveObjectCapacity: Int
    let mountActuator: PfsMacOS26DeferredMountActuator?

    private let lock = NSLock()
    private var runnerTask: Task<Void, Never>?
    private var actuatorInstallInFlight = false

    public init(
        contract: PfsMacOSV3LocalContract?,
        namespaceIndex: PfsMacOSNamespaceIndex,
        liveObjects: PfsMacOSLiveObjectIndex,
        barrier: PfsMacOSFSKitPublicationBarrier,
        repairGate: any PfsMacOS26RepairGate,
        mountActuator: PfsMacOS26DeferredMountActuator? = nil,
        namespaceCapacity: Int = PfsMacOSV3VolumeCoherence.defaultNamespaceCapacity,
        liveObjectCapacity: Int = PfsMacOSV3VolumeCoherence.defaultLiveObjectCapacity
    ) {
        self.contract = contract
        self.namespaceIndex = namespaceIndex
        self.liveObjects = liveObjects
        self.barrier = barrier
        self.repairGate = repairGate
        self.mountActuator = mountActuator
        self.namespaceCapacity = namespaceCapacity
        self.liveObjectCapacity = liveObjectCapacity
    }

    func adoptRunnerTask(_ task: Task<Void, Never>) {
        lock.lock()
        runnerTask = task
        lock.unlock()
    }

    /// Attempts to bind the deferred actuator to the live kernel mount.
    /// Triggered from ordinary serving rather than the mount callback because
    /// the kernel's mount-table entry exists only after mounting completes; a
    /// failed attempt retries at the next served callback until the mount
    /// appears. Failure stays loud at repair time, not here: an uninstalled
    /// actuator fails every repair closed.
    func scheduleActuatorInstall(_ locate: @escaping @Sendable () throws -> Int32) {
        lock.lock()
        guard !actuatorInstallInFlight, let mountActuator, !mountActuator.isInstalled else {
            lock.unlock()
            return
        }
        actuatorInstallInFlight = true
        lock.unlock()
        Task.detached { [weak self] in
            defer { self?.finishActuatorInstallAttempt() }
            guard let fd = try? locate() else { return }
            defer { close(fd) }
            try? mountActuator.installRoot(fileDescriptor: fd)
        }
    }

    private nonisolated func finishActuatorInstallAttempt() {
        lock.lock()
        actuatorInstallInFlight = false
        lock.unlock()
    }

    public func shutdown() {
        lock.lock()
        let task = runnerTask
        runnerTask = nil
        lock.unlock()
        task?.cancel()
    }

    /// Composes the full strict-v3 stack for a `VolumeCore` whose resolve
    /// carried the macOS 26 compatibility policy: indexes, transport bound to
    /// the exact resolved UDS connection (one connection, no reconnect,
    /// liveness pulse at one third of the repair budget — all enforced by the
    /// transport itself), arm registry, publication barrier, backend, and the
    /// running coherence session. Throws — with the client already closed by
    /// the caller's fail-closed discipline — when any strict term is invalid.
    static func compose(
        client: PfsLocalClient,
        resolved: PfsResolveReply,
        contract: PfsMacOSV3LocalContract
    ) async throws -> PfsMacOSV3VolumeCoherence {
        let rootIdentity = try PfsMacOSStableIdentity(resolved.root.stableIdentity)
        let namespaceIndex = PfsMacOSNamespaceIndex(rootIdentity: rootIdentity)
        let liveObjects = PfsMacOSLiveObjectIndex()
        let planner = PfsMacOSRepairPlanner(index: namespaceIndex, liveObjects: liveObjects)
        let transport = try await PfsLocalMacOSV3CoherenceTransport.connect(
            client: client,
            resolved: resolved,
            planner: planner
        )

        // The repair secret authenticates only this mount incarnation's own
        // operands to itself; it is minted here and never leaves the process.
        var generator = SystemRandomNumberGenerator()
        var secret = Data(capacity: 32)
        for _ in 0..<4 {
            var word = UInt64.random(in: UInt64.min...UInt64.max, using: &generator)
            withUnsafeBytes(of: &word) { secret.append(contentsOf: $0) }
        }
        let authenticator = try PfsMacOS26RepairAuthenticator(
            mountSessionID: UUID(),
            secret: secret
        )
        let registry = PfsMacOS26RepairArmRegistry(authenticator: authenticator)
        let barrier = try PfsMacOSFSKitPublicationBarrier(
            localAuthoritySessionID: contract.sessionID
        )
        let actuator = PfsMacOS26DeferredMountActuator()
        let backend = try PfsMacOS26CoherenceBackend(
            localAuthoritySessionID: contract.sessionID,
            authenticator: authenticator,
            armer: registry,
            actuator: actuator,
            publicationBarrier: barrier
        )
        let runner = try await transport.makeRunner(backend: backend)

        let coherence = PfsMacOSV3VolumeCoherence(
            contract: contract,
            namespaceIndex: namespaceIndex,
            liveObjects: liveObjects,
            barrier: barrier,
            repairGate: registry,
            mountActuator: actuator
        )
        coherence.adoptRunnerTask(Task {
            do {
                try await runner.run()
            } catch {
                // The runner has already reported the blocked cursor and
                // closed the pfslocal client. Failing the barrier is what
                // stops admission-gated callbacks from hanging on a gate
                // nobody will reopen.
                await barrier.fail(error)
            }
            withExtendedLifetime(transport) {}
        })
        return coherence
    }
}
