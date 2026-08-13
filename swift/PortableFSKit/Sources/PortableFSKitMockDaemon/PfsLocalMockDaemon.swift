import Foundation
import PortableFSKit
@preconcurrency import Dispatch
@preconcurrency import Darwin

/// Owns every Swift task created by the mock server. Socket reads and writes
/// belong to dedicated Dispatch queues, while protocol handling remains async
/// because the in-memory filesystem is an actor and several tests inject
/// cancellable delays. Keeping those tasks in an explicit registry gives
/// `stop()` one exact cancellation-and-join boundary instead of leaving
/// detached work behind for the process to reap.
private final class PfsMockRequestRegistry: @unchecked Sendable {
    private let condition = NSCondition()
    private let group = DispatchGroup()
    private var accepting = true
    private var registrationsInFlight = 0
    private var tasks: [UUID: Task<Void, Never>] = [:]
    private var completedBeforeRegistration: Set<UUID> = []

    func spawn(_ operation: @escaping @Sendable () async -> Void) {
        let id = UUID()

        condition.lock()
        guard accepting else {
            condition.unlock()
            return
        }
        registrationsInFlight += 1
        group.enter()
        condition.unlock()

        let task = Task.detached(priority: .userInitiated) { [self] in
            defer { finish(id) }
            await operation()
        }

        condition.lock()
        if completedBeforeRegistration.remove(id) == nil {
            tasks[id] = task
        }
        registrationsInFlight -= 1
        let shouldCancel = !accepting
        condition.broadcast()
        condition.unlock()

        if shouldCancel {
            task.cancel()
        }
    }

    func cancelAndWait() {
        condition.lock()
        accepting = false
        while registrationsInFlight != 0 {
            condition.wait()
        }
        let active = Array(tasks.values)
        condition.unlock()

        for task in active {
            task.cancel()
        }
        group.wait()
    }

    private func finish(_ id: UUID) {
        condition.lock()
        if tasks.removeValue(forKey: id) == nil {
            completedBeforeRegistration.insert(id)
        }
        condition.unlock()
        group.leave()
    }
}

public final class PfsLocalMockDaemon: @unchecked Sendable {
    public struct Stats: Sendable, Equatable {
        public var openRequests: Int
        public var closeRequests: Int
        public var reclaimRequests: Int
        public var activeHandles: Int
        public var readRequests: Int
        public var writeRequests: Int
        /// One entry per ordered mutation frame, in receive order. This is the
        /// wire-level source-phase scheduling proof supplied by the frontend,
        /// not a value the mock re-derives from request shape.
        public var orderedMutationSourcePhaseQueueable: [Bool]
        public var enumerateRequests: Int
        public var getAttrRequests: Int
        public var setAttrRequests: Int
        /// Lookups that actually crossed the socket. The reserved repair
        /// namespace must be refused locally, and only the daemon can testify
        /// that no probe of it ever became a request.
        public var lookupRequests: Int
        /// Namespace mutations that actually crossed the socket. The macOS 26
        /// repair contract's central claim is that a consumed repair callback
        /// produces no request at all, and only the daemon can testify to that.
        public var createRequests: Int
        public var removeRequests: Int
        public var renameRequests: Int
        public var xattrGetRequests: Int
        public var xattrSetRequests: Int
        public var xattrListRequests: Int
        public var xattrRemoveRequests: Int
        /// Setattr requests that arrived carrying `set_flags`. The frontend
        /// gate is invisible from the outside — a refused change and a
        /// forwarded-then-refused change both surface as ENOTSUP — so proving
        /// forwarding needs the daemon to say it saw the frame.
        public var flagChangeRequests: Int
        public var maxReadLength: UInt32
        public var maxWriteLength: Int
        public var publicationAcks: Int
        public var resourceAccepts: Int
        public var resourceAbandons: Int
        /// Exact item-prefix verdict on each resource disposition, in receive
        /// order. Enumeration tests use occurrences rather than item IDs so
        /// duplicate hard-link aliases remain distinguishable.
        public var resourceAcceptedItemCounts: [UInt32]
        public var visibilityAcks: Int
        public var v3LivenessRequests: Int
        public var syncVolumeRequests: Int
    }

    public struct Configuration: Sendable {
        public var attachRef: String
        public var volumeID: String
        public var volumeName: String
        public var branch: String
        public var lookupDelaysNanoseconds: [String: UInt64]
        public var lookupNoReplyNames: Set<String>
        public var strictItemNamespace: Bool
        public var protocolMinor: UInt32?
        /// Optional strict-v3 coherence terms returned by resolve. Tests leave
        /// this nil unless they are exercising strict-v3 minor negotiation.
        public var v3Coherence: PfsV3CoherenceContract?
        /// Test-only delay or identity corruption for the on-demand authority
        /// liveness reply. A normal reply echoes the request exactly.
        public var v3LivenessDelayNanoseconds: UInt64
        public var v3LivenessEpochOverride: Data?
        public var v3LivenessSessionOverride: Data?
        public var v3LivenessOverrideAfterRequestCount: Int
        /// Mirrors the real daemon's per-attach AUTHORITY knowledge: it rides
        /// the resolve reply as `Capabilities.flagsSupported`, and a setattr
        /// carrying `setFlags` against an AUTHORITY-BACKED node without it is
        /// answered ENOTSUP rather than silently dropped. It says nothing
        /// about grafted nodes — see `graftBackedNames`.
        public var flagsSupported: Bool
        /// Mirrors `Capabilities.flagsUnderstood`: this daemon parses
        /// `set_flags`/`flags` at all. A real daemon sets it unconditionally;
        /// it is configurable here only so a test can model one that does not.
        /// This — not `flagsSupported` — is what the frontend gates on.
        public var flagsUnderstood: Bool
        /// Mirrors `Capabilities.xattrSetSupported`. The mock is writable by
        /// default so existing round-trip fixtures keep modelling a backend
        /// that implements the full xattr family; production v3 advertises
        /// false and is exercised by opting out explicitly.
        public var xattrSetSupported: Bool
        /// Names whose backing is machine-local (a graft over the volume
        /// namespace). chflags(2) on such a node is applied to a real host
        /// inode, so it succeeds regardless of `flagsSupported`: no authority
        /// feature is involved. This is what makes a volume's flag support
        /// PER-OBJECT, and why a volume-wide frontend gate is wrong.
        public var graftBackedNames: Set<String>
        /// Models a daemon built BEFORE `set_flags`/`flags` existed. Both are
        /// appended fields at the same protocol minor, so such a daemon
        /// proto3-discards them: it never advertises `flagsSupported`, it
        /// cannot refuse what it does not parse, and it applies the rest of
        /// the setattr and reports success. That silent no-op is the failure
        /// the frontend-side gate exists to prevent.
        public var predatesFlagFields: Bool
        /// Optional per-operation failures for exercising the FSKit xattr
        /// boundary. `nil` preserves the mock's writable in-memory xattrs;
        /// a value makes the corresponding request fail after it is counted
        /// but before it observes or mutates a node.
        public var xattrGetErrno: Int32?
        public var xattrSetErrno: Int32?
        public var xattrListErrno: Int32?
        public var xattrRemoveErrno: Int32?
        /// Test-only protocol corruption: stamps the request-only scheduling
        /// bit on daemon replies so the Swift client's directional validator
        /// can prove it closes the connection before delivering the frame.
        public var sourcePhaseQueueableOnReplies: Bool

        public init(
            attachRef: String = "mock",
            volumeID: String = "mock-volume",
            volumeName: String = "PortableFS Mock",
            branch: String = "main",
            lookupDelaysNanoseconds: [String: UInt64] = [:],
            lookupNoReplyNames: Set<String> = [],
            strictItemNamespace: Bool = false,
            protocolMinor: UInt32? = nil,
            v3Coherence: PfsV3CoherenceContract? = nil,
            v3LivenessDelayNanoseconds: UInt64 = 0,
            v3LivenessEpochOverride: Data? = nil,
            v3LivenessSessionOverride: Data? = nil,
            v3LivenessOverrideAfterRequestCount: Int = 0,
            flagsSupported: Bool = true,
            flagsUnderstood: Bool = true,
            xattrSetSupported: Bool = true,
            graftBackedNames: Set<String> = [],
            predatesFlagFields: Bool = false,
            xattrGetErrno: Int32? = nil,
            xattrSetErrno: Int32? = nil,
            xattrListErrno: Int32? = nil,
            xattrRemoveErrno: Int32? = nil,
            sourcePhaseQueueableOnReplies: Bool = false
        ) {
            self.attachRef = attachRef
            self.volumeID = volumeID
            self.volumeName = volumeName
            self.branch = branch
            self.lookupDelaysNanoseconds = lookupDelaysNanoseconds
            self.lookupNoReplyNames = lookupNoReplyNames
            self.strictItemNamespace = strictItemNamespace
            self.protocolMinor = protocolMinor
            self.v3Coherence = v3Coherence
            self.v3LivenessDelayNanoseconds = v3LivenessDelayNanoseconds
            self.v3LivenessEpochOverride = v3LivenessEpochOverride
            self.v3LivenessSessionOverride = v3LivenessSessionOverride
            self.v3LivenessOverrideAfterRequestCount = v3LivenessOverrideAfterRequestCount
            self.flagsSupported = flagsSupported
            self.flagsUnderstood = flagsUnderstood
            self.xattrSetSupported = xattrSetSupported
            self.graftBackedNames = graftBackedNames
            self.predatesFlagFields = predatesFlagFields
            self.xattrGetErrno = xattrGetErrno
            self.xattrSetErrno = xattrSetErrno
            self.xattrListErrno = xattrListErrno
            self.xattrRemoveErrno = xattrRemoveErrno
            self.sourcePhaseQueueableOnReplies = sourcePhaseQueueableOnReplies
        }
    }

    public let socketPath: String
    private let fileSystem: MockFileSystem
    private let runtime: PfsMockDaemonRuntime

    public init(configuration: Configuration = Configuration()) throws {
        var template = Array("/tmp/pfs-mock.XXXXXX".utf8CString)
        guard let created = Darwin.mkdtemp(&template) else {
            throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
        }
        let directory = String(cString: created)
        self.socketPath = directory + "/pfs.sock"
        self.fileSystem = MockFileSystem(configuration: configuration)
        let serverFD: Int32
        do {
            let boundFD = try PfsUnixSocket.bindAndListen(path: socketPath)
            guard Darwin.chmod(socketPath, 0o600) == 0 else {
                let failure = POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
                PfsUnixSocket.close(boundFD)
                throw failure
            }
            serverFD = boundFD
        } catch {
            unlink(socketPath)
            rmdir(directory)
            throw error
        }
        self.runtime = PfsMockDaemonRuntime(
            serverFD: serverFD,
            socketPath: socketPath,
            socketDirectory: directory,
            fileSystem: fileSystem
        )
        runtime.start()
    }

    deinit {
        stop()
    }

    public func stop() {
        runtime.stop()
    }

    public func dropConnections() {
        runtime.dropConnections()
    }

    /// Causes the next daemon close request to fail before releasing its
    /// handle. Lifecycle tests use this to verify confirmed-close ownership.
    public func failNextClose() async {
        await fileSystem.failNextClose()
    }

    /// Causes the next close to consume its handle and report a terminal errno,
    /// matching a local descriptor whose close syscall failed after retirement.
    public func retireNextCloseWithError(errno: Int32 = EIO) async {
        await fileSystem.retireNextCloseWithError(errno: errno)
    }

    /// Retires the next close handle, remembers its exact outcome for replay,
    /// then closes that client connection before sending the reply.
    public func loseNextRetiredCloseReply(errno: Int32 = 0) async {
        await fileSystem.loseNextRetiredCloseReply(errno: errno)
    }

    /// Marks the next `count` publication-bearing replies as retracted,
    /// modelling the daemon discovering that a delegation handoff crossed the
    /// operation those replies belong to.
    ///
    /// The retraction rides an ordinary reply rather than arriving as its own
    /// frame, which is the whole ordering argument: the frontend cannot see it
    /// after the values it condemns. A mock that emitted a separate message
    /// would be testing a protocol this one does not have.
    public func retractNextPublications(count: Int = 1) async {
        await fileSystem.retractNextPublications(count: count)
    }

    /// Retracts the next `count` publication-bearing requests AND refuses them
    /// without executing, which is what the real daemon does once an operation
    /// has been crossed: it fails every still-undispatched request of that
    /// operation EINTR rather than running it.
    ///
    /// This is the production shape of a retraction. The bit rides the
    /// refusal's own reply, so the frame that condemns the operation is
    /// usually an ErrorReply rather than a successful one — and a mutation
    /// that was waiting on the handoff never lands, which is what lets the
    /// frontend answer EINTR without lying about what happened.
    public func refuseNextPublicationsAsRetracted(count: Int = 1) async {
        await fileSystem.refuseNextPublicationsAsRetracted(count: count)
    }

    public func delayNextOpen(nanoseconds: UInt64) async {
        await fileSystem.delayNextOpen(nanoseconds: nanoseconds)
    }

    /// Corrupts the next successful CreateReply by omitting its mandatory
    /// handle. The namespace mutation still lands, matching the post-apply
    /// protocol-failure shape the strict frontend must terminally fence.
    public func omitNextCreateHandle() async {
        await fileSystem.omitNextCreateHandle()
    }

    /// Corrupts the next successful LookupReply with an identifier from the
    /// frontend-owned repair partition so VolumeCore's mapping rejection and
    /// item-abandonment path can be exercised directly.
    public func corruptNextLookupItemIdentifier() async {
        await fileSystem.corruptNextLookupItemIdentifier()
    }

    /// Corrupts the next successful OpenReply by omitting its mandatory handle.
    public func omitNextOpenHandle() async {
        await fileSystem.omitNextOpenHandle()
    }

    public func delayNextClose(nanoseconds: UInt64) async {
        await fileSystem.delayNextClose(nanoseconds: nanoseconds)
    }

    public func delayNextRead(nanoseconds: UInt64) async {
        await fileSystem.delayNextRead(nanoseconds: nanoseconds)
    }

    public func delayNextWrite(nanoseconds: UInt64) async {
        await fileSystem.delayNextWrite(nanoseconds: nanoseconds)
    }

    /// Refuses the Nth-next write request with `errno`, AFTER any earlier
    /// request in the same framework callback has already committed. That is
    /// the shape one FSKit write callback takes when it spans several daemon
    /// requests and a later one hits a fence, a lane change or an EIO: the
    /// earlier chunks are on media and the callback still has to say something
    /// truthful about them.
    public func failWrite(atIndex index: Int, errno code: Int32 = EIO) async {
        await fileSystem.failWrite(atIndex: index, errno: code)
    }

    /// Answers the Nth-next write request with a SHORT count — `written` bytes
    /// of the request's payload — which is a healthy POSIX outcome the daemon
    /// produces whenever a credit grant covers only a prefix.
    public func shortenNextWrite(to written: Int) async {
        await fileSystem.shortenNextWrite(to: written)
    }

    public func emitInvalidation(
        item: PfsItem,
        contentChanged: Bool = true,
        attrsChanged: Bool = true,
        namespaceChanged: Bool = false,
        contentVersion: UInt64 = 1
    ) {
        var invalidation = PfsInvalidation()
        invalidation.item = item
        invalidation.contentChanged = contentChanged
        invalidation.attrsChanged = attrsChanged
        invalidation.namespaceChanged = namespaceChanged
        invalidation.contentVersion = contentVersion

        var event = PfsEvent()
        event.kind = .invalidation(invalidation)

        var envelope = PfsEnvelope()
        envelope.requestID = 0
        envelope.body = .event(event)

        for session in runtime.sessionSnapshot() where session.isSubscribed {
            session.send(envelope)
        }
    }

    /// Publishes an authority-shaped minor-8 visibility event to every
    /// subscribed client, preserving the same request-id-zero event lane as
    /// the production daemon.
    public func emitVisibility(_ visibility: PfsV3VisibilityEvent) {
        var event = PfsEvent()
        event.kind = .visibility(visibility)

        var envelope = PfsEnvelope()
        envelope.requestID = 0
        envelope.body = .event(event)

        for session in runtime.sessionSnapshot() where session.isSubscribed {
            session.send(envelope)
        }
    }

    public func emitAttachState(_ state: PfsAttachState.State, detail: String = "") {
        var attachState = PfsAttachState()
        attachState.state = state
        attachState.detail = detail

        var event = PfsEvent()
        event.kind = .attachState(attachState)

        var envelope = PfsEnvelope()
        envelope.requestID = 0
        envelope.body = .event(event)

        for session in runtime.sessionSnapshot() where session.isSubscribed {
            session.send(envelope)
        }
    }

    public func rootIdentity() async -> PfsItemIdentity {
        await fileSystem.rootIdentity()
    }

    public func stats() async -> Stats {
        await fileSystem.stats()
    }

    public func visibilityAcknowledgements() async -> [PfsVisibilityAckRequest] {
        await fileSystem.visibilityAcknowledgements()
    }

    public func v3LivenessRequests() async -> [PfsV3LivenessRequest] {
        await fileSystem.v3LivenessRequestsSnapshot()
    }

    public func resetStats() async {
        await fileSystem.resetStats()
    }

    /// Test-only observation of responses that have left protocol handling but
    /// have not yet completed their dedicated blocking socket write. It lets a
    /// lifecycle regression prove shutdown while real backpressure exists,
    /// rather than assuming a particular kernel socket-buffer size.
    func testingPendingResponseCount() -> Int {
        runtime.sessionSnapshot().reduce(0) { $0 + $1.pendingResponseCount }
    }

}

/// Owns every blocking worker independently of the public daemon object.
///
/// A dispatch closure that calls a long-running instance method retains that
/// instance for the entire call, even when the closure captured it weakly.
/// Keeping the worker graph in this runtime lets `PfsLocalMockDaemon.deinit`
/// synchronously stop and join the graph instead of being retained by it.
private final class PfsMockDaemonRuntime: @unchecked Sendable {
    private let serverFD: Int32
    private let socketPath: String
    private let socketDirectory: String
    private let fileSystem: MockFileSystem
    private let sessionLock = NSLock()
    private var sessions: [Int32: MockSession] = [:]
    private let acceptQueue = DispatchQueue(label: "dev.portablefs.mock.accept", qos: .userInitiated)
    private let clientQueue = DispatchQueue(
        label: "dev.portablefs.mock.client",
        qos: .userInitiated,
        attributes: .concurrent
    )
    private let acceptGroup = DispatchGroup()
    private let clientGroup = DispatchGroup()
    private let requests = PfsMockRequestRegistry()
    private let lifecycleLock = NSLock()
    private var started = false
    private var stopped = false

    init(
        serverFD: Int32,
        socketPath: String,
        socketDirectory: String,
        fileSystem: MockFileSystem
    ) {
        self.serverFD = serverFD
        self.socketPath = socketPath
        self.socketDirectory = socketDirectory
        self.fileSystem = fileSystem
    }

    func start() {
        lifecycleLock.lock()
        precondition(!started && !stopped)
        started = true
        acceptGroup.enter()
        lifecycleLock.unlock()
        acceptQueue.async { [runtime = self] in
            defer { runtime.acceptGroup.leave() }
            runtime.acceptLoop()
        }
    }

    func stop() {
        lifecycleLock.lock()
        guard !stopped else {
            lifecycleLock.unlock()
            return
        }
        stopped = true
        lifecycleLock.unlock()

        if let wakeFD = try? PfsUnixSocket.connect(path: socketPath) {
            PfsUnixSocket.close(wakeFD)
        }
        // The wake connection makes accept return. This is an ownership join,
        // not a best-effort timeout: cleanup must not race an accept that can
        // still publish a new session.
        acceptGroup.wait()
        for session in sessionSnapshot() {
            session.close()
        }
        // Closing each peer interrupts its blocking reader. Once all readers
        // have left, no new protocol task can enter the request registry.
        clientGroup.wait()
        requests.cancelAndWait()
        Darwin.shutdown(serverFD, SHUT_RDWR)
        PfsUnixSocket.close(serverFD)
        unlink(socketPath)
        rmdir(socketDirectory)
    }

    func dropConnections() {
        for session in sessionSnapshot() {
            session.close()
        }
    }

    private func acceptLoop() {
        while !isStopped {
            do {
                let clientFD = try PfsUnixSocket.accept(serverFD)
                if isStopped {
                    PfsUnixSocket.close(clientFD)
                    return
                }
                let session = MockSession(fd: clientFD)
                addSession(session)
                clientGroup.enter()
                let group = clientGroup
                clientQueue.async { [weak self, session, group] in
                    defer { group.leave() }
                    self?.clientLoop(session: session)
                }
            } catch {
                if !isStopped {
                    continue
                }
                return
            }
        }
    }

    private func clientLoop(session: MockSession) {
        defer {
            removeSession(fd: session.fd)
            session.close()
        }
        var reader = PfsMockFrameReader(fd: session.fd)
        while !isStopped {
            do {
                let envelope = try reader.readFrame()
                requests.spawn { [fileSystem, session] in
                    let reply = await fileSystem.handle(envelope, session: session)
                    session.send(reply)
                }
            } catch {
                return
            }
        }
    }

    private var isStopped: Bool {
        lifecycleLock.lock()
        let value = stopped
        lifecycleLock.unlock()
        return value
    }

    private func addSession(_ session: MockSession) {
        sessionLock.lock()
        sessions[session.fd] = session
        sessionLock.unlock()
    }

    private func removeSession(fd: Int32) {
        sessionLock.lock()
        sessions.removeValue(forKey: fd)
        sessionLock.unlock()
    }

    func sessionSnapshot() -> [MockSession] {
        sessionLock.lock()
        let snapshot = Array(sessions.values)
        sessionLock.unlock()
        return snapshot
    }
}

private final class MockSession: @unchecked Sendable {
    let fd: Int32
    /// Blocking `send(2)` must never run on Swift's cooperative executor. A
    /// full peer receive buffer previously let one response hold `ioLock`
    /// while more detached request tasks blocked behind it, exhausting the
    /// executor that the client needed to consume those responses. One owned
    /// serial Dispatch queue is the socket's write executor and preserves
    /// complete-frame ordering without consuming Swift task threads.
    private let writeQueue = DispatchQueue(
        label: "dev.portablefs.mock.session.write.\(UUID().uuidString)",
        qos: .userInitiated
    )
    private let closeLock = NSLock()
    private let closeGroup = DispatchGroup()
    private let pendingResponseLock = NSLock()
    private let stateLock = NSLock()
    private var subscribed = false
    private var closeStarted = false
    private var fdClosed = false
    private var pendingResponses = 0

    var isSubscribed: Bool {
        stateLock.lock()
        let value = subscribed
        stateLock.unlock()
        return value
    }

    init(fd: Int32) {
        self.fd = fd
        closeGroup.enter()
        PfsMockFrameIO.disableSigPipe(fd: fd)
    }

    func setSubscribed() {
        stateLock.lock()
        subscribed = true
        stateLock.unlock()
    }

    /// Mirrors the real daemon's obligation ledger: an operation exists on
    /// this connection once its ID appears on a request, and it may be
    /// acknowledged exactly once. The real frontend reader closes the whole
    /// connection on a violation, so the mock must too — a lenient mock once
    /// hid an ack that overtook its own request on the priority lane.
    func noteOperationID(_ id: UInt64) {
        guard id != 0 else { return }
        stateLock.lock()
        seenOperationIDs.insert(id)
        stateLock.unlock()
    }

    func acknowledgeOperation(_ id: UInt64) -> Bool {
        stateLock.lock()
        defer { stateLock.unlock() }
        guard id != 0,
              seenOperationIDs.contains(id),
              !acknowledgedOperationIDs.contains(id) else {
            return false
        }
        acknowledgedOperationIDs.insert(id)
        return true
    }

    private var seenOperationIDs: Set<UInt64> = []
    private var acknowledgedOperationIDs: Set<UInt64> = []

    func send(_ envelope: PfsEnvelope) {
        let frame: Data
        do {
            frame = try PfsMockFrameIO.encode(envelope: envelope)
        } catch {
            close()
            return
        }

        // Serialize admission with the close transition. Every admitted block
        // is therefore ahead of close()'s writeQueue.sync barrier, and no
        // response closure can appear after stop has joined the session.
        closeLock.lock()
        guard !closeStarted else {
            closeLock.unlock()
            return
        }
        pendingResponseLock.lock()
        pendingResponses += 1
        pendingResponseLock.unlock()
        writeQueue.async { [self] in
            defer {
                pendingResponseLock.lock()
                pendingResponses -= 1
                pendingResponseLock.unlock()
            }
            guard !isClosing else {
                return
            }
            do {
                try PfsMockFrameIO.writeFrame(fd: fd, frame: frame)
            } catch {
                closeFromWriteQueue()
            }
        }
        closeLock.unlock()
    }

    var pendingResponseCount: Int {
        pendingResponseLock.lock()
        let value = pendingResponses
        pendingResponseLock.unlock()
        return value
    }

    func close() {
        if beginClose() {
            // shutdown(2) is deliberately outside the serial write queue: it
            // is what interrupts a write already blocked in send(2). Exactly
            // one caller can reach it, so the descriptor cannot be shut down
            // after another caller has closed and the fd number was reused.
            Darwin.shutdown(fd, SHUT_RDWR)
            writeQueue.sync { [self] in
                finishCloseOnWriteQueue()
            }
        } else {
            closeGroup.wait()
        }
    }

    private var isClosing: Bool {
        closeLock.lock()
        let value = closeStarted
        closeLock.unlock()
        return value
    }

    private func beginClose() -> Bool {
        closeLock.lock()
        defer { closeLock.unlock() }
        guard !closeStarted else {
            return false
        }
        closeStarted = true
        return true
    }

    /// The error originates on `writeQueue`, so this variant must not call
    /// `writeQueue.sync`. It shares the same one-winner close transition as an
    /// external stop and publishes completion through `closeGroup`.
    private func closeFromWriteQueue() {
        guard beginClose() else {
            return
        }
        Darwin.shutdown(fd, SHUT_RDWR)
        finishCloseOnWriteQueue()
    }

    private func finishCloseOnWriteQueue() {
        closeLock.lock()
        guard !fdClosed else {
            closeLock.unlock()
            return
        }
        fdClosed = true
        closeLock.unlock()

        PfsUnixSocket.close(fd)
        closeGroup.leave()
    }
}

private struct PfsMockFrameReader {
    private let fd: Int32
    private var decoder: PfsFrameDecoder
    private var bufferedFrames: [PfsEnvelope] = []

    init(fd: Int32, maxFrameLength: Int = PfsFrameCodec.defaultMaxFrameLength) {
        self.fd = fd
        self.decoder = PfsFrameDecoder(maxFrameLength: maxFrameLength)
    }

    mutating func readFrame() throws -> PfsEnvelope {
        if !bufferedFrames.isEmpty {
            return bufferedFrames.removeFirst()
        }

        var buffer = [UInt8](repeating: 0, count: 4096)
        while true {
            let count = buffer.withUnsafeMutableBytes { rawBuffer in
                Darwin.recv(fd, rawBuffer.baseAddress, rawBuffer.count, 0)
            }
            if count > 0 {
                let frames = try decoder.append(Data(buffer.prefix(count)))
                if let frame = frames.first {
                    bufferedFrames.append(contentsOf: frames.dropFirst())
                    return frame
                }
                continue
            }
            if count == 0 {
                if decoder.bufferedByteCount == 0 {
                    throw PfsLocalClientError.connectionClosed
                }
                throw PfsLocalClientError.invalidFrame("EOF before completing frame")
            }
            let error = Darwin.errno
            if error == EINTR {
                continue
            }
            throw PfsLocalClientError.system(errno: error, operation: "recv")
        }
    }
}

private enum PfsMockFrameIO {
    static func disableSigPipe(fd: Int32) {
        var value: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &value, socklen_t(MemoryLayout<Int32>.size))
    }

    static func encode(
        envelope: PfsEnvelope,
        maxFrameLength: Int = PfsFrameCodec.defaultMaxFrameLength
    ) throws -> Data {
        try PfsFrameCodec(maxFrameLength: maxFrameLength).encode(envelope)
    }

    static func writeFrame(fd: Int32, frame: Data) throws {
        try frame.withUnsafeBytes { rawBuffer in
            guard let base = rawBuffer.baseAddress else {
                return
            }
            var offset = 0
            while offset < frame.count {
                let sent = Darwin.send(fd, base.advanced(by: offset), frame.count - offset, 0)
                if sent > 0 {
                    offset += sent
                    continue
                }
                if sent == 0 {
                    throw PfsLocalClientError.connectionClosed
                }
                let error = Darwin.errno
                if error == EINTR {
                    continue
                }
                throw PfsLocalClientError.system(errno: error, operation: "send")
            }
        }
    }
}

private actor MockFileSystem {
    // Enumeration cookie layout mirrors portablefsd exactly: [marker:1][cursor:61][tag:2],
    // where the cursor is a pure function of the entry name. Resumption is
    // "first entry whose cursor is strictly greater than the cookie", so a
    // cookie stays resolvable no matter what the directory does between pages
    // and no matter which pages the daemon already served. The mock exists to
    // hold the adapter to that contract, so it must not be more forgiving.
    private static let daemonCookieMarker: UInt64 = 1 << 63
    private static let cookieTagMask: UInt64 = 0x3
    private static let cookieTagCursor: UInt64 = 0x1
    private static let cursorMax: UInt64 = (1 << 61) - 1
    private static let cursorSpace: UInt64 = cursorMax - (1 << 20)

    private final class Node {
        let id: UInt64
        let generation: UInt64
        var kind: PfsItemKind
        var mode: UInt32
        var nlink: UInt32
        var uid: UInt32
        var gid: UInt32
        var data: Data
        var symlinkTarget: Data
        var children: [Data: UInt64]
        var xattrs: [String: Data]
        var parent: UInt64?
        var mtimeMs: Int64
        var ctimeMs: Int64
        var atimeMs: Int64
        var birthtimeMs: Int64
        var contentVersion: UInt64
        var flags: UInt32

        init(id: UInt64, kind: PfsItemKind, mode: UInt32, parent: UInt64?) {
            self.id = id
            self.generation = 1
            self.kind = kind
            self.mode = mode
            self.nlink = kind == .directory ? 2 : 1
            self.uid = UInt32(getuid())
            self.gid = UInt32(getgid())
            self.data = Data()
            self.symlinkTarget = Data()
            self.children = [:]
            self.xattrs = [:]
            self.parent = parent
            let now = Int64(Date().timeIntervalSince1970 * 1000)
            self.mtimeMs = now
            self.ctimeMs = now
            self.atimeMs = now
            self.birthtimeMs = now
            self.contentVersion = 1
            self.flags = 0
        }

        var item: PfsItem {
            var item = PfsItem()
            item.itemID = id
            item.itemGeneration = generation
            item.stableIdentity = Node.stableIdentity(for: id)
            return item
        }

        /// A strict daemon supplies a 16-byte stable XFS identity for every
        /// item; the v3 namespace/live-object indexes are keyed by it. The
        /// mock derives one deterministically from the node ID so tests can
        /// predict it.
        static func stableIdentity(for id: UInt64) -> Data {
            var identity = Data("pfsmock!".utf8)
            var bigEndian = id.bigEndian
            withUnsafeBytes(of: &bigEndian) { identity.append(contentsOf: $0) }
            return identity
        }
    }

    private struct MockPOSIXError: Error {
        var errno: Int32
        var message: String
    }

    private let configuration: PfsLocalMockDaemon.Configuration
    private var nodes: [UInt64: Node] = [:]
    private var handles: [UInt64: UInt64] = [:]
    private var nextNodeID: UInt64 = 2
    private var nextHandle: UInt64 = 1
    private var openRequests = 0
    private var closeRequests = 0
    private var reclaimRequests = 0
    private var readRequests = 0
    private var writeRequests = 0
    private var orderedMutationSourcePhaseQueueable: [Bool] = []
    private var enumerateRequests = 0
    private var getAttrRequests = 0
    private var setAttrRequests = 0
    private var lookupRequests = 0
    private var createRequests = 0
    private var removeRequests = 0
    private var renameRequests = 0
    private var xattrGetRequests = 0
    private var xattrSetRequests = 0
    private var xattrListRequests = 0
    private var xattrRemoveRequests = 0
    private var flagChangeRequests = 0
    private var maxReadLength: UInt32 = 0
    private var maxWriteLength = 0
    private var publicationAcks = 0
    private var visibilityAcks: [PfsVisibilityAckRequest] = []
    private var v3LivenessRequests: [PfsV3LivenessRequest] = []
    private var syncVolumeRequests = 0
    private var pendingRetractions = 0
    private var pendingRetractionRefusals = 0
    private var pendingCloseFailures = 0
    private var pendingRetiredCloseErrnos: [Int32] = []
    private var pendingLostRetiredCloseErrnos: [Int32] = []
    private var retiredCloseReplies: [UInt64: PfsCloseReply] = [:]
    private var pendingOpenDelaysNanoseconds: [UInt64] = []
    private var pendingCreateHandlesToOmit = 0
    private var pendingOpenHandlesToOmit = 0
    private var pendingLookupItemIdentifiersToCorrupt = 0
    private struct ProvisionalResource {
        var handle: UInt64
        var itemCount: UInt32
    }
    private var provisionalResourcesByRequestID: [UInt64: ProvisionalResource] = [:]
    private var resourceAccepts = 0
    private var resourceAbandons = 0
    private var resourceAcceptedItemCounts: [UInt32] = []
    private var pendingCloseDelaysNanoseconds: [UInt64] = []
    private var pendingReadDelaysNanoseconds: [UInt64] = []
    private var pendingWriteDelaysNanoseconds: [UInt64] = []
    /// Write-request index (0-based, counted across the whole session) → errno.
    /// Positional rather than a queue because the shape under test is "chunk k
    /// of one framework callback fails after chunks 0..<k committed", and that
    /// needs the failure placed at a known request, not merely next in line.
    private var writeErrnoByIndex: [Int: Int32] = [:]
    private var pendingWriteShortCounts: [Int] = []

    init(configuration: PfsLocalMockDaemon.Configuration) {
        self.configuration = configuration
        let root = Node(id: 1, kind: .directory, mode: 0o755, parent: nil)
        nodes[root.id] = root
    }

    func rootIdentity() -> PfsItemIdentity {
        PfsItemIdentity(
            itemID: 1,
            generation: 1,
            stableIdentity: Node.stableIdentity(for: 1)
        )
    }

    func stats() -> PfsLocalMockDaemon.Stats {
        PfsLocalMockDaemon.Stats(
            openRequests: openRequests,
            closeRequests: closeRequests,
            reclaimRequests: reclaimRequests,
            activeHandles: handles.count,
            readRequests: readRequests,
            writeRequests: writeRequests,
            orderedMutationSourcePhaseQueueable: orderedMutationSourcePhaseQueueable,
            enumerateRequests: enumerateRequests,
            getAttrRequests: getAttrRequests,
            setAttrRequests: setAttrRequests,
            lookupRequests: lookupRequests,
            createRequests: createRequests,
            removeRequests: removeRequests,
            renameRequests: renameRequests,
            xattrGetRequests: xattrGetRequests,
            xattrSetRequests: xattrSetRequests,
            xattrListRequests: xattrListRequests,
            xattrRemoveRequests: xattrRemoveRequests,
            flagChangeRequests: flagChangeRequests,
            maxReadLength: maxReadLength,
            maxWriteLength: maxWriteLength,
            publicationAcks: publicationAcks,
            resourceAccepts: resourceAccepts,
            resourceAbandons: resourceAbandons,
            resourceAcceptedItemCounts: resourceAcceptedItemCounts,
            visibilityAcks: visibilityAcks.count,
            v3LivenessRequests: v3LivenessRequests.count,
            syncVolumeRequests: syncVolumeRequests
        )
    }

    func visibilityAcknowledgements() -> [PfsVisibilityAckRequest] {
        visibilityAcks
    }

    func v3LivenessRequestsSnapshot() -> [PfsV3LivenessRequest] {
        v3LivenessRequests
    }

    func resetStats() {
        openRequests = 0
        closeRequests = 0
        reclaimRequests = 0
        readRequests = 0
        writeRequests = 0
        orderedMutationSourcePhaseQueueable.removeAll()
        enumerateRequests = 0
        getAttrRequests = 0
        setAttrRequests = 0
        lookupRequests = 0
        createRequests = 0
        removeRequests = 0
        renameRequests = 0
        xattrGetRequests = 0
        xattrSetRequests = 0
        xattrListRequests = 0
        xattrRemoveRequests = 0
        flagChangeRequests = 0
        resourceAccepts = 0
        resourceAbandons = 0
        resourceAcceptedItemCounts.removeAll()
        maxReadLength = 0
        maxWriteLength = 0
        publicationAcks = 0
        visibilityAcks.removeAll()
        v3LivenessRequests.removeAll()
        syncVolumeRequests = 0
    }

    func retractNextPublications(count: Int) {
        pendingRetractions += count
    }

    func refuseNextPublicationsAsRetracted(count: Int) {
        pendingRetractionRefusals += count
    }

    func failNextClose() {
        pendingCloseFailures += 1
    }

    func retireNextCloseWithError(errno: Int32) {
        pendingRetiredCloseErrnos.append(errno)
    }

    func loseNextRetiredCloseReply(errno: Int32) {
        pendingLostRetiredCloseErrnos.append(errno)
    }

    func delayNextOpen(nanoseconds: UInt64) {
        pendingOpenDelaysNanoseconds.append(nanoseconds)
    }

    func omitNextCreateHandle() {
        pendingCreateHandlesToOmit += 1
    }

    func corruptNextLookupItemIdentifier() {
        pendingLookupItemIdentifiersToCorrupt += 1
    }

    func omitNextOpenHandle() {
        pendingOpenHandlesToOmit += 1
    }

    func delayNextClose(nanoseconds: UInt64) {
        pendingCloseDelaysNanoseconds.append(nanoseconds)
    }

    func delayNextRead(nanoseconds: UInt64) {
        pendingReadDelaysNanoseconds.append(nanoseconds)
    }

    func delayNextWrite(nanoseconds: UInt64) {
        pendingWriteDelaysNanoseconds.append(nanoseconds)
    }

    func failWrite(atIndex index: Int, errno code: Int32) {
        writeErrnoByIndex[index] = code
    }

    func shortenNextWrite(to written: Int) {
        pendingWriteShortCounts.append(written)
    }

    func handle(_ envelope: PfsEnvelope, session: MockSession) async -> PfsEnvelope {
        session.noteOperationID(envelope.operationID)
        var reply = PfsEnvelope()
        reply.requestID = envelope.requestID
        do {
            guard let body = envelope.body else {
                throw MockPOSIXError(errno: EINVAL, message: "missing body")
            }
            switch body {
            case .setAttr, .write, .create, .mkdir, .remove, .rename,
                 .symlink, .hardLink, .xattrSet, .xattrRemove:
                orderedMutationSourcePhaseQueueable.append(
                    envelope.sourcePhaseQueueable
                )
            default:
                break
            }
            switch body {
            case .lookup(_), .enumerate(_), .getAttr(_), .setAttr(_),
                 .read(_), .write(_), .create(_), .mkdir(_), .remove(_),
                 .rename(_), .symlink(_), .readlink(_), .hardLink(_),
                 .xattrGet(_), .xattrSet(_), .xattrList(_), .xattrRemove(_):
                reply.publicationAckRequired = true
            default:
                reply.publicationAckRequired = false
            }
            // Only a reply the frontend could publish can be retracted, and
            // the retraction still leaves the acknowledgement owed: the
            // daemon's handoff gate is released by the ack, not by whether
            // the frontend kept the values.
            if reply.publicationAckRequired && pendingRetractions > 0 {
                pendingRetractions -= 1
                reply.publicationRetracted = true
            }
            // The refusal arm must throw BEFORE the dispatch switch below, or
            // the mock would be modelling a daemon that retracts an operation
            // and mutates for it anyway — precisely the state the real
            // daemon's pre-dispatch check exists to make unreachable.
            if reply.publicationAckRequired && pendingRetractionRefusals > 0 {
                pendingRetractionRefusals -= 1
                reply.publicationRetracted = true
                throw MockPOSIXError(errno: EINTR, message: "operation retracted before dispatch")
            }
            switch body {
            case let .hello(request):
                var response = PfsHelloReply()
                response.protocolMajor = request.protocolMajor
                response.protocolMinor = configuration.protocolMinor ?? request.protocolMinor
                response.daemonVersion = "mock"
                reply.body = .helloReply(response)
            case let .resolve(request):
                guard request.attachRef == configuration.attachRef else {
                    throw MockPOSIXError(errno: ENOENT, message: "unknown attachRef")
                }
                var response = PfsResolveReply()
                let root = try node(for: rootIdentity().proto)
                response.root = root.item
                response.rootAttr = attr(for: root)
                response.volumeID = configuration.volumeID
                response.volumeName = configuration.volumeName
                response.branch = configuration.branch
                var capabilities = PfsCapabilities()
                capabilities.symlinks = true
                capabilities.hardLinks = true
                capabilities.xattrs = true
                capabilities.caseSensitive = true
                capabilities.maxNameBytes = 255
                capabilities.maxFileSize = UInt64.max
                capabilities.preferredIoBytes = 1_048_576
                // A daemon predating the flag fields advertises neither: it
                // cannot set fields it does not know exist, and both decode
                // false on the frontend.
                capabilities.flagsSupported = configuration.flagsSupported && !configuration.predatesFlagFields
                capabilities.flagsUnderstood = configuration.flagsUnderstood && !configuration.predatesFlagFields
                capabilities.xattrSetSupported = configuration.xattrSetSupported
                response.capabilities = capabilities
                if let v3Coherence = configuration.v3Coherence {
                    response.v3Coherence = v3Coherence
                }
                reply.body = .resolveReply(response)
            case let .lookup(request):
                lookupRequests += 1
                let name = displayName(request.name)
                if configuration.lookupNoReplyNames.contains(name) {
                    try await Task.sleep(nanoseconds: 3_600_000_000_000)
                }
                if let delay = configuration.lookupDelaysNanoseconds[name] {
                    try await Task.sleep(nanoseconds: delay)
                }
                let directory = try node(for: request.dir)
                guard directory.kind == .directory else {
                    throw MockPOSIXError(errno: ENOTDIR, message: "not a directory")
                }
                guard let childID = directory.children[request.name], let child = nodes[childID] else {
                    throw MockPOSIXError(errno: ENOENT, message: "not found")
                }
                var response = PfsLookupReply()
                response.attr = attr(for: child, parent: directory)
                if pendingLookupItemIdentifiersToCorrupt > 0 {
                    pendingLookupItemIdentifiersToCorrupt -= 1
                    response.attr.item.itemID =
                        PfsFSKitMapping.localRepairIdentifierFloor
                }
                provisionalResourcesByRequestID[envelope.requestID] =
                    ProvisionalResource(handle: 0, itemCount: 1)
                reply.body = .lookupReply(response)
            case let .enumerate(request):
                enumerateRequests += 1
                let directory = try node(for: request.dir)
                guard directory.kind == .directory else {
                    throw MockPOSIXError(errno: ENOTDIR, message: "not a directory")
                }
                guard request.handle != 0, handles[request.handle] == directory.item.itemID else {
                    throw MockPOSIXError(errno: EBADF, message: "enumeration handle does not belong to directory")
                }
                let ordered = orderedChildren(of: directory)
                let resume = try decodeCookie(request.cookie)
                let start = ordered.firstIndex { $0.cursor > resume } ?? ordered.count
                let maxEntries = max(1, Int(request.maxEntries))
                let end = min(ordered.count, start + maxEntries)
                var response = PfsEnumerateReply()
                for index in start..<end {
                    let name = ordered[index].name
                    if let childID = directory.children[name], let child = nodes[childID] {
                        var entry = PfsDirEntry()
                        entry.name = name
                        entry.attr = attr(for: child, parent: directory)
                        entry.cookie = index + 1 >= ordered.count ? 0 : encodeCookie(cursor: ordered[index].cursor)
                        response.entries.append(entry)
                    }
                }
                response.nextCookie = response.entries.last?.cookie ?? 0
                response.dirVersion = directory.contentVersion
                provisionalResourcesByRequestID[envelope.requestID] =
                    ProvisionalResource(
                        handle: 0,
                        itemCount: UInt32(clamping: response.entries.count)
                    )
                reply.body = .enumerateReply(response)
            case let .getAttr(request):
                getAttrRequests += 1
                var response = PfsGetAttrReply()
                response.attr = attr(for: try node(for: request.item, handle: request.handle))
                reply.body = .getAttrReply(response)
            case let .setAttr(request):
                setAttrRequests += 1
                let node = try node(for: request.item, handle: request.handle)
                // A daemon predating the appended fields never observes them:
                // proto3 discards unknown fields before any handler runs, so
                // it can neither apply nor refuse the flags change.
                let setFlags = request.setFlags && !configuration.predatesFlagFields
                if setFlags {
                    flagChangeRequests += 1
                }
                // The real daemon's decision is PER TARGET, taken where the
                // backing is known. A grafted node's backing is a real host
                // inode, so its chflags(2) lands whatever the authority can or
                // cannot store; an authority-backed node without
                // FeatureFlagPersistence is refused the WHOLE setattr before
                // anything is applied. The frontend cannot make this call — it
                // does not know what backs the object — which is exactly why
                // its own gate asks a different question (does this daemon
                // parse set_flags at all).
                if setFlags && !configuration.flagsSupported && !isGraftBacked(node) {
                    throw MockPOSIXError(errno: ENOTSUP, message: "authority does not persist BSD file flags")
                }
                if request.hasMode { node.mode = request.mode }
                if request.hasUid { node.uid = request.uid }
                if request.hasGid { node.gid = request.gid }
                if request.hasSize { resize(node: node, size: Int(request.size)) }
                if request.hasMtimeMs { node.mtimeMs = request.mtimeMs }
                if request.hasAtimeMs { node.atimeMs = request.atimeMs }
                if setFlags { node.flags = request.flags }
                node.ctimeMs = nowMs()
                var response = PfsSetAttrReply()
                response.attr = attr(for: node)
                reply.body = .setAttrReply(response)
            case let .open(request):
                _ = try namespaceNode(for: request.item)
                openRequests += 1
                let handle: UInt64
                if pendingOpenHandlesToOmit > 0 {
                    pendingOpenHandlesToOmit -= 1
                    handle = 0
                } else {
                    handle = nextHandle
                    nextHandle += 1
                    handles[handle] = request.item.itemID
                }
                provisionalResourcesByRequestID[envelope.requestID] =
                    ProvisionalResource(handle: handle, itemCount: 0)
                if !pendingOpenDelaysNanoseconds.isEmpty {
                    let delay = pendingOpenDelaysNanoseconds.removeFirst()
                    try await Task.sleep(nanoseconds: delay)
                }
                var response = PfsOpenReply()
                response.handle = handle
                reply.body = .openReply(response)
            case let .close(request):
                closeRequests += 1
                if !pendingCloseDelaysNanoseconds.isEmpty {
                    let delay = pendingCloseDelaysNanoseconds.removeFirst()
                    try await Task.sleep(nanoseconds: delay)
                }
                if pendingCloseFailures > 0 {
                    pendingCloseFailures -= 1
                    throw MockPOSIXError(errno: EIO, message: "injected close failure")
                }
                if let response = retiredCloseReplies[request.handle] {
                    reply.body = .closeReply(response)
                    break
                }
                guard let nodeID = handles.removeValue(forKey: request.handle) else {
                    throw MockPOSIXError(errno: EINVAL, message: "unknown handle")
                }
                reapIfUnlinked(nodeID: nodeID)
                var response = PfsCloseReply()
                response.retired = true
                let loseReply = !pendingLostRetiredCloseErrnos.isEmpty
                if loseReply {
                    response.closeErrno = pendingLostRetiredCloseErrnos.removeFirst()
                } else if !pendingRetiredCloseErrnos.isEmpty {
                    response.closeErrno = pendingRetiredCloseErrnos.removeFirst()
                }
                retiredCloseReplies[request.handle] = response
                reply.body = .closeReply(response)
                if loseReply {
                    session.close()
                }
            case let .read(request):
                readRequests += 1
                maxReadLength = max(maxReadLength, request.length)
                if !pendingReadDelaysNanoseconds.isEmpty {
                    let delay = pendingReadDelaysNanoseconds.removeFirst()
                    try await Task.sleep(nanoseconds: delay)
                }
                let node = try node(forHandle: request.handle)
                let offset = min(Int(request.offset), node.data.count)
                let end = min(node.data.count, offset + Int(request.length))
                var response = PfsReadReply()
                response.data = node.data.subdata(in: offset..<end)
                reply.body = .readReply(response)
            case let .write(request):
                let writeIndex = writeRequests
                writeRequests += 1
                maxWriteLength = max(maxWriteLength, request.data.count)
                if !pendingWriteDelaysNanoseconds.isEmpty {
                    let delay = pendingWriteDelaysNanoseconds.removeFirst()
                    try await Task.sleep(nanoseconds: delay)
                }
                if let code = writeErrnoByIndex[writeIndex] {
                    throw MockPOSIXError(errno: code, message: "injected write failure")
                }
                let node = try node(forHandle: request.handle)
                var payload = request.data
                if !pendingWriteShortCounts.isEmpty {
                    let want = pendingWriteShortCounts.removeFirst()
                    payload = payload.prefix(max(0, min(want, payload.count)))
                }
                write(node: node, offset: Int(request.offset), data: payload)
                var response = PfsWriteReply()
                response.written = UInt32(payload.count)
                response.attr = attr(for: node)
                reply.body = .writeReply(response)
            case let .create(request):
                createRequests += 1
                let directory = try node(for: request.dir)
                guard directory.children[request.name] == nil else {
                    throw MockPOSIXError(errno: EEXIST, message: "exists")
                }
                let node = createNode(kind: .file, mode: request.mode, parent: directory.id)
                directory.children[request.name] = node.id
                bump(directory)
                let handle: UInt64
                if pendingCreateHandlesToOmit > 0 {
                    pendingCreateHandlesToOmit -= 1
                    handle = 0
                } else {
                    handle = nextHandle
                    nextHandle += 1
                    handles[handle] = node.id
                }
                provisionalResourcesByRequestID[envelope.requestID] =
                    ProvisionalResource(handle: handle, itemCount: 1)
                var response = PfsCreateReply()
                response.attr = attr(for: node)
                response.handle = handle
                reply.body = .createReply(response)
            case let .mkdir(request):
                createRequests += 1
                let directory = try node(for: request.dir)
                guard directory.children[request.name] == nil else {
                    throw MockPOSIXError(errno: EEXIST, message: "exists")
                }
                let node = createNode(kind: .directory, mode: request.mode, parent: directory.id)
                directory.children[request.name] = node.id
                bump(directory)
                var response = PfsMkdirReply()
                response.attr = attr(for: node)
                provisionalResourcesByRequestID[envelope.requestID] =
                    ProvisionalResource(handle: 0, itemCount: 1)
                reply.body = .mkdirReply(response)
            case let .remove(request):
                removeRequests += 1
                let directory = try node(for: request.dir)
                guard let childID = directory.children[request.name], let child = nodes[childID] else {
                    throw MockPOSIXError(errno: ENOENT, message: "not found")
                }
                if request.directory && !child.children.isEmpty {
                    throw MockPOSIXError(errno: ENOTEMPTY, message: "directory not empty")
                }
                directory.children.removeValue(forKey: request.name)
                child.nlink = child.nlink > 0 ? child.nlink - 1 : 0
                reapIfUnlinked(nodeID: childID)
                bump(directory)
                reply.body = .removeReply(PfsRemoveReply())
            case let .rename(request):
                renameRequests += 1
                let fromDirectory = try node(for: request.fromDir)
                let toDirectory = try node(for: request.toDir)
                guard let childID = fromDirectory.children[request.fromName] else {
                    throw MockPOSIXError(errno: ENOENT, message: "not found")
                }
                let replacedID = toDirectory.children[request.toName]
                if request.noReplace && replacedID != nil && replacedID != childID {
                    throw MockPOSIXError(errno: EEXIST, message: "exists")
                }
                if replacedID == childID {
                    // POSIX specifies a no-op when both names are hard links
                    // to the same inode: neither directory entry is removed.
                    reply.body = .renameReply(PfsRenameReply())
                    break
                }
                fromDirectory.children.removeValue(forKey: request.fromName)
                if let replacedID, replacedID != childID, let replaced = nodes[replacedID] {
                    replaced.nlink = replaced.nlink > 0 ? replaced.nlink - 1 : 0
                    reapIfUnlinked(nodeID: replacedID)
                }
                toDirectory.children[request.toName] = childID
                nodes[childID]?.parent = toDirectory.id
                bump(fromDirectory)
                bump(toDirectory)
                reply.body = .renameReply(PfsRenameReply())
            case let .symlink(request):
                createRequests += 1
                let directory = try node(for: request.dir)
                guard directory.children[request.name] == nil else {
                    throw MockPOSIXError(errno: EEXIST, message: "exists")
                }
                let node = createNode(kind: .symlink, mode: 0o777, parent: directory.id)
                node.symlinkTarget = request.target
                node.data = request.target
                directory.children[request.name] = node.id
                bump(directory)
                var response = PfsSymlinkReply()
                response.attr = attr(for: node)
                provisionalResourcesByRequestID[envelope.requestID] =
                    ProvisionalResource(handle: 0, itemCount: 1)
                reply.body = .symlinkReply(response)
            case let .readlink(request):
                let node = try node(for: request.item)
                guard node.kind == .symlink else {
                    throw MockPOSIXError(errno: EINVAL, message: "not a symlink")
                }
                var response = PfsReadlinkReply()
                response.target = node.symlinkTarget
                reply.body = .readlinkReply(response)
            case let .hardLink(request):
                createRequests += 1
                let item = try node(for: request.item)
                let directory = try node(for: request.dir)
                guard item.kind != .directory else {
                    throw MockPOSIXError(errno: EPERM, message: "hard links to directories are not permitted")
                }
                guard directory.children[request.name] == nil else {
                    throw MockPOSIXError(errno: EEXIST, message: "exists")
                }
                item.nlink += 1
                directory.children[request.name] = item.id
                bump(directory)
                var response = PfsHardLinkReply()
                response.name = request.name
                response.attr = attr(for: item, parent: directory)
                reply.body = .hardLinkReply(response)
            case let .xattrGet(request):
                xattrGetRequests += 1
                if let errno = configuration.xattrGetErrno {
                    throw MockPOSIXError(errno: errno, message: "injected get-xattr failure")
                }
                let node = try node(for: request.item, handle: request.handle)
                guard let value = node.xattrs[request.name] else {
                    throw MockPOSIXError(errno: ENOATTR, message: "xattr not found")
                }
                var response = PfsXattrGetReply()
                response.value = value
                reply.body = .xattrGetReply(response)
            case let .xattrSet(request):
                xattrSetRequests += 1
                if let errno = configuration.xattrSetErrno {
                    throw MockPOSIXError(errno: errno, message: "injected set-xattr failure")
                }
                let node = try node(for: request.item, handle: request.handle)
                let exists = node.xattrs[request.name] != nil
                if request.createOnly && exists {
                    throw MockPOSIXError(errno: EEXIST, message: "xattr exists")
                }
                if request.replaceOnly && !exists {
                    throw MockPOSIXError(errno: ENOATTR, message: "xattr missing")
                }
                node.xattrs[request.name] = request.value
                reply.body = .xattrSetReply(PfsXattrSetReply())
            case let .xattrList(request):
                xattrListRequests += 1
                if let errno = configuration.xattrListErrno {
                    throw MockPOSIXError(errno: errno, message: "injected list-xattr failure")
                }
                let node = try node(for: request.item, handle: request.handle)
                var response = PfsXattrListReply()
                response.names = node.xattrs.keys.sorted()
                reply.body = .xattrListReply(response)
            case let .xattrRemove(request):
                xattrRemoveRequests += 1
                if let errno = configuration.xattrRemoveErrno {
                    throw MockPOSIXError(errno: errno, message: "injected remove-xattr failure")
                }
                let node = try node(for: request.item, handle: request.handle)
                guard node.xattrs.removeValue(forKey: request.name) != nil else {
                    throw MockPOSIXError(errno: ENOATTR, message: "xattr missing")
                }
                reply.body = .xattrRemoveReply(PfsXattrRemoveReply())
            case .statfs:
                var response = PfsStatfsReply()
                response.blockSize = 4096
                response.totalBlocks = 1_000_000
                response.freeBlocks = 750_000
                response.totalFiles = 1_000_000
                response.freeFiles = 900_000
                reply.body = .statfsReply(response)
            case .syncVolume:
                syncVolumeRequests += 1
                reply.body = .syncVolumeReply(PfsSyncVolumeReply())
            case .fsync:
                reply.body = .fsyncReply(PfsFsyncReply())
            case let .reclaim(request):
                reclaimRequests += 1
                // Reclaim can legally arrive after unlink+close already reaped
                // the node: the kernel's last reference is gone either way, so
                // an absent node is a completed reclaim, not a stale item. A
                // node that still exists under a different generation is.
                if let node = nodes[request.item.itemID],
                   node.generation != request.item.itemGeneration {
                    throw MockPOSIXError(errno: ESTALE, message: "stale item")
                }
                reply.body = .reclaimReply(PfsReclaimReply())
            case .subscribeEvents:
                session.setSubscribed()
                reply.body = .subscribeEventsReply(PfsSubscribeEventsReply())
            case let .publicationAck(request):
                // One-way publication completion; requestID zero keeps the
                // empty mock envelope outside the request multiplexer. The
                // ledger check mirrors the real daemon: an ack for an
                // operation this connection never showed on a request — for
                // example one that overtook its own request on the priority
                // lane — or a duplicate ack, closes the connection.
                if session.acknowledgeOperation(request.operationID) {
                    publicationAcks += 1
                } else {
                    session.close()
                }
                break
            case let .resourceReplyDisposition(request):
                guard let resource = provisionalResourcesByRequestID.removeValue(
                    forKey: request.targetRequestID
                ) else {
                    throw MockPOSIXError(
                        errno: EINVAL,
                        message: "unknown or duplicate resource reply disposition"
                    )
                }
                guard request.acceptedItemCount <= resource.itemCount,
                      !request.acceptHandles || resource.handle != 0 else {
                    session.close()
                    break
                }
                resourceAcceptedItemCounts.append(request.acceptedItemCount)
                if request.acceptHandles || request.acceptedItemCount > 0 {
                    resourceAccepts += 1
                } else {
                    resourceAbandons += 1
                }
                if resource.handle != 0, !request.acceptHandles,
                   let nodeID = handles.removeValue(forKey: resource.handle) {
                    reapIfUnlinked(nodeID: nodeID)
                }
                break
            case let .visibilityAck(request):
                visibilityAcks.append(request)
                reply.body = .visibilityAckReply(PfsVisibilityAckReply())
            case let .v3Liveness(request):
                guard request.authorityEpoch.count == 16,
                      request.sessionID.count == 16 else {
                    throw MockPOSIXError(errno: EINVAL, message: "invalid v3 liveness identity")
                }
                if let contract = configuration.v3Coherence {
                    guard request.authorityEpoch == contract.authorityEpoch,
                          request.sessionID == contract.sessionID else {
                        throw MockPOSIXError(errno: EINVAL, message: "wrong v3 liveness identity")
                    }
                }
                v3LivenessRequests.append(request)
                if configuration.v3LivenessDelayNanoseconds > 0 {
                    try await Task.sleep(
                        nanoseconds: configuration.v3LivenessDelayNanoseconds
                    )
                }
                var response = PfsV3LivenessReply()
                let applyOverrides = v3LivenessRequests.count
                    > configuration.v3LivenessOverrideAfterRequestCount
                response.authorityEpoch = applyOverrides
                    ? (configuration.v3LivenessEpochOverride ?? request.authorityEpoch)
                    : request.authorityEpoch
                response.sessionID = applyOverrides
                    ? (configuration.v3LivenessSessionOverride ?? request.sessionID)
                    : request.sessionID
                reply.body = .v3LivenessReply(response)
            case .helloReply, .resolveReply, .lookupReply, .enumerateReply, .getAttrReply,
                 .setAttrReply, .openReply, .closeReply, .readReply, .writeReply,
                 .createReply, .mkdirReply, .removeReply, .renameReply, .symlinkReply,
                 .readlinkReply, .xattrGetReply, .xattrSetReply, .xattrListReply,
                 .xattrRemoveReply, .statfsReply, .fsyncReply, .reclaimReply,
                 .subscribeEventsReply, .hardLinkReply, .syncVolumeReply,
                 .visibilityAckReply, .v3LivenessReply, .error, .event:
                throw MockPOSIXError(errno: EINVAL, message: "daemon received reply body")
            }
        } catch let error as MockPOSIXError {
            var errorReply = PfsErrorReply()
            errorReply.errno = error.errno
            errorReply.message = error.message
            reply.body = .error(errorReply)
        } catch {
            var errorReply = PfsErrorReply()
            errorReply.errno = EIO
            errorReply.message = String(describing: error)
            reply.body = .error(errorReply)
        }
        reply.sourcePhaseQueueable = configuration.sourcePhaseQueueableOnReplies
        return reply
    }

    private func node(for item: PfsItem) throws -> Node {
        guard let node = nodes[item.itemID], node.generation == item.itemGeneration else {
            throw MockPOSIXError(errno: ESTALE, message: "stale item")
        }
        return node
    }

    private func node(for item: PfsItem, handle: UInt64) throws -> Node {
        guard handle != 0 else {
            return try namespaceNode(for: item)
        }
        let retained = try node(forHandle: handle)
        guard retained.id == item.itemID, retained.generation == item.itemGeneration else {
            throw MockPOSIXError(errno: EINVAL, message: "handle does not belong to item")
        }
        return retained
    }

    private func namespaceNode(for item: PfsItem) throws -> Node {
        let node = try node(for: item)
        if configuration.strictItemNamespace && node.nlink == 0 {
            throw MockPOSIXError(errno: ENOENT, message: "item is detached from the namespace")
        }
        return node
    }

    private func node(forHandle handle: UInt64) throws -> Node {
        guard let id = handles[handle], let node = nodes[id] else {
            throw MockPOSIXError(errno: EBADF, message: "bad handle")
        }
        return node
    }

    private func reapIfUnlinked(nodeID: UInt64) {
        guard let node = nodes[nodeID], node.nlink == 0 else {
            return
        }
        if handles.values.contains(nodeID) {
            return
        }
        nodes.removeValue(forKey: nodeID)
    }

    private func createNode(kind: PfsItemKind, mode: UInt32, parent: UInt64) -> Node {
        let node = Node(id: nextNodeID, kind: kind, mode: mode, parent: parent)
        nextNodeID += 1
        nodes[node.id] = node
        return node
    }

    private func liveParent(for node: Node) -> Node? {
        guard node.id != rootIdentity().itemID else {
            return nil
        }
        return nodes.values
            .filter { candidate in
                candidate.kind == .directory &&
                    candidate.children.values.contains(node.id)
            }
            .min { lhs, rhs in lhs.id < rhs.id }
    }

    private func attr(for node: Node, parent explicitParent: Node? = nil) -> PfsAttr {
        var attr = PfsAttr()
        attr.item = node.item
        if let parent = explicitParent ?? liveParent(for: node) {
            attr.parent = parent.item
        }
        attr.kind = node.kind
        attr.mode = node.mode
        attr.nlink = node.nlink
        attr.uid = node.uid
        attr.gid = node.gid
        attr.size = UInt64(node.kind == .symlink ? node.symlinkTarget.count : node.data.count)
        attr.allocSize = attr.size
        attr.mtimeMs = node.mtimeMs
        attr.ctimeMs = node.ctimeMs
        attr.atimeMs = node.atimeMs
        attr.birthtimeMs = node.birthtimeMs
        attr.contentVersion = node.contentVersion
        attr.flags = node.flags
        return attr
    }

    private func resize(node: Node, size: Int) {
        if node.data.count < size {
            node.data.append(Data(repeating: 0, count: size - node.data.count))
        } else if node.data.count > size {
            node.data.removeSubrange(size..<node.data.count)
        }
        bump(node)
    }

    private func write(node: Node, offset: Int, data: Data) {
        if node.data.count < offset {
            node.data.append(Data(repeating: 0, count: offset - node.data.count))
        }
        let end = offset + data.count
        if node.data.count < end {
            node.data.append(Data(repeating: 0, count: end - node.data.count))
        }
        node.data.replaceSubrange(offset..<end, with: data)
        bump(node)
    }

    private func bump(_ node: Node) {
        let now = nowMs()
        node.mtimeMs = now
        node.ctimeMs = now
        node.contentVersion += 1
    }

    private func nowMs() -> Int64 {
        Int64(Date().timeIntervalSince1970 * 1000)
    }

    /// A node is graft-backed when its name matches a configured graft rule.
    /// The real daemon knows this from its routing table; the mock recovers the
    /// name from the parent's directory map so no rename path has to keep a
    /// second copy of it in sync.
    private func isGraftBacked(_ node: Node) -> Bool {
        if configuration.graftBackedNames.isEmpty {
            return false
        }
        guard let parentID = node.parent, let directory = nodes[parentID] else {
            return false
        }
        for (name, id) in directory.children where id == node.id {
            if configuration.graftBackedNames.contains(displayName(name)) {
                return true
            }
        }
        return false
    }

    private func displayName(_ data: Data) -> String {
        String(data: data, encoding: .utf8) ?? data.map { String(format: "%02x", $0) }.joined()
    }

    /// The directory's total enumeration order: ascending name cursor, ties
    /// broken by name, with equal cursors perturbed upward so every entry has a
    /// unique strictly increasing resumption key.
    private func orderedChildren(of directory: Node) -> [(name: Data, cursor: UInt64)] {
        var ordered = directory.children.keys.map { (name: $0, cursor: enumerationCursor($0)) }
        ordered.sort { lhs, rhs in
            if lhs.cursor != rhs.cursor {
                return lhs.cursor < rhs.cursor
            }
            return displayName(lhs.name) < displayName(rhs.name)
        }
        for index in 1..<max(ordered.count, 1) where ordered[index].cursor <= ordered[index - 1].cursor {
            ordered[index].cursor = ordered[index - 1].cursor + 1
        }
        return ordered
    }

    private func enumerationCursor(_ name: Data) -> UInt64 {
        var hash: UInt64 = 0xcbf2_9ce4_8422_2325
        for byte in name {
            hash ^= UInt64(byte)
            hash = hash &* 0x0000_0100_0000_01b3
        }
        return 1 + hash % Self.cursorSpace
    }

    private func encodeCookie(cursor: UInt64) -> UInt64 {
        Self.daemonCookieMarker | (cursor << 2) | Self.cookieTagCursor
    }

    /// Returns the resume cursor for a cookie. Foreign cookies fail with
    /// ESTALE, the daemon's documented fail-safe; cookies this daemon issued
    /// always resolve.
    private func decodeCookie(_ cookie: UInt64) throws -> UInt64 {
        if cookie == 0 {
            return 0
        }
        guard (cookie & Self.daemonCookieMarker) != 0,
              (cookie & Self.cookieTagMask) == Self.cookieTagCursor
        else {
            throw MockPOSIXError(errno: ESTALE, message: "invalid directory cookie")
        }
        let cursor = (cookie & ~Self.daemonCookieMarker) >> 2
        guard cursor != 0 else {
            throw MockPOSIXError(errno: ESTALE, message: "invalid directory cookie")
        }
        return cursor
    }
}
