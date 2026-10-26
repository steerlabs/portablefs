import Foundation
import PortableFSWorkspaceCore

/// One durable desired-state owner above the existing VM and guest jobs. API
/// connections are waiters only; closing an app/CLI never cancels accepted work.
@MainActor public final class WorkspaceProductOwner {
    public typealias Factory = () throws -> any WorkspaceProductRuntime
    public let store: WorkspaceHostState
    private let reservationDirectory: URL
    private let hostBoot: String
    private let factory: Factory
    private var runtime: (any WorkspaceProductRuntime)?
    private var latest: WorkspaceStatusReply?
    private var inFlight = Set<String>()
    private var authorizations: [String: WorkspaceProvision] = [:]
    private var stopRequested = false
    private var stopForce = false
    private var shutdownIssued = false
    private var failure = ""
    private var updateQueued = false
    private var quiescing = false

    public init(store: WorkspaceHostState, reservationDirectory: URL, hostBoot: String, factory: @escaping Factory) {
        self.store = store; self.reservationDirectory = reservationDirectory; self.hostBoot = hostBoot; self.factory = factory
    }
    public func launch() {
        do {
            if store.value.running { try startIfNeeded() }
            else {
                try store.requirePriorExecutionAbsent(hostBoot:hostBoot)
                try releaseAbsentReservations()
            }
        } catch { failure = String(describing:error) }
    }
    public func handle(_ request: WorkspaceHostRequest) -> WorkspaceHostReply {
        do {
            defer { scheduleUpdate() }
            try request.validate()
            guard !quiescing || request.operation == "status" else { throw WorkspaceVMError("workspace service is quiescing") }
            switch request.operation {
            case "status": break
            case "start":
                guard !stopRequested else { throw WorkspaceVMError("workspace stop is pending") }
                try store.commit { $0.running = true }; try startIfNeeded()
            case "mount":
                guard let document = request.document, !stopRequested else { throw WorkspaceControlError.grammar }
                try accept(document); try startIfNeeded(); scheduleUpdate()
            case "umount":
                guard let volume = request.volumeId else { throw WorkspaceControlError.grammar }
                try remove(volume, force: request.force == true)
            case "stop":
                stopRequested = true; stopForce = request.force == true
                if stopForce { try store.commit { $0.running = false }; runtime?.stop(force: true) { _ in } }
                scheduleUpdate()
            default: throw WorkspaceControlError.grammar
            }
            if request.operation != "status" { failure = "" }
            return snapshot()
        } catch {
            var reply = snapshot(); reply.state = "refused"; reply.message = String(describing: error); return reply
        }
    }
    private func accept(_ document: WorkspaceConnectionDocument) throws {
        try document.validate()
        let connection = document.connection
        if let index = store.value.volumes.firstIndex(where: { $0.connection.volumeId == connection.volumeId }) {
            let old = store.value.volumes[index]
            guard old.connection == connection else { throw WorkspaceVMError("Cleanup required") }
            if document.kind == "authorization" {
                guard let saved = old.request, document.matchesRequest(saved) else { throw WorkspaceVMError("authorization does not bind the saved request") }
                if old.authorizationConsumed { return }
                let provision = try document.provision()
                try store.commit { $0.running = true; $0.volumes[index].authorizationConsumed = true; $0.volumes[index].operation = "provision"; $0.volumes[index].message = "pending" }
                authorizations[connection.volumeId] = provision
            } else {
                guard document.kind == "connection" else { throw WorkspaceVMError("import an authorization response") }
                if old.operation == "terminal" {
                    if old.authorizationConsumed, let identity = try old.request?.guestIdentity() {
                        let observed = (latest?.mounts ?? []) + (latest?.retired.filter(\.hasMountStatus).map(\.mountStatus) ?? []) + store.value.retained.compactMap { try? WorkspaceControl.decode($0).statusReply.retired.first?.mountStatus }
                        guard observed.contains(where: { $0.mount == identity.mount && $0.cleanup == "complete" }) else { throw WorkspaceVMError("Cleanup required") }
                    }
                    try store.commit { $0.running = true; $0.volumes[index].operation = "identity"; $0.volumes[index].request = nil; $0.volumes[index].authorizationConsumed = false; $0.volumes[index].reopenRequired = true }
                } else { try store.commit { $0.running = true } }
            }
            return
        }
        guard document.kind == "connection", store.value.volumes.count < 64 else { throw WorkspaceVMError("connection document required") }
        let intent = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
        let desired = WorkspaceDesiredVolume(connection: connection, intent: intent)
        let transition = try WorkspaceReservations(directory: reservationDirectory)
        try transition.reserve(desired.reservation)
        try store.commit { $0.running = true; $0.volumes.append(desired) }
        withExtendedLifetime(transition) {}
    }
    private func startIfNeeded() throws {
        guard store.value.running else { return }
        if let runtime {
            guard runtime.phase != .stopped else { throw WorkspaceVMError(failure.isEmpty ? "Cleanup required" : failure) }
            return
        }
        try store.requirePriorExecutionAbsent(hostBoot: hostBoot)
        let transition = try WorkspaceReservations(directory: reservationDirectory)
        for volume in store.value.volumes { try transition.reserve(volume.reservation) }
        let instance: any WorkspaceProductRuntime
        do { instance = try factory() } catch { failure = String(describing: error); throw error }
        instance.onStatus = { [weak self] in guard let self else { throw WorkspaceControlError.transition }; try self.observe($0) }
        instance.onChange = { [weak self] in self?.scheduleUpdate() }
        try store.commit { state in
            if let current = state.current, !state.retained.contains(current) { state.retained.append(current) }
            state.current = nil
            state.execution = WorkspaceExecution(hostBoot: hostBoot, boot: instance.bootID)
            // Fresh boot requests fresh initial authorization for a new MountID.
            // Desired availability, key/scope (in guest) and old evidence survive.
            for index in state.volumes.indices { state.volumes[index].lastJob = 0; state.volumes[index].request = nil; state.volumes[index].authorizationConsumed = false; state.volumes[index].operation = "identity" }
        }
        runtime = instance
        do { try instance.start() }
        catch { failure=String(describing:error);scheduleUpdate();throw error }
        withExtendedLifetime(transition) {}
    }
    private func remove(_ volume: String, force: Bool) throws {
        guard let index = store.value.volumes.firstIndex(where: { $0.connection.volumeId == volume }) else { throw WorkspaceVMError("unknown workspace volume") }
        let old = store.value.volumes[index]
        if runtime == nil {
            try store.requirePriorExecutionAbsent(hostBoot: hostBoot)
            try forget(old); return
        }
        guard !inFlight.contains(volume) else { throw WorkspaceVMError("workspace operation is pending") }
        if !old.authorizationConsumed { try forget(old); return }
        guard let mount = try old.request?.guestIdentity().mount else { throw WorkspaceVMError("workspace operation is pending") }
        try store.commit { $0.volumes[index].operation = force ? "force-umount" : "umount"; $0.volumes[index].message = "pending" }
        dispatchUmount(volume: old, mount: mount, force: force)
    }
    private func dispatchUmount(volume: WorkspaceDesiredVolume, mount: WorkspaceMountID, force: Bool) {
        guard let runtime, !inFlight.contains(volume.connection.volumeId) else { return }
        let name = volume.connection.volumeId; inFlight.insert(name)
        runtime.umount(mount, force: force) { [weak self] result in
            guard let self else { return }; self.inFlight.remove(name)
            if case .failure = result { self.failVolume(name, message: "Cleanup required") }
            else if case .success(let accepted) = result, accepted.code != "accepted" { self.failVolume(name, message: "Cleanup required") }
            self.scheduleUpdate()
        }
    }
    private func scheduleUpdate() {
        guard !updateQueued else { return }; updateQueued = true
        DispatchQueue.main.async { [weak self] in self?.updateQueued = false; self?.update() }
    }
    private func update() {
        do {
            if let runtime, runtime.phase == .stopped {
                try store.commit { state in
                    if let raw=state.current, let frame=try? WorkspaceControl.decode(raw), !frame.statusReply.mounts.isEmpty, !state.retained.contains(raw) {
                        guard state.retained.count < 128 else { throw WorkspaceVMError("workspace evidence capacity reached") }
                        state.retained.append(raw)
                    }
                    state.current=nil; state.execution=nil
                    if stopRequested { state.running=false }
                }
                self.runtime = nil; latest = nil; inFlight.removeAll(); authorizations.removeAll()
                try releaseAbsentReservations()
                if stopRequested { try store.commit { $0.running = false }; stopRequested = false }
                else if failure.isEmpty { failure = runtime.failureMessage.isEmpty ? "Cleanup required" : runtime.failureMessage }
                return
            }
            if stopRequested {
                if runtime == nil {
                    try store.requirePriorExecutionAbsent(hostBoot: hostBoot)
                    try releaseAbsentReservations(); try store.commit { $0.running = false }; stopRequested = false; return
                }
                if stopForce { return }
                guard let runtime, runtime.ready, runtime.phase == .running, inFlight.isEmpty else { return }
                let registered = latest?.mounts ?? []
                if let mounted = registered.first(where: { $0.cleanup != "complete" }),
                   let volume = store.value.volumes.first(where: { $0.connection.volumeId == mounted.mount.volumeID }) {
                    if volume.message == WorkspaceHostControl.busy { stopRequested = false; return }
                    if !["umount", "force-umount"].contains(volume.operation) {
                        if let index = store.value.volumes.firstIndex(where: { $0.intent == volume.intent }) { try store.commit { $0.volumes[index].operation = "umount" } }
                        dispatchUmount(volume: volume, mount: mounted.mount, force: false)
                    }
                    return
                }
                guard !(latest?.jobs.contains { $0.phase == "offered" || $0.phase == "running" } ?? false) else { return }
                guard !shutdownIssued else { return }; shutdownIssued = true
                runtime.stop(force: false) { [weak self] result in
                    guard let self else { return }; self.shutdownIssued = false
                    if case .failure = result { self.stopRequested = false; self.failure = "Workspace is still running: orderly shutdown failed" }
                    self.scheduleUpdate()
                }; return
            }
            guard let runtime, runtime.ready else { return }
            for volume in store.value.volumes where !inFlight.contains(volume.connection.volumeId) {
                let name = volume.connection.volumeId
                switch volume.operation {
                case "identity":
                    guard runtime.phase == .running else { continue }
                    var request = WorkspaceIdentityRequest(); request.volumeID = name
                    request.authorityID = Data(stride(from: 0, to: volume.connection.authority.count, by: 2).compactMap { offset in UInt8(volume.connection.authority.dropFirst(offset).prefix(2), radix: 16) })
                    inFlight.insert(name)
                    runtime.identity(request) { [weak self] result in
                        guard let self else { return }; self.inFlight.remove(name)
                        do {
                            let identity = try result.get()
                            let document = try WorkspaceConnectionDocument(connection: volume.connection, intent: volume.intent, identity: identity)
                            try document.validate()
                            _ = try self.store.saveRequest(document)
                            try self.changeVolume(volume) { $0.request = document; $0.operation = "authorization-required"; $0.message = WorkspaceHostControl.authorizationRequired }
                        } catch { self.failVolume(name, message: "Authorization required") }
                        self.scheduleUpdate()
                    }
                case "provision":
                    guard runtime.phase == .running, let provision = authorizations.removeValue(forKey: name) else { continue }
                    inFlight.insert(name)
                    runtime.provision(provision) { [weak self] result in
                        guard let self else { return }; self.inFlight.remove(name)
                        if case .failure = result { self.failVolume(name, message: "Authorization required") }
                        else if case .success(let accepted) = result, accepted.code != "accepted" { self.failVolume(name, message: "Authorization required") }
                    }
                case "mount":
                    guard let mount = try volume.request?.guestIdentity().mount else { continue }
                    // The coordinator, including its existing power-transition
                    // queue, owns this pending Mount through final observation.
                    try changeVolume(volume) { $0.operation = "mount-pending" }
                    inFlight.insert(name)
                    runtime.mount(mount) { [weak self] result in
                        guard let self else { return }; self.inFlight.remove(name)
                        if case .failure = result { self.failVolume(name, message: "Cleanup required") }
                        else if case .success(let accepted) = result, accepted.code != "accepted" { self.failVolume(name, message: "Authorization required") }
                    }
                default: break
                }
            }
        } catch { failure = String(describing: error) }
    }
    private func observe(_ status: WorkspaceStatusReply) throws {
        var frame = WorkspaceEnvelope(); frame.version = 8; frame.requestID = 1; frame.statusReply = status
        let raw = try WorkspaceControl.encode(frame)
        // Keep one current snapshot and all exact retired outcomes before ack.
        // Each retained page is deduplicated; capacity refuses instead of
        // silently losing an unobserved write outcome.
        try store.commit { state in
            state.current = raw
            for retired in status.retired {
                var page = status; page.mounts = []; page.jobs = []; page.retired = [retired]
                var envelope = frame; envelope.statusReply = page
                let evidence = try WorkspaceControl.encode(envelope)
                if !state.retained.contains(evidence) {
                    guard state.retained.count < 128 else { throw WorkspaceVMError("workspace evidence capacity reached") }
                    state.retained.append(evidence)
                }
            }
        }
        latest = status
        let jobs = status.jobs + status.retired.filter(\.hasJob).map(\.job)
        for volume in store.value.volumes {
            guard let identity = try volume.request?.guestIdentity(),
                  let job = jobs.last(where: { $0.mount == identity.mount && $0.requestID > volume.lastJob && $0.phase != "offered" && $0.phase != "running" }) else { continue }
            try changeVolume(volume) { $0.lastJob = job.requestID }
            if job.phase == "failed" {
                if job.operation == "umount" && job.failure == "busy" {
                    try changeVolume(volume) { $0.operation = "ready"; $0.message = WorkspaceHostControl.busy }
                    if stopRequested { stopRequested = false; failure = WorkspaceHostControl.busy }
                } else { try changeVolume(volume) { $0.operation = "terminal"; $0.message = job.failure == "authorization-required" ? WorkspaceHostControl.authorizationRequired : "Cleanup required" } }
            } else if job.operation == "provision", volume.operation == "provision" {
                try changeVolume(volume) { $0.operation = "mount"; $0.message = "pending" }
            } else if job.operation == "mount", volume.operation == "mount-pending" {
                try changeVolume(volume) { $0.operation = "ready"; $0.message = "" }
            } else if job.operation == "umount", ["umount", "force-umount"].contains(volume.operation) {
                guard !status.mounts.contains(where: { $0.mount == identity.mount && $0.cleanup != "complete" }) else { continue }
                if stopRequested { try changeVolume(volume) { $0.operation = "identity"; $0.request = nil; $0.authorizationConsumed = false } }
                else { try forget(volume) }
            }
        }
        for volume in store.value.volumes where !["umount", "force-umount", "identity"].contains(volume.operation) {
            guard let identity = try volume.request?.guestIdentity(), let terminal = (status.mounts + status.retired.filter(\.hasMountStatus).map(\.mountStatus)).first(where: { $0.mount == identity.mount && ["terminal", "authorization-required"].contains($0.state) }) else { continue }
            try changeVolume(volume) { $0.operation = "terminal"; $0.reopenRequired = true; $0.message = terminal.state == "authorization-required" ? WorkspaceHostControl.authorizationRequired : "Reconnect your editor and reopen this folder." }
        }
        scheduleUpdate()
    }
    private func changeVolume(_ volume: WorkspaceDesiredVolume, update: (inout WorkspaceDesiredVolume) -> Void) throws {
        try store.commit { state in
            guard let index = state.volumes.firstIndex(where: { $0.intent == volume.intent }) else { throw WorkspaceControlError.transition }
            update(&state.volumes[index])
        }
    }
    private func failVolume(_ name: String, message: String) {
        guard let volume = store.value.volumes.first(where: { $0.connection.volumeId == name }) else { return }
        do { try changeVolume(volume) { $0.operation = "terminal"; $0.message = message } }
        catch { failure = String(describing: error) }
    }
    private func forget(_ volume: WorkspaceDesiredVolume) throws {
        let transition = try WorkspaceReservations(directory: reservationDirectory)
        let owned=transition.inventory.filter { $0.frontend == "workspace" && $0.authority == volume.connection.authority && $0.volume == volume.connection.volumeId }
        guard owned.isEmpty || owned == [volume.reservation] else { throw WorkspaceVMError("Cleanup required") }
        try store.commit { $0.volumes.removeAll { $0.intent == volume.intent } }
        if !owned.isEmpty { try transition.release(volume.reservation) }
    }
    private func releaseAbsentReservations() throws {
        guard store.value.execution == nil else { throw WorkspaceVMError("VM termination unconfirmed") }
        let transition = try WorkspaceReservations(directory: reservationDirectory)
        for entry in transition.inventory where entry.frontend == "workspace" { try transition.release(entry) }
    }
    // Lifecycle v1 is independent of the paired operational version. Quiesce
    // closes this serving execution's admission only after exact VM absence;
    // the installer must still unregister and prove singleton release.
    public func lifecycle(_ request: WorkspaceHostLifecycleRequest) throws -> WorkspaceHostLifecycleReply {
        try request.validate()
        var reply=WorkspaceHostLifecycleReply()
        reply.executionPresent=runtime != nil || store.value.execution != nil
        reply.desiredRunning=store.value.running
        if request.operation == "quiesce" {
            guard !reply.executionPresent, !store.value.running, inFlight.isEmpty else { reply.state="busy";return reply }
            try releaseAbsentReservations();quiescing=true;reply.state="quiesced"
        } else { reply.state=request.operation }
        return reply
    }
    public func snapshot() -> WorkspaceHostReply {
        var result = WorkspaceHostReply(); result.desiredRunning = store.value.running; result.retainedEvidence=store.value.retained
        if !failure.isEmpty { result.state = "cleanup-required"; result.message = failure }
        else if runtime == nil, store.value.execution != nil { result.state="cleanup-required";result.message="Cleanup required" }
        else if let runtime {
            if [.unknown,.pausedDiscard].contains(runtime.phase) { result.state = "cleanup-required"; result.message = runtime.failureMessage.isEmpty ? "Cleanup required" : runtime.failureMessage }
            else if stopRequested || runtime.phase == .stopping { result.state = "pending"; result.message = "Stop Linux Workspace" }
            else if runtime.ready, runtime.phase == .running { result.state = "running"; result.message = WorkspaceHostControl.running }
            else if [.draining, .pausing, .pausedCold, .resuming, .recovering].contains(runtime.phase) { result.state = "reconnecting"; result.message = "Reconnecting…" }
            else { result.state = "starting"; result.message = WorkspaceHostControl.starting }
        }
        for evidence in store.value.retained {
            guard let frame = try? WorkspaceControl.decode(evidence) else { continue }
            let statuses = frame.statusReply.mounts + frame.statusReply.retired.filter(\.hasMountStatus).map(\.mountStatus)
            result.someChangesWereNotSaved = result.someChangesWereNotSaved || statuses.contains { !$0.loss.isEmpty || $0.outcome.durability == "lost" }
            result.previousWriteOutcomeUnknown = result.previousWriteOutcomeUnknown || statuses.contains { $0.outcome.observation == "unobserved" }
        }
        for desired in store.value.volumes {
            let state: String
            if desired.message == WorkspaceHostControl.busy { state = "busy" }
            else if desired.operation == "authorization-required" || desired.operation == "identity" { state = "authorization-required" }
            else if desired.operation == "ready" { state = "ready" }
            else if desired.operation == "terminal" { state = "terminal" }
            else { state = "pending" }
            var volume = WorkspaceHostVolume(volume: desired.connection.volumeId, state: state, message: desired.message)
            if let runtime, runtime.phase != .running, state == "ready" { volume.state = "pending"; volume.message = "Reconnecting…" }
            if let current = latest?.mounts.first(where: { $0.mount.volumeID == volume.volumeId }) {
                if ["recovering", "closed", "suspended-cold"].contains(current.state), state != "busy" { volume.state = "pending"; volume.message = "Reconnecting…" }
                if current.state == "terminal" { volume.state = "terminal"; volume.message = "Reconnect your editor and reopen this folder." }
                if current.state == "authorization-required" { volume.state = "authorization-required"; volume.message = WorkspaceHostControl.authorizationRequired }
            }
            if volume.state == "ready", desired.reopenRequired { volume.message = "Reconnect your editor and reopen this folder." }
            if runtime == nil, store.value.execution == nil { volume.state="stopped";volume.message="Linux Workspace: Stopped" }
            if desired.request != nil { volume.authorizationRequest = store.directory.url.appendingPathComponent("authorization-" + desired.connection.volumeId + ".pfsworkspace").path }
            if let latest {
                var page = latest; page.mounts = page.mounts.filter { $0.mount.volumeID == volume.volumeId }; page.jobs = page.jobs.filter { $0.mount.volumeID == volume.volumeId }
                page.retired = page.retired.filter { $0.mountStatus.mount.volumeID == volume.volumeId || $0.job.mount.volumeID == volume.volumeId }
                var envelope = WorkspaceEnvelope(); envelope.version = 8; envelope.requestID = 1; envelope.statusReply = page
                volume.evidence = try? WorkspaceControl.encode(envelope)
            }
            result.volumes.append(volume)
        }
        return result
    }
}
