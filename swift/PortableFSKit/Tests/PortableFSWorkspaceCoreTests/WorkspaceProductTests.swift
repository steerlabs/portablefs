import Foundation
import Testing
import PortableFSWorkspaceCore
@testable import PortableFSWorkspaceVM
@testable import PortableFSAppCore

private enum ProductFailure: Error { case refused }
@MainActor private final class ProductRuntime: WorkspaceProductRuntime {
    var phase: WorkspacePhase = .starting
    var ready = false
    var bootID = Data(repeating: 8, count: 16)
    var onChange: (() -> Void)?
    var onStatus: ((WorkspaceStatusReply) throws -> Void)?
    var starts = 0
    var startFails = false
    var identityCalls = 0
    var mounts = 0
    var umounts: [Bool] = []
    var stops: [Bool] = []
    var shutdownFails = false
    var identityReply: WorkspaceIdentityReply
    var provisions: [WorkspaceProvision] = []
    init() throws { identityReply = try WorkspaceControl.decode(workspaceGolden("identity_reply")).identityReply }
    func start() throws { starts += 1; if startFails { phase = .stopped; throw ProductFailure.refused } }
    func running() { ready = true; phase = .running; onChange?() }
    func identity(_ request: WorkspaceIdentityRequest, completion: @escaping (Result<WorkspaceIdentityReply, Error>) -> Void) {
        identityCalls += 1; identityReply.mount.authorityID = request.authorityID; identityReply.mount.volumeID = request.volumeID
        completion(.success(identityReply))
    }
    func provision(_ provision: WorkspaceProvision, completion: @escaping (Result<WorkspaceResult, Error>) -> Void) { provisions.append(provision); var result = WorkspaceResult(); result.code = "accepted"; completion(.success(result)) }
    func mount(_ mount: WorkspaceMountID, completion: @escaping (Result<WorkspaceResult, Error>) -> Void) { mounts += 1; var result = WorkspaceResult(); result.code = "accepted"; completion(.success(result)) }
    func umount(_ mount: WorkspaceMountID, force: Bool, completion: @escaping (Result<WorkspaceResult, Error>) -> Void) { umounts.append(force); var result = WorkspaceResult(); result.code = "accepted"; completion(.success(result)) }
    func stop(force: Bool, completion: @escaping (Result<Void, Error>) -> Void) {
        stops.append(force)
        if shutdownFails { completion(.failure(ProductFailure.refused)) }
        else { ready = false; phase = .stopped; completion(.success(())); onChange?() }
    }
    func report(_ job: WorkspaceMountJob, mounted: Bool = false) throws {
        var status = WorkspaceStatusReply(); status.bootID = bootID; status.hostServiceID = Data(repeating: 6, count: 16); status.guestServiceID = Data(repeating: 7, count: 16); status.state = "running"
        if mounted { var mount = WorkspaceMountStatus(); mount.mount = job.mount; mount.state = "ready"; mount.cleanup = "retained"; mount.renewal.state = "not-required"; mount.outcome = unknownTestOutcome(); status.mounts = [mount] }
        status.jobs = [job]; try onStatus?(status)
    }
}
private func productDirectory() throws -> URL {
    let path = FileManager.default.temporaryDirectory.resolvingSymlinksInPath().appendingPathComponent("pfs-product-" + UUID().uuidString)
    try FileManager.default.createDirectory(at: path, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700]); return path
}
private func productRequest(_ operation: String, volume: String? = nil, force: Bool? = nil) throws -> WorkspaceHostRequest {
    var value: [String: Any] = ["version": 1, "operation": operation]
    if let volume { value["volumeId"] = volume }; if let force { value["force"] = force }
    return try WorkspaceHostControl.decodeRequest(JSONSerialization.data(withJSONObject: value))
}
private func productConnection() throws -> WorkspaceConnectionDocument {
    let value: [String: Any] = ["version":1, "kind":"connection", "connection":["authority":try WorkspaceHostControl.authorityIdentity("authority.example"), "volumeId":"vol-1", "endpoint":"authority.example:7443", "serverName":"authority.example", "caCertificate":Data("test public CA".utf8).base64EncodedString(), "routesRevision":Data(repeating:4,count:32).base64EncodedString(), "hosted":false]]
    let raw = try JSONSerialization.data(withJSONObject:value)
    return try JSONDecoder().decode(WorkspaceConnectionDocument.self,from:raw)
}
private func productMount(_ document: WorkspaceConnectionDocument) throws -> WorkspaceHostRequest {
    let encoded = try WorkspaceHostControl.encode(document)
    let value: [String: Any] = ["version":1, "operation":"mount", "document":try JSONSerialization.jsonObject(with:encoded)]
    return try WorkspaceHostControl.decodeRequest(JSONSerialization.data(withJSONObject:value))
}
@MainActor private func productTurn() async throws { try await Task.sleep(for:.milliseconds(30)) }

@Suite(.serialized) struct WorkspaceProductTests {
    @Test @MainActor func startupIsIdempotentAndStopPersistsWithoutAppOwnership() async throws {
        let directory = try productDirectory(); defer { try? FileManager.default.removeItem(at:directory) }
        let store = try WorkspaceHostState(directory:directory.appendingPathComponent("workspace")), runtime = try ProductRuntime()
        let owner = WorkspaceProductOwner(store:store,reservationDirectory:directory,hostBoot:"host-boot") { _ in runtime }
        #expect(owner.handle(try productRequest("status")).desiredRunning == false)
        #expect(runtime.starts == 0)
        _ = owner.handle(try productRequest("start")); _ = owner.handle(try productRequest("start"))
        #expect(runtime.starts == 1); #expect(store.value.running)
        runtime.running(); try await productTurn()
        // Dropping every API request leaves the independent owner running.
        #expect(owner.snapshot().state == "running"); #expect(runtime.stops.isEmpty)
        _ = owner.handle(try productRequest("stop")); try await productTurn(); try await productTurn()
        #expect(runtime.stops == [false]); #expect(!store.value.running); #expect(store.value.execution == nil)
        #expect(owner.snapshot().state == "stopped")
        let onDisk = try #require(try store.directory.read("desired.json"))
        #expect(try JSONDecoder().decode(WorkspaceDesiredState.self,from:onDisk).running == false)
        owner.launch(); #expect(runtime.starts == 1)
    }
    @Test @MainActor func crashWitnessNeverAdoptsRAMOrTreatsPIDExitAsTermination() throws {
        for lost in [false, true] {
            let directory = try productDirectory(); defer { try? FileManager.default.removeItem(at:directory) }
            let store = try WorkspaceHostState(directory:directory)
            var reference: WorkspaceFileLock? = try store.directory.lock("owner.lock")
            guard let identity = reference?.identity else { throw ProductFailure.refused }
            var old = try WorkspaceControl.decode(workspaceGolden("status_reply"))
            try #require(!old.statusReply.mounts.isEmpty)
            old.statusReply.mounts = [old.statusReply.mounts[0]]
            old.statusReply.retired = []; old.statusReply.jobs = []
            old.statusReply.mounts[0].outcome = unknownTestOutcome()
            old.statusReply.mounts[0].loss = []
            if lost {
                var loss = WorkspaceLoss(); loss.sequence = 1; loss.acceptedEntries = 1; loss.acceptedBytes = 4096; loss.reason = "accepted old tail lost"
                old.statusReply.mounts[0].loss = [loss]
                old.statusReply.mounts[0].state = "terminal"; old.statusReply.mounts[0].reason = loss.reason
                old.statusReply.mounts[0].outcome.durability = "lost"; old.statusReply.mounts[0].outcome.observation = "observed"; old.statusReply.mounts[0].outcome.release = "abandoned"
            }
            let evidence = try WorkspaceControl.encode(old)
            try store.commit { $0.running = true; $0.execution = WorkspaceExecution(hostBoot:"same-boot",boot:Data(repeating:1,count:16),reference:identity); $0.current = evidence }
            let runtime = try ProductRuntime()
            let owner = WorkspaceProductOwner(store:store,reservationDirectory:directory,hostBoot:"same-boot") { _ in runtime }
            let start = try productRequest("start")
            withExtendedLifetime(reference) {
                owner.launch(); #expect(runtime.starts == 0); #expect(owner.snapshot().state == "cleanup-required")
                #expect(owner.handle(start).state == "refused"); #expect(runtime.starts == 0)
                #expect(throws:(any Error).self) { try store.requirePriorExecutionAbsent(hostBoot:"same-boot") }
            }
            reference = nil
            #expect(owner.handle(try productRequest("start")).state == "starting")
            #expect(runtime.starts == 1); #expect(store.value.execution?.boot == runtime.bootID)
            #expect(store.value.execution?.boot != Data(repeating:1,count:16))
            #expect(!store.value.retained.isEmpty); #expect(owner.snapshot().previousWriteOutcomeUnknown); #expect(owner.snapshot().someChangesWereNotSaved == lost)
        }
    }
    @Test func descriptorPassedLockSurvivesOriginalOwnerRetirement() throws {
        let directory = try productDirectory(); defer { try? FileManager.default.removeItem(at:directory) }
        let state = try WorkspacePrivateDirectory(directory)
        var reference: WorkspaceFileLock? = try state.lock("owner.lock")
        guard let identity = reference?.identity, let descriptor = reference?.fileHandle.fileDescriptor else { throw ProductFailure.refused }
        // Process duplicates this descriptor onto the child's stdin. This
        // borrowed wrapper must not keep the original description alive.
        let borrowed = FileHandle(fileDescriptor: descriptor, closeOnDealloc:false)
        let child = Process(), output = Pipe()
        child.executableURL = URL(fileURLWithPath:"/usr/bin/python3")
        child.arguments = ["-c", "import os,signal; os.fstat(0); print('holding',flush=True); signal.pause()"]
        child.standardInput = borrowed; child.standardOutput = output; child.standardError = FileHandle.nullDevice
        try child.run()
        defer { if child.isRunning { child.terminate(); child.waitUntilExit() } }
        #expect(try output.fileHandleForReading.read(upToCount:8) == Data("holding\n".utf8))
        withExtendedLifetime(reference) {}
        reference = nil
        #expect(throws:(any Error).self) { try state.lock("owner.lock") }
        child.terminate(); child.waitUntilExit()
        let successor = try state.lock("owner.lock")
        #expect(successor.identity == identity)
    }
    @Test func replacedExecutionLockCannotProveSameBootAbsence() throws {
        let directory = try productDirectory(); defer { try? FileManager.default.removeItem(at:directory) }
        let store = try WorkspaceHostState(directory:directory)
        let reference = try store.directory.lock("owner.lock")
        try store.commit { $0.execution = WorkspaceExecution(hostBoot:"same-boot",boot:Data(repeating:1,count:16),reference:reference.identity) }
        try store.directory.remove("owner.lock")
        #expect(throws:(any Error).self) { try store.requirePriorExecutionAbsent(hostBoot:"same-boot") }
        #expect(store.value.execution != nil)
        withExtendedLifetime(reference) {}
    }
    @Test func desiredStateRequiresDescriptorWitnessFormat() throws {
        let directory = try productDirectory(); defer { try? FileManager.default.removeItem(at:directory) }
        let state = try WorkspacePrivateDirectory(directory)
        var unequal = WorkspaceDesiredState(); unequal.version = 1
        try state.write("desired.json",data:WorkspaceHostControl.encode(unequal))
        #expect(throws:(any Error).self) { try WorkspaceHostState(directory:directory) }
    }
    @Test func workspaceStateRetainsTransferredOwnerLock() throws {
        let directory = try productDirectory(); defer { try? FileManager.default.removeItem(at:directory) }
        let privateDirectory = try WorkspacePrivateDirectory(directory)
        var reference: WorkspaceFileLock? = try privateDirectory.lock("owner.lock")
        var state: WorkspaceState? = try WorkspaceState(directory:directory,ownership:reference)
        reference = nil
        #expect(throws:(any Error).self) { try privateDirectory.lock("owner.lock") }
        withExtendedLifetime(state) {}
        state = nil
        let successor = try privateDirectory.lock("owner.lock")
        withExtendedLifetime(successor) {}
    }
    @Test func workspaceStateRejectsForeignOwnershipBeforeDiskCreation() throws {
        let first = try productDirectory(), second = try productDirectory()
        defer { try? FileManager.default.removeItem(at:first); try? FileManager.default.removeItem(at:second) }
        let owner = try WorkspacePrivateDirectory(first).lock("owner.lock")
        #expect(throws:(any Error).self) { try WorkspaceState(directory:second,ownership:owner) }
        #expect(!FileManager.default.fileExists(atPath:second.appendingPathComponent("data.ext4").path))
        withExtendedLifetime(owner) {}
    }
    @Test @MainActor func statusPollingRetainsSetupRefusalUntilAnExplicitRetry() throws {
        let directory = try productDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
        let store = try WorkspaceHostState(directory: directory.appendingPathComponent("workspace"))
        let owner = WorkspaceProductOwner(store: store, reservationDirectory: directory, hostBoot: "host-boot") { _ in
            throw WorkspaceVMError("SSH name already in use")
        }
        #expect(owner.handle(try productRequest("start")).message == "SSH name already in use")
        for _ in 0..<3 {
            let status = owner.handle(try productRequest("status"))
            #expect(status.state == "cleanup-required"); #expect(status.message == "SSH name already in use")
        }
    }
    @Test @MainActor func pendingMountKeepsIntentAcrossTransitionAndRequiresExactResponse() async throws {
        let directory = try productDirectory(); defer { try? FileManager.default.removeItem(at:directory) }
        let store = try WorkspaceHostState(directory:directory.appendingPathComponent("workspace")), runtime = try ProductRuntime()
        let owner = WorkspaceProductOwner(store:store,reservationDirectory:directory,hostBoot:"host-boot") { _ in runtime }
        _ = owner.handle(try productMount(productConnection()))
        #expect(store.value.volumes.count == 1); #expect(runtime.identityCalls == 0)
        runtime.running(); try await productTurn()
        let request = try #require(store.value.volumes.first?.request)
        #expect(owner.snapshot().volumes.first?.state == "authorization-required")
        #expect(try store.directory.read("authorization-vol-1.pfsworkspace") != nil)
        var provision = try WorkspaceControl.decode(workspaceGolden("provision")).provision
        provision.mount = try request.guestIdentity().mount; provision.publicKey = try request.guestIdentity().publicKey
        provision.authorityEndpoint = request.connection.endpoint; provision.serverName = request.connection.serverName; provision.caCertificate = request.connection.caCertificate; provision.routesRevision = request.connection.routesRevision
        var frame = WorkspaceEnvelope(); frame.version = 8; frame.requestID = 1; frame.provision = provision
        var response = request; response.kind = "authorization"; response.authorization = try WorkspaceControl.encode(frame)
        var foreign = response; foreign.intent = String(repeating:"2",count:32)
        #expect(owner.handle(try productMount(foreign)).state == "refused"); #expect(runtime.provisions.isEmpty)
        runtime.phase = .pausedCold
        _ = owner.handle(try productMount(response)); try await productTurn()
        #expect(runtime.provisions.isEmpty); #expect(store.value.volumes[0].authorizationConsumed)
        runtime.phase = .running; runtime.onChange?(); try await productTurn()
        #expect(runtime.provisions.count == 1)
        var job = WorkspaceMountJob(); job.mount = provision.mount; job.requestID = 4; job.operation = "provision"; job.phase = "complete"
        runtime.phase = .pausedCold; try runtime.report(job); try await productTurn()
        // The existing coordinator queue receives the mount even while paused.
        #expect(runtime.mounts == 1)
        _ = owner.handle(try productMount(response)); try await productTurn(); #expect(runtime.provisions.count == 1); #expect(runtime.mounts == 1)
    }
    @Test @MainActor func busyUnmountRetainsServingReservationAndStopNeverForces() async throws {
        let directory = try productDirectory(); defer { try? FileManager.default.removeItem(at:directory) }
        let store = try WorkspaceHostState(directory:directory.appendingPathComponent("workspace")), runtime = try ProductRuntime()
        let owner = WorkspaceProductOwner(store:store,reservationDirectory:directory,hostBoot:"host-boot") { _ in runtime }
        _ = owner.handle(try productMount(productConnection())); runtime.running(); try await productTurn()
        let request = try #require(store.value.volumes.first?.request), mount = try request.guestIdentity().mount
        var job = WorkspaceMountJob(); job.mount = mount; job.requestID = 2; job.operation = "mount"; job.phase = "complete"
        try runtime.report(job,mounted:true)
        try store.commit { $0.volumes[0].authorizationConsumed = true }
        _ = owner.handle(try productRequest("umount",volume:"vol-1")); #expect(runtime.umounts == [false])
        job.requestID = 3; job.operation = "umount"; job.phase = "failed"; job.failure = "busy"; job.reason = "kernel EBUSY"
        try runtime.report(job,mounted:true); try await productTurn()
        #expect(owner.snapshot().volumes[0].message == WorkspaceHostControl.busy)
        do { let transition = try WorkspaceReservations(directory:directory); #expect(transition.inventory.count == 1) }
        _ = owner.handle(try productRequest("stop")); try await productTurn()
        #expect(runtime.stops.isEmpty); #expect(store.value.running)
        _ = owner.handle(try productRequest("umount",volume:"vol-1",force:true)); #expect(runtime.umounts == [false,true])
        // Re-observing an old busy result cannot consume the new force intent.
        try runtime.report(job,mounted:true)
        #expect(store.value.volumes[0].operation == "force-umount")
    }
    @Test @MainActor func failedOrderlyShutdownLeavesRunningIntentAndVM() async throws {
        let directory = try productDirectory(); defer { try? FileManager.default.removeItem(at:directory) }
        let store = try WorkspaceHostState(directory:directory.appendingPathComponent("workspace")), runtime = try ProductRuntime(); runtime.shutdownFails = true
        let owner = WorkspaceProductOwner(store:store,reservationDirectory:directory,hostBoot:"host-boot") { _ in runtime }
        _ = owner.handle(try productRequest("start")); runtime.running(); try await productTurn()
        _ = owner.handle(try productRequest("stop")); try await productTurn()
        #expect(runtime.stops == [false]); #expect(store.value.running); #expect(store.value.execution != nil); #expect(runtime.phase == .running)
    }
    @Test func reservationCodecBothOrdersAndCanonicalTransitionLock() throws {
        let directory = try productDirectory(); defer { try? FileManager.default.removeItem(at:directory) }
        let authority = try WorkspaceHostControl.authorityIdentity("AUTHORITY.example.")
        #expect(authority == (try WorkspaceHostControl.authorityIdentity("authority.example")))
        let mac = WorkspaceReservation(authority:authority,volume:"vol-1",frontend:"fskit",owner:"mac-ref")
        let linux = WorkspaceReservation(authority:authority,volume:"vol-1",owner:"linux-intent")
        do { let transition = try WorkspaceReservations(directory:directory); try transition.reserve(mac)
            #expect(throws:(any Error).self) { try transition.reserve(linux) }
            #expect(throws:(any Error).self) { try WorkspaceReservations(directory:directory) }
        }
        do { let transition = try WorkspaceReservations(directory:directory); #expect(transition.inventory == [mac]); try transition.release(mac); try transition.reserve(linux)
            #expect(throws:(any Error).self) { try transition.reserve(mac) }
        }
        #expect(!FileManager.default.fileExists(atPath:directory.appendingPathComponent("workspace").path))
    }
    @Test func privateStateRefusesSingletonAndReplacedOrCorruptInventory() throws {
        let directory = try productDirectory(); defer { try? FileManager.default.removeItem(at:directory) }
        let state = try WorkspaceHostState(directory:directory)
        #expect(throws:(any Error).self) { try WorkspaceHostState(directory:directory) }
        try state.directory.write("volume-reservations.json",data:Data("{\"version\":2,\"reservations\":[]}".utf8))
        #expect(throws:(any Error).self) { try WorkspaceReservations(directory:directory) }
    }
    @Test func hostAPIRejectsUnknownDuplicateCrossVersionAndExtraVerbs() throws {
        for raw in ["{\"version\":1,\"version\":1,\"operation\":\"status\"}","{\"version\":8,\"operation\":\"status\"}","{\"version\":1,\"operation\":\"status\",\"secret\":\"x\"}"] {
            #expect(throws:(any Error).self) { try WorkspaceHostControl.decodeRequest(Data(raw.utf8)) }
        }
        for verb in ["shell","exec","pause","resume","identity","vm-list","ssh-config"] { #expect(throws:(any Error).self) { try productRequest(verb) } }
    }
}

@Suite(.serialized) struct WorkspaceProductRecoveryTests {
    @Test @MainActor func issuerOutageRetainsPublicRequestAndPendingAuthorizationCanBeRemoved() async throws {
        let directory = try productDirectory(); defer { try? FileManager.default.removeItem(at:directory) }
        let store = try WorkspaceHostState(directory:directory.appendingPathComponent("workspace")), runtime = try ProductRuntime()
        let owner = WorkspaceProductOwner(store:store,reservationDirectory:directory,hostBoot:"host-boot") { _ in runtime }
        _ = owner.handle(try productMount(productConnection())); runtime.running(); try await productTurn()
        let before = try #require(store.value.volumes.first?.request)
        for _ in 0..<10 { _ = owner.handle(try productRequest("status")) }
        _ = owner.handle(try productMount(productConnection())); try await productTurn()
        #expect(runtime.identityCalls == 1); #expect(runtime.provisions.isEmpty)
        #expect(store.value.volumes.first?.request == before)
        _ = owner.handle(try productRequest("umount",volume:"vol-1"))
        #expect(store.value.volumes.isEmpty); #expect(runtime.umounts.isEmpty)
        let transition = try WorkspaceReservations(directory:directory)
        #expect(transition.inventory.isEmpty)
    }
    @Test @MainActor func terminalCleanupAllowsFreshRequestAndKeepsKnownAndUnknownLoss() async throws {
        let directory = try productDirectory(); defer { try? FileManager.default.removeItem(at:directory) }
        let store = try WorkspaceHostState(directory:directory.appendingPathComponent("workspace")), runtime = try ProductRuntime()
        let owner = WorkspaceProductOwner(store:store,reservationDirectory:directory,hostBoot:"host-boot") { _ in runtime }
        _ = owner.handle(try productMount(productConnection())); runtime.running(); try await productTurn()
        let old = try #require(store.value.volumes.first?.request)
        try store.commit { $0.volumes[0].authorizationConsumed=true; $0.volumes[0].operation="ready" }
        var terminal = WorkspaceMountStatus(); terminal.mount = try old.guestIdentity().mount
        terminal.state="terminal";terminal.reason="authorization ended";terminal.cleanup="retained";terminal.outcome=unknownTestOutcome()
        var loss=WorkspaceLoss();loss.sequence=1;loss.acceptedBytes=4096;loss.acceptedEntries=1;loss.reason="accepted tail lost";terminal.loss=[loss]
        var status=WorkspaceStatusReply();status.bootID=runtime.bootID;status.hostServiceID=Data(repeating:6,count:16);status.guestServiceID=Data(repeating:7,count:16);status.state="running";status.mounts=[terminal]
        try runtime.onStatus?(status)
        #expect(owner.handle(try productMount(productConnection())).state=="refused")
        terminal.cleanup="complete"
        var retired=WorkspaceRetiredOutcome();retired.retirementSequence=1;retired.mountStatus=terminal
        status.mounts=[];status.retired=[retired];try runtime.onStatus?(status)
        runtime.identityReply.mount.incarnation=Data(repeating:9,count:16)
        #expect(owner.handle(try productMount(productConnection())).state != "refused")
        try await productTurn()
        let fresh=try #require(store.value.volumes.first?.request)
        #expect(fresh.identity != old.identity)
        #expect(owner.snapshot().someChangesWereNotSaved)
        #expect(owner.snapshot().previousWriteOutcomeUnknown)
        #expect(store.value.volumes[0].reopenRequired)
    }
    @Test @MainActor func forceStopRetainsUnobservedPriorWriteOutcome() async throws {
        let directory=try productDirectory();defer{try? FileManager.default.removeItem(at:directory)}
        let store=try WorkspaceHostState(directory:directory.appendingPathComponent("workspace")),runtime=try ProductRuntime()
        let owner=WorkspaceProductOwner(store:store,reservationDirectory:directory,hostBoot:"host-boot"){ _ in runtime }
        _=owner.handle(try productMount(productConnection()));runtime.running();try await productTurn()
        let request=try #require(store.value.volumes.first?.request)
        var job=WorkspaceMountJob();job.mount=try request.guestIdentity().mount;job.requestID=2;job.operation="mount";job.phase="complete"
        try runtime.report(job,mounted:true)
        _=owner.handle(try productRequest("stop",force:true));try await productTurn()
        #expect(!store.value.running);#expect(store.value.execution==nil)
        #expect(owner.snapshot().previousWriteOutcomeUnknown)
    }
    @Test func authorityIPCanonicalizationMatchesGoNamespace() throws {
        #expect(try WorkspaceHostControl.authorityIdentity("2001:0db8:0:0::1") == WorkspaceHostControl.authorityIdentity("2001:db8::1"))
        #expect(try WorkspaceHostControl.authorityIdentity("::ffff:192.0.2.1") == WorkspaceHostControl.authorityIdentity("192.0.2.1"))
    }
}

@Test @MainActor func productLifecycleQuiescenceIsIdleOnlyAndIndependentOfOperationalVersion() throws {
    let directory=try productDirectory();defer{try? FileManager.default.removeItem(at:directory)}
    let store=try WorkspaceHostState(directory:directory.appendingPathComponent("workspace")),runtime=try ProductRuntime()
    let owner=WorkspaceProductOwner(store:store,reservationDirectory:directory,hostBoot:"host-boot"){ _ in runtime }
    let quiesce=try WorkspaceHostLifecycleRequest.decode(Data("{\"lifecycleVersion\":1,\"operation\":\"quiesce\"}".utf8))
    _=owner.handle(try productRequest("start"))
    #expect(try owner.lifecycle(quiesce).state=="busy")
    #expect(store.value.running)
    runtime.phase = .stopped
    // A separate idle owner with no execution can close its admission.
    let idleDirectory=try productDirectory();defer{try? FileManager.default.removeItem(at:idleDirectory)}
    let idleStore=try WorkspaceHostState(directory:idleDirectory.appendingPathComponent("workspace"))
    let idle=WorkspaceProductOwner(store:idleStore,reservationDirectory:idleDirectory,hostBoot:"host-boot"){ _ in runtime }
    #expect(try idle.lifecycle(quiesce).state=="quiesced")
    #expect(idle.handle(try productRequest("start")).state=="refused")
    #expect(!idleStore.value.running)
    #expect(throws:(any Error).self) { try WorkspaceHostLifecycleRequest.decode(Data("{\"lifecycleVersion\":2,\"operation\":\"identity\"}".utf8)) }
}

@Test @MainActor func productPowerRegistrationFailureRetiresOnlyTheNeverStartedInstance() async throws {
    let directory=try productDirectory();defer{try? FileManager.default.removeItem(at:directory)}
    let store=try WorkspaceHostState(directory:directory.appendingPathComponent("workspace"))
    let first=try ProductRuntime(),second=try ProductRuntime();first.startFails=true;second.bootID=Data(repeating:9,count:16)
    var creations=0
    let owner=WorkspaceProductOwner(store:store,reservationDirectory:directory,hostBoot:"host-boot"){ _ in creations+=1;return creations==1 ? first:second}
    #expect(owner.handle(try productRequest("start")).state=="refused")
    #expect(owner.handle(try productRequest("start")).state=="refused")
    try await productTurn()
    #expect(store.value.execution==nil)
    #expect(owner.handle(try productRequest("start")).state=="starting")
    #expect(creations==2);#expect(first.starts==1);#expect(second.starts==1)
    #expect(store.value.execution?.boot==second.bootID)
}

@Test @MainActor func productStopIntentPersistsBeforeContendedReservationCleanup() async throws {
    let directory=try productDirectory();defer{try? FileManager.default.removeItem(at:directory)}
    let store=try WorkspaceHostState(directory:directory.appendingPathComponent("workspace")),runtime=try ProductRuntime()
    let owner=WorkspaceProductOwner(store:store,reservationDirectory:directory,hostBoot:"host-boot"){ _ in runtime }
    _=owner.handle(try productMount(productConnection()));runtime.running();try await productTurn()
    do {
        let transition=try WorkspaceReservations(directory:directory)
        _=owner.handle(try productRequest("stop",force:true));try await productTurn()
        #expect(!store.value.running);#expect(store.value.execution==nil)
        #expect(owner.snapshot().volumes[0].state=="stopped")
        withExtendedLifetime(transition){}
    }
    _=owner.handle(try productRequest("status"));try await productTurn()
    let transition=try WorkspaceReservations(directory:directory)
    #expect(transition.inventory.isEmpty);#expect(runtime.starts==1)
}
@Test @MainActor func productStoppedIntentCannotHideUnconfirmedOldExecution() throws {
    let directory=try productDirectory();defer{try? FileManager.default.removeItem(at:directory)}
    let store=try WorkspaceHostState(directory:directory.appendingPathComponent("workspace")),runtime=try ProductRuntime()
    let reference = try store.directory.lock("owner.lock")
    try store.commit{$0.running=false;$0.execution=WorkspaceExecution(hostBoot:"host-boot",boot:Data(repeating:1,count:16),reference:reference.identity)}
    let owner=WorkspaceProductOwner(store:store,reservationDirectory:directory,hostBoot:"host-boot"){ _ in runtime }
    owner.launch()
    #expect(owner.snapshot().state=="cleanup-required");#expect(runtime.starts==0)
    #expect(store.value.execution != nil)
    withExtendedLifetime(reference) {}
}

@Test @MainActor func productStoppedDescriptorRemovalDoesNotReleaseAFollowingMacReservation() async throws {
    let directory=try productDirectory();defer{try? FileManager.default.removeItem(at:directory)}
    let store=try WorkspaceHostState(directory:directory.appendingPathComponent("workspace")),runtime=try ProductRuntime()
    let owner=WorkspaceProductOwner(store:store,reservationDirectory:directory,hostBoot:"host-boot"){ _ in runtime }
    let connection=try productConnection()
    _=owner.handle(try productMount(connection));runtime.running();try await productTurn()
    _=owner.handle(try productRequest("stop",force:true));try await productTurn()
    let mac=WorkspaceReservation(authority:connection.connection.authority,volume:"vol-1",frontend:"fskit",owner:"mac-ref")
    do{let transition=try WorkspaceReservations(directory:directory);try transition.reserve(mac)}
    #expect(owner.handle(try productRequest("umount",volume:"vol-1")).state != "refused")
    #expect(store.value.volumes.isEmpty)
    let transition=try WorkspaceReservations(directory:directory)
    #expect(transition.inventory == [mac]);#expect(runtime.starts==1)
}

@Test @MainActor func productUpdateExcludesStartsAndRetainsCrashWitness() async throws {
    let directory = try productDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
    let account = try WorkspacePrivateDirectory(directory)
    let store = try WorkspaceHostState(directory: directory.appendingPathComponent("workspace"))
    let runtime = try ProductRuntime()
    let owner = WorkspaceProductOwner(store: store, reservationDirectory: directory, hostBoot: "host-boot") { _ in runtime }
    do {
        let update = try account.lock("mount-lifecycle.lock")
        #expect(owner.handle(try productRequest("start")).state == "refused")
        #expect(!store.value.running); #expect(runtime.starts == 0)
        withExtendedLifetime(update) {}
    }
    #expect(owner.handle(try productRequest("start")).state == "starting")
    #expect(try store.directory.read("resources.present") != nil)
    do {
        // Closing new admission must still permit Stop to drain the live VM.
        // Its durable presence marker blocks ordinary replacement meanwhile.
        let update = try account.lock("mount-lifecycle.lock")
        #expect(try store.directory.read("resources.present") != nil)
        #expect(owner.handle(try productRequest("start")).state == "refused")
        withExtendedLifetime(update) {}
    }
    runtime.running(); try await productTurn()
    _ = owner.handle(try productRequest("stop")); try await productTurn(); try await productTurn()
    #expect(store.value.execution == nil)
    #expect(try store.directory.read("resources.present") == nil)
    let update = try account.lock("mount-lifecycle.lock")
    #expect(owner.handle(try productRequest("start")).state == "refused")
    #expect(owner.handle(try productRequest("stop")).state != "refused")
    try await productTurn()
    #expect(!store.value.running)
    withExtendedLifetime(update) {}
}

@Test func pendingUpdateRefusesReservationButAllowsCleanup() throws {
    let directory = try productDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
    let transition = try WorkspaceReservations(directory: directory)
    let old = WorkspaceReservation(authority: String(repeating: "a", count: 64), volume: "old", owner: "old")
    try transition.reserve(old)
    let host = try WorkspacePrivateDirectory(directory.appendingPathComponent("host"))
    let release: [String: Any] = ["codeDirectoryHash": String(repeating: "b", count: 40), "executableSHA256": String(repeating: "b", count: 64), "daemonVersion": "1"]
    let lease: [String: Any] = ["schemaVersion": 1, "phase": "preparing-old", "tokenSHA256": String(repeating: "c", count: 64), "oldRelease": release, "targetRelease": release, "createdAtUnixMs": 1_800_000_000_000, "deadlineUnixMs": 1_800_000_300_000]
    try host.write("activation.json", data: JSONSerialization.data(withJSONObject: lease))
    #expect(throws: (any Error).self) { try transition.reserve(WorkspaceReservation(authority: old.authority, volume: "new", owner: "new")) }
    try transition.release(old)
    #expect(transition.inventory.isEmpty)
}

@Test @MainActor func productEmptyWitnessRequiresTerminationAndPreservesLostOutcome() throws {
    let directory = try productDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
    let store = try WorkspaceHostState(directory: directory)
    do {
        let reference = try store.directory.lock("owner.lock")
        try store.commit { $0.execution = WorkspaceExecution(hostBoot: "same-boot", boot: Data(repeating: 1, count: 16), reference: reference.identity) }
        #expect(throws: (any Error).self) { try store.publishEmptyResources() }
        #expect(throws: (any Error).self) { try store.requirePriorExecutionAbsent(hostBoot: "same-boot") }
        withExtendedLifetime(reference) {}
    }
    #expect(try store.directory.read("resources.present") != nil)
    // A reboot proves execution absence, but never silently acknowledges loss.
    var frame = try WorkspaceControl.decode(workspaceGolden("status_reply"))
    frame.statusReply.mounts[0].outcome = unknownTestOutcome()
    let raw = try WorkspaceControl.encode(frame)
    try store.commit { $0.current = raw }
    try store.requirePriorExecutionAbsent(hostBoot: "new-host-boot")
    #expect(store.value.execution == nil)
    #expect(throws: (any Error).self) { try store.publishEmptyResources() }
    #expect(try store.directory.read("resources.present") != nil)
    #expect(!store.value.retained.isEmpty)
}

@Test @MainActor func productForceStopWithoutStatusKeepsUnknownOutcomeAcrossSuccessor() async throws {
    let directory = try productDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
    let store = try WorkspaceHostState(directory: directory.appendingPathComponent("workspace"))
    let runtime = try ProductRuntime()
    let owner = WorkspaceProductOwner(store: store, reservationDirectory: directory, hostBoot: "host-boot") { _ in runtime }
    _ = owner.handle(try productRequest("start")); runtime.running(); try await productTurn()
    _ = owner.handle(try productRequest("stop", force: true))
    // Retry the stopped-owner continuation after its durable outcome cut.
    try store.retainUnobservedExecution()
    try await productTurn(); try await productTurn()
    #expect(store.value.execution == nil)
    #expect(owner.snapshot().previousWriteOutcomeUnknown)
    #expect(try store.directory.read("resources.present") == Data("8\n".utf8))
    _ = owner.handle(try productRequest("start")); runtime.running(); try await productTurn()
    _ = owner.handle(try productRequest("stop")); try await productTurn(); try await productTurn()
    #expect(store.value.execution == nil)
    #expect(store.previousWriteOutcomeUnknown)
    #expect(throws: (any Error).self) { try store.publishEmptyResources() }
    let quiesce = try WorkspaceHostLifecycleRequest.decode(Data("{\"lifecycleVersion\":1,\"operation\":\"quiesce\"}".utf8))
    #expect(try owner.lifecycle(quiesce).state == "busy")
}

@Test func productUnknownExecutionWitnessSurvivesServiceRecreation() throws {
    let directory = try productDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
    do {
        let store = try WorkspaceHostState(directory: directory)
        let reference = try store.directory.lock("owner.lock")
        try store.commit { $0.execution = WorkspaceExecution(hostBoot: "host", boot: Data(repeating: 1, count: 16), reference: reference.identity) }
        try store.retainUnobservedExecution()
        try store.commit { $0.running = false }
    }
    let reopened = try WorkspaceHostState(directory: directory)
    #expect(reopened.previousWriteOutcomeUnknown)
    try reopened.commit { $0.running = false }
    #expect(throws: (any Error).self) { try reopened.publishEmptyResources() }
    #expect(try reopened.directory.read("resources.present") == Data("8\n".utf8))
}

@Test @MainActor func productCleanRetirementDoesNotAccumulateAcross1000Cycles() throws {
    let directory = try productDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
    let store = try WorkspaceHostState(directory: directory.appendingPathComponent("workspace"))
    let runtime = try ProductRuntime()
    let owner = WorkspaceProductOwner(store: store, reservationDirectory: directory, hostBoot: "host-boot") { _ in runtime }
    _ = owner.handle(try productRequest("start"))
    var status = try WorkspaceControl.decode(workspaceGolden("status_reply")).statusReply
    status.bootID = runtime.bootID; status.mounts = []; status.jobs = []; status.retired = []
    var peakBytes = 0
    for cycle in 1...1000 {
        var mount = WorkspaceMountStatus(); mount.mount = runtime.identityReply.mount
        mount.mount.incarnation = Data(repeating: 1, count: 8) + withUnsafeBytes(of: UInt64(cycle).bigEndian) { Data($0) }
        mount.state = "ready"; mount.cleanup = "retained"; mount.renewal.state = "not-required"; mount.outcome = unknownTestOutcome()
        var job = WorkspaceMountJob(); job.mount = mount.mount; job.requestID = UInt64(cycle * 2); job.operation = "mount"; job.phase = "complete"
        status.mounts = [mount]; status.jobs = [job]; status.retired = []
        try runtime.onStatus?(status)
        mount.state = "terminal"; mount.reason = "unmounted"; mount.cleanup = "complete"
        mount.outcome.durability = "durable"; mount.outcome.observation = "observed"; mount.outcome.release = "released"
        job.operation = "umount"; job.requestID += 1
        var retired = WorkspaceRetiredOutcome(); retired.retirementSequence = UInt64(cycle); retired.mountStatus = mount; retired.job = job
        status.mounts = []; status.jobs = []; status.retired = [retired]
        try runtime.onStatus?(status)
        #expect(store.value.retained.isEmpty)
        peakBytes = max(peakBytes, try #require(try store.directory.read("desired.json")).count)
    }
    #expect(peakBytes < 4096)
    #expect(store.value.outcomeSequence == 0)
    #expect(store.value.retained.isEmpty)
}

@Test func productExactDismissOperationExists() throws {
    let raw = Data("{\"version\":1,\"operation\":\"dismiss\",\"outcomeId\":\"1/01010101010101010101010101010101/vol-1\"}".utf8)
    _ = try WorkspaceHostControl.decodeRequest(raw)
}


private func dismissRequest(_ id: String) throws -> WorkspaceHostRequest {
    try WorkspaceHostControl.decodeRequest(JSONSerialization.data(withJSONObject: ["version": 1, "operation": "dismiss", "outcomeId": id]))
}
private func quiesceRequest() throws -> WorkspaceHostLifecycleRequest {
    try WorkspaceHostLifecycleRequest.decode(Data("{\"lifecycleVersion\":1,\"operation\":\"quiesce\"}".utf8))
}

@Test @MainActor func productForceUnmountDismissThenRemovalSucceeds() async throws {
    let home = try productDirectory(); defer { try? FileManager.default.removeItem(at: home) }
    let account = home.appendingPathComponent(".local/state/portablefs")
    var store: WorkspaceHostState? = try WorkspaceHostState(directory: account.appendingPathComponent("workspace"))
    let runtime = try ProductRuntime()
    var owner: WorkspaceProductOwner? = WorkspaceProductOwner(store: try #require(store), reservationDirectory: account, hostBoot: "host") { _ in runtime }
    _ = try owner?.handle(productMount(productConnection())); runtime.running(); try await productTurn()
    let request = try #require(store?.value.volumes.first?.request)
    try store?.commit { $0.volumes[0].authorizationConsumed = true; $0.volumes[0].operation = "ready" }
    _ = try owner?.handle(productRequest("umount", volume: "vol-1", force: true))
    #expect(runtime.umounts == [true])
    var status = try WorkspaceControl.decode(workspaceGolden("retired_mount_with_job")).statusReply
    var retired = try #require(status.retired.first)
    retired.retirementSequence = 1; retired.mountStatus.mount = try request.guestIdentity().mount
    retired.mountStatus.outcome.durability = "lost"; retired.mountStatus.outcome.observation = "observed"; retired.mountStatus.outcome.release = "abandoned"
    retired.job.mount = retired.mountStatus.mount; retired.job.operation = "umount"; retired.job.phase = "complete"; retired.job.failure = ""; retired.job.reason = ""; retired.job.requestID = 20
    status.bootID = runtime.bootID; status.mounts = []; status.jobs = []; status.retired = [retired]
    try runtime.onStatus?(status)
    _ = try owner?.handle(productRequest("stop")); try await productTurn(); try await productTurn()
    #expect(store?.value.volumes.isEmpty == true)
    let notice = try #require(owner?.snapshot().outcomes.first)
    #expect(notice.someChangesWereNotSaved); #expect(notice.details.contains("4096 bytes"))
    #expect(try owner?.lifecycle(quiesceRequest()).state == "busy")
    let denied = try #require(owner?.snapshot())
    let refusedActions = WorkspaceRemoval.Actions(stop: { denied }, status: { denied }, quiesce: { Issue.record("unacknowledged outcome reached quiescence") }, unregister: { Issue.record("unacknowledged outcome unregistered") }, removeSSH: {})
    await #expect(throws: (any Error).self) { try await WorkspaceRemoval.run(data: .keep, home: home, actions: refusedActions) }
    _ = try owner?.handle(dismissRequest(notice.id))
    // A repeated pre-ACK guest page cannot recreate the notice. Test this while
    // the runtime is present in the separate cursor test below.
    #expect(owner?.snapshot().outcomes.isEmpty == true)
    #expect(try owner?.lifecycle(quiesceRequest()).state == "quiesced")
    let clean = try #require(owner?.snapshot())
    #expect(!clean.someChangesWereNotSaved && !clean.previousWriteOutcomeUnknown)
    owner = nil; store = nil
    var unregistered = false
    let actions = WorkspaceRemoval.Actions(stop: { clean }, status: { clean }, quiesce: {}, unregister: { unregistered = true }, removeSSH: {})
    _ = try await WorkspaceRemoval.run(data: .keep, home: home, actions: actions)
    #expect(unregistered)
}

@Test @MainActor func productCrashDismissAllowsUpdateAndDoubleOrUnknownDismissIsHarmless() throws {
    let directory = try productDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
    let store = try WorkspaceHostState(directory: directory.appendingPathComponent("workspace"))
    do {
        let reference = try store.directory.lock("owner.lock")
        try store.commit { $0.execution = WorkspaceExecution(hostBoot: "host", boot: Data(repeating: 7, count: 16), reference: reference.identity) }
    }
    let runtime = try ProductRuntime()
    let owner = WorkspaceProductOwner(store: store, reservationDirectory: directory, hostBoot: "host") { _ in runtime }
    owner.launch()
    let id = try #require(owner.snapshot().outcomes.first?.id)
    #expect(owner.snapshot().previousWriteOutcomeUnknown)
    #expect(try owner.lifecycle(quiesceRequest()).state == "busy")
    let fields = id.split(separator: "/").map(String.init)
    for foreign in ["999/" + fields[1] + "/" + fields[2], fields[0] + "/09090909090909090909090909090909/" + fields[2], fields[0] + "/" + fields[1] + "/other"] {
        #expect(owner.handle(try dismissRequest(foreign)).state != "refused")
        #expect(owner.snapshot().outcomes.map(\.id) == [id])
    }
    _ = owner.handle(try dismissRequest(id)); _ = owner.handle(try dismissRequest(id))
    #expect(!owner.snapshot().previousWriteOutcomeUnknown)
    #expect(try owner.lifecycle(quiesceRequest()).state == "quiesced")
    #expect(try store.directory.read("resources.present") == nil)
}

@Test func productDismissCrashCutsDoNotResurrectOrEraseAnotherOutcome() throws {
    for cut in ["before", "after"] {
        let directory = try productDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
        var dismissed = "", other = ""
        do {
            let store = try WorkspaceHostState(directory: directory)
            var page = try WorkspaceControl.decode(workspaceGolden("status_reply"))
            try store.commit { state in
                try WorkspaceHostState.retain(page.statusReply.mounts[0], evidence: WorkspaceControl.encode(page), state: &state)
                page.statusReply.mounts[0].mount.incarnation = Data(repeating: 9, count: 16)
                try WorkspaceHostState.retain(page.statusReply.mounts[0], evidence: WorkspaceControl.encode(page), state: &state)
            }
            dismissed = store.value.retained[0].notice.id; other = store.value.retained[1].notice.id
            store.afterDismissCommit = { throw ProductFailure.refused }
            if cut == "after" { #expect(throws: ProductFailure.self) { try store.dismiss(dismissed) } }
            // Cut before commit leaves the notice; cut after commit leaves only
            // a conservative resource witness. Recreating the owner reads the
            // single atomic decision rather than interpreting that witness.
        }
        let reopened = try WorkspaceHostState(directory: directory)
        #expect(reopened.retainedOutcomes.contains { $0.notice.id == dismissed } == (cut == "before"))
        #expect(reopened.retainedOutcomes.contains { $0.notice.id == other })
        try reopened.dismiss(dismissed); try reopened.dismiss(dismissed)
        #expect(reopened.retainedOutcomes.map { $0.notice.id } == [other])
        #expect(throws: (any Error).self) { try reopened.publishEmptyResources() }
        try reopened.dismiss(other); try reopened.publishEmptyResources()
        #expect(reopened.retainedOutcomes.isEmpty)
        var completed = try WorkspaceControl.decode(workspaceGolden("status_reply")).statusReply
        completed.mounts = []; completed.jobs = []; completed.retired = []
        try reopened.commit { state in WorkspaceHostState.confirmGuestRetirements(completed, state: &state) }
        #expect(reopened.value.retained.isEmpty)
        #expect(try reopened.directory.read("resources.present") == nil)
    }
}

@Test @MainActor func productDismissedRetirementCannotReturnOnDuplicateStatusOrRecovery() async throws {
    let directory = try productDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
    let store = try WorkspaceHostState(directory: directory.appendingPathComponent("workspace")), runtime = try ProductRuntime()
    let owner = WorkspaceProductOwner(store: store, reservationDirectory: directory, hostBoot: "host") { _ in runtime }
    _ = owner.handle(try productRequest("start"))
    var status = try WorkspaceControl.decode(workspaceGolden("retired_mount_with_job")).statusReply
    status.bootID = runtime.bootID; status.mounts = []; status.jobs = []; status.retired = [try #require(status.retired.first)]
    try runtime.onStatus?(status)
    let notice = try #require(owner.snapshot().outcomes.first)
    _ = owner.handle(try dismissRequest(notice.id)); try runtime.onStatus?(status)
    #expect(owner.snapshot().outcomes.isEmpty)
    #expect(store.value.retirementThrough == status.retired[0].retirementSequence)
    _ = owner.handle(try productRequest("stop", force: true)); try await productTurn()
    let crash = try #require(owner.snapshot().outcomes.first)
    #expect(crash.id != notice.id)
    // A new execution's uncertainty is independent, even after old Dismiss.
    #expect(owner.snapshot().previousWriteOutcomeUnknown)
}

@Test @MainActor func productCapacityBackpressuresAdmissionButAlwaysAcceptsReservedFinalOutcome() async throws {
    let directory = try productDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
    let store = try WorkspaceHostState(directory: directory.appendingPathComponent("workspace")), runtime = try ProductRuntime()
    let owner = WorkspaceProductOwner(store: store, reservationDirectory: directory, hostBoot: "host") { _ in runtime }
    var frame = try WorkspaceControl.decode(workspaceGolden("status_reply"))
    // 126 retained notices plus one admitted volume and its execution fill
    // the 128 slots. The admitted volume can always publish its final loss.
    try store.commit { state in
        for sequence in 1...126 {
            frame.statusReply.mounts[0].mount.incarnation = Data(repeating: 1, count: 8) + withUnsafeBytes(of: UInt64(sequence).bigEndian) { Data($0) }
            try WorkspaceHostState.retain(frame.statusReply.mounts[0], evidence: WorkspaceControl.encode(frame), state: &state)
        }
    }
    #expect(owner.handle(try productMount(productConnection())).state != "refused")
    runtime.running(); try await productTurn()
    let request = try #require(store.value.volumes.first?.request)
    #expect(throws: (any Error).self) { try store.requireOutcomeCapacity(replacing: "other") }
    let before = store.value.outcomeSequence
    var another = try productConnection(); another.connection.volumeId = "other"
    #expect(owner.handle(try productMount(another)).state == "refused")
    #expect(store.value.outcomeSequence == before)
    // Final evidence uses the volume's existing reservation; it never enters
    // the new-admission capacity guard or crashes the status observer.
    var final = frame.statusReply.mounts[0]; final.mount = try request.guestIdentity().mount; final.cleanup = "complete"
    var retired = WorkspaceRetiredOutcome(); retired.retirementSequence = 1; retired.mountStatus = final
    frame.statusReply.bootID = runtime.bootID; frame.statusReply.mounts = []; frame.statusReply.jobs = []; frame.statusReply.retired = [retired]
    try runtime.onStatus?(frame.statusReply)
    #expect(store.value.retained.count == 127)
    frame.statusReply.retired = []; try runtime.onStatus?(frame.statusReply)
    let id = try #require(owner.snapshot().outcomes.first?.id)
    _ = owner.handle(try dismissRequest(id))
    #expect(owner.handle(try productMount(another)).state != "refused")
}


@Test @MainActor func productMaximumRetainedOutcomesFitDiskAndHostFrame() throws {
    let directory = try productDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
    let store = try WorkspaceHostState(directory: directory.appendingPathComponent("workspace")), runtime = try ProductRuntime()
    let owner = WorkspaceProductOwner(store: store, reservationDirectory: directory, hostBoot: "host") { _ in runtime }
    var frame = try maximumWorkspaceStatus()
    frame.statusReply.mounts = [frame.statusReply.mounts[0]]; frame.statusReply.jobs = []; frame.statusReply.retired = []
    try store.commit { state in
        for sequence in 1...128 {
            frame.statusReply.mounts[0].mount.incarnation = Data(repeating: 1, count: 8) + withUnsafeBytes(of: UInt64(sequence).bigEndian) { Data($0) }
            try WorkspaceHostState.retain(frame.statusReply.mounts[0], evidence: WorkspaceControl.encode(frame), state: &state)
        }
    }
    let raw = try WorkspaceHostControl.encode(owner.snapshot())
    #expect(raw.count <= WorkspaceHostControl.maxFrame)
    #expect(try PortableFSWorkspaceStatus.decode(raw).outcomes.count == 128)
    #expect(try #require(try store.directory.read("desired.json", limit: 4 << 20)).count <= 4 << 20)
}

@Test @MainActor func productRetirementReplayedAfterCrashKeepsExactDismissDecision() async throws {
    for dismissed in [false, true] {
        let directory = try productDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
        let store = try WorkspaceHostState(directory: directory.appendingPathComponent("workspace")), runtime = try ProductRuntime()
        let owner = WorkspaceProductOwner(store: store, reservationDirectory: directory, hostBoot: "host") { _ in runtime }
        _ = owner.handle(try productRequest("start"))
        var status = try WorkspaceControl.decode(workspaceGolden("retired_mount_with_job")).statusReply
        status.bootID = runtime.bootID; status.mounts = []; status.jobs = []; status.retired = [try #require(status.retired.first)]
        try runtime.onStatus?(status)
        let old = try #require(owner.snapshot().outcomes.first?.id)
        if dismissed { _ = owner.handle(try dismissRequest(old)) }
        // The guest never confirmed its retirement ACK before this crash.
        _ = owner.handle(try productRequest("stop", force: true)); try await productTurn()
        for outcome in owner.snapshot().outcomes where outcome.id != old { _ = owner.handle(try dismissRequest(outcome.id)) }
        runtime.bootID = Data(repeating: 9, count: 16); runtime.phase = .starting
        _ = owner.handle(try productRequest("start"))
        status.bootID = runtime.bootID; status.retired[0].retirementSequence = 1
        try runtime.onStatus?(status)
        #expect(owner.snapshot().outcomes.map(\.id) == (dismissed ? [] : [old]))
    }
}


@Test @MainActor func productPendingGuestAcksCannotDeadlockColdBootOrGrowAcrossReconciliation() async throws {
    let directory = try productDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
    let store = try WorkspaceHostState(directory: directory.appendingPathComponent("workspace")), runtime = try ProductRuntime()
    var frame = try WorkspaceControl.decode(workspaceGolden("status_reply"))
    do {
        let reference = try store.directory.lock("owner.lock")
        try store.commit { state in
            for sequence in 1...63 {
                frame.statusReply.mounts[0].mount.incarnation = Data(repeating: 1, count: 8) + withUnsafeBytes(of: UInt64(sequence).bigEndian) { Data($0) }
                try WorkspaceHostState.retain(frame.statusReply.mounts[0], evidence: WorkspaceControl.encode(frame), state: &state)
            }
            state.running = true
            state.execution = WorkspaceExecution(hostBoot: "host", boot: Data(repeating: 1, count: 16), reference: reference.identity)
            // All 64 Mounts were admitted after the last snapshot. Each exact
            // consumed request must transfer its reserved slot on owner death.
            for volume in 0..<64 {
                var connection = try productConnection().connection; connection.volumeId = "volume-" + String(volume)
                let intent = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()
                var desired = WorkspaceDesiredVolume(connection: connection, intent: intent)
                var identity = runtime.identityReply
                identity.mount.volumeID = connection.volumeId
                identity.mount.authorityID = Data(stride(from: 0, to: connection.authority.count, by: 2).compactMap { UInt8(connection.authority.dropFirst($0).prefix(2), radix: 16) })
                desired.request = try WorkspaceConnectionDocument(connection: connection, intent: intent, identity: identity)
                desired.authorizationConsumed = true; desired.operation = "mount-pending"
                state.volumes.append(desired)
            }
        }
    }
    try store.requirePriorExecutionAbsent(hostBoot: "host")
    #expect(store.value.retained.count == 127)
    let oldMounts = try store.value.volumes.map { volume in try #require(try volume.request?.guestIdentity().mount) }
    for mount in oldMounts { #expect(store.value.retained.contains { $0.guestMountKey == WorkspaceControl.mountKey(mount) }) }
    for outcome in store.retainedOutcomes { try store.dismiss(outcome.notice.id) }
    #expect(store.value.retained.count == 127); #expect(store.retainedOutcomes.isEmpty)
    let owner = WorkspaceProductOwner(store: store, reservationDirectory: directory, hostBoot: "host") { _ in runtime }
    owner.launch(); #expect(runtime.starts == 1)
    runtime.running(); try await productTurn()
    #expect(runtime.identityCalls == 0)
    #expect(owner.snapshot().volumes.allSatisfy { $0.state == "pending" && $0.message == WorkspaceHostControl.outcomeCapacity })
    frame.statusReply.bootID = runtime.bootID; frame.statusReply.mounts = []; frame.statusReply.jobs = []; frame.statusReply.retired = []
    for page in 0..<4 {
        frame.statusReply.retired = oldMounts[(page*16)..<(page*16+16)].enumerated().map { offset, mount in
            var status = WorkspaceMountStatus(); status.mount = mount; status.state = "terminal"; status.cleanup = "complete"; status.reason = "old owner ended"; status.renewal.state = "pending"; status.outcome = unknownTestOutcome()
            var retired = WorkspaceRetiredOutcome(); retired.retirementSequence = UInt64(page*16+offset+1); retired.mountStatus = status
            return retired
        }
        try runtime.onStatus?(frame.statusReply)
        #expect(store.value.retained.count == 127); #expect(owner.snapshot().outcomes.isEmpty)
    }
    frame.statusReply.retired = []; try runtime.onStatus?(frame.statusReply); try await productTurn()
    #expect(store.value.retained.isEmpty)
    #expect(runtime.identityCalls == 64)
    #expect(owner.snapshot().outcomes.isEmpty)
}

@Test @MainActor func readyReopenNoticeClearsOnlyForItsExactIncarnationAndStaysCleared() async throws {
    let directory = try productDirectory(); defer { try? FileManager.default.removeItem(at: directory) }
    let store = try WorkspaceHostState(directory: directory.appendingPathComponent("workspace")), runtime = try ProductRuntime()
    let owner = WorkspaceProductOwner(store: store, reservationDirectory: directory, hostBoot: "host-boot") { _ in runtime }
    _ = owner.handle(try productMount(productConnection())); runtime.running(); try await productTurn()
    try store.commit { $0.volumes[0].operation = "ready"; $0.volumes[0].reopenRequired = true; $0.volumes[0].message = "" }
    let json = try #require(JSONSerialization.jsonObject(with: WorkspaceHostControl.encode(owner.snapshot())) as? [String: Any])
    let rows = try #require(json["volumes"] as? [[String: Any]])
    let token = try #require(rows.first?["reopenId"] as? String)
    #expect(owner.snapshot().volumes[0].requiresReopen)
    func acknowledge(_ id: String) throws -> WorkspaceHostReply {
        let raw = try JSONSerialization.data(withJSONObject: ["version": 1, "operation": "dismiss-reopen", "volumeId": "vol-1", "reopenId": id])
        return owner.handle(try WorkspaceHostControl.decodeRequest(raw))
    }
    _ = try acknowledge(String(repeating: "09", count: 16))
    #expect(store.value.volumes[0].reopenRequired)
    try store.commit { $0.volumes[0].operation = "mount-pending" }
    _ = try acknowledge(token)
    #expect(store.value.volumes[0].reopenRequired)
    try store.commit { $0.volumes[0].operation = "ready" }
    #expect(try !acknowledge(token).volumes[0].requiresReopen)
    _ = try acknowledge(token)
    #expect(!store.value.volumes[0].reopenRequired)
    let persisted = try JSONDecoder().decode(WorkspaceDesiredState.self, from: Data(contentsOf: store.directory.url.appendingPathComponent("desired.json")))
    #expect(!persisted.volumes[0].reopenRequired)
    let desired = store.value.volumes[0]
    var nextIdentity = try #require(desired.request).guestIdentity()
    nextIdentity.mount.incarnation = Data(repeating: 11, count: 16)
    let nextRequest = try WorkspaceConnectionDocument(connection: desired.connection, intent: desired.intent, identity: nextIdentity)
    try store.commit {
        $0.volumes[0].request = nextRequest; $0.volumes[0].reopenRequired = true
        $0.outcomeSequence = 1
        var retained = WorkspaceRetainedOutcome(notice: .init(id: "1/01010101010101010101010101010101/-", lost: false, unknown: true), evidence: nil)
        retained.awaitingGuest = false; $0.retained = [retained]
    }
    #expect(owner.snapshot().volumes[0].requiresReopen)
    _ = try acknowledge(token)
    #expect(owner.snapshot().volumes[0].requiresReopen)
    _ = try acknowledge(String(repeating: "0b", count: 16))
    #expect(!owner.snapshot().volumes[0].requiresReopen)
    #expect(owner.snapshot().outcomes.count == 1)
    #expect(owner.snapshot().previousWriteOutcomeUnknown)
}
