import Foundation
import Testing
import PortableFSWorkspaceCore
@testable import PortableFSWorkspaceVM

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
        let owner = WorkspaceProductOwner(store:store,reservationDirectory:directory,hostBoot:"host-boot") { runtime }
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
        let directory = try productDirectory(); defer { try? FileManager.default.removeItem(at:directory) }
        let store = try WorkspaceHostState(directory:directory)
        try store.commit { $0.running = true; $0.execution = WorkspaceExecution(hostBoot:"same-boot",boot:Data(repeating:1,count:16)) }
        let runtime = try ProductRuntime()
        let owner = WorkspaceProductOwner(store:store,reservationDirectory:directory,hostBoot:"same-boot") { runtime }
        owner.launch(); #expect(runtime.starts == 0); #expect(owner.snapshot().state == "cleanup-required")
        #expect(owner.handle(try productRequest("start")).state == "refused"); #expect(runtime.starts == 0)
        #expect(throws:(any Error).self) { try store.requirePriorExecutionAbsent(hostBoot:"same-boot") }
        try store.requirePriorExecutionAbsent(hostBoot:"new-host-boot")
        #expect(store.value.execution == nil)
    }
    @Test @MainActor func pendingMountKeepsIntentAcrossTransitionAndRequiresExactResponse() async throws {
        let directory = try productDirectory(); defer { try? FileManager.default.removeItem(at:directory) }
        let store = try WorkspaceHostState(directory:directory.appendingPathComponent("workspace")), runtime = try ProductRuntime()
        let owner = WorkspaceProductOwner(store:store,reservationDirectory:directory,hostBoot:"host-boot") { runtime }
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
        let owner = WorkspaceProductOwner(store:store,reservationDirectory:directory,hostBoot:"host-boot") { runtime }
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
        let owner = WorkspaceProductOwner(store:store,reservationDirectory:directory,hostBoot:"host-boot") { runtime }
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
        let owner = WorkspaceProductOwner(store:store,reservationDirectory:directory,hostBoot:"host-boot") { runtime }
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
        let owner = WorkspaceProductOwner(store:store,reservationDirectory:directory,hostBoot:"host-boot") { runtime }
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
        let owner=WorkspaceProductOwner(store:store,reservationDirectory:directory,hostBoot:"host-boot"){runtime}
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
    let owner=WorkspaceProductOwner(store:store,reservationDirectory:directory,hostBoot:"host-boot"){runtime}
    let quiesce=try WorkspaceHostLifecycleRequest.decode(Data("{\"lifecycleVersion\":1,\"operation\":\"quiesce\"}".utf8))
    _=owner.handle(try productRequest("start"))
    #expect(try owner.lifecycle(quiesce).state=="busy")
    #expect(store.value.running)
    runtime.phase = .stopped
    // A separate idle owner with no execution can close its admission.
    let idleDirectory=try productDirectory();defer{try? FileManager.default.removeItem(at:idleDirectory)}
    let idleStore=try WorkspaceHostState(directory:idleDirectory.appendingPathComponent("workspace"))
    let idle=WorkspaceProductOwner(store:idleStore,reservationDirectory:idleDirectory,hostBoot:"host-boot"){runtime}
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
    let owner=WorkspaceProductOwner(store:store,reservationDirectory:directory,hostBoot:"host-boot"){creations+=1;return creations==1 ? first:second}
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
    let owner=WorkspaceProductOwner(store:store,reservationDirectory:directory,hostBoot:"host-boot"){runtime}
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
    try store.commit{$0.running=false;$0.execution=WorkspaceExecution(hostBoot:"host-boot",boot:Data(repeating:1,count:16))}
    let owner=WorkspaceProductOwner(store:store,reservationDirectory:directory,hostBoot:"host-boot"){runtime}
    owner.launch()
    #expect(owner.snapshot().state=="cleanup-required");#expect(runtime.starts==0)
    #expect(store.value.execution != nil)
}

@Test @MainActor func productStoppedDescriptorRemovalDoesNotReleaseAFollowingMacReservation() async throws {
    let directory=try productDirectory();defer{try? FileManager.default.removeItem(at:directory)}
    let store=try WorkspaceHostState(directory:directory.appendingPathComponent("workspace")),runtime=try ProductRuntime()
    let owner=WorkspaceProductOwner(store:store,reservationDirectory:directory,hostBoot:"host-boot"){runtime}
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
