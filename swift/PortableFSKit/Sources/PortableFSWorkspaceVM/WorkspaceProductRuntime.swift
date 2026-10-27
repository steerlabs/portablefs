import Foundation
import PortableFSAppCore
import PortableFSWorkspaceCore

@MainActor public protocol WorkspaceProductRuntime: AnyObject {
    var phase: WorkspacePhase { get }
    var ready: Bool { get }
    var failureMessage: String { get }
    var onChange: (() -> Void)? { get set }
    var onStatus: ((WorkspaceStatusReply) throws -> Void)? { get set }
    var bootID: Data { get }
    func start() throws
    func identity(_ request: WorkspaceIdentityRequest, completion: @escaping (Result<WorkspaceIdentityReply, Error>) -> Void)
    func provision(_ provision: WorkspaceProvision, completion: @escaping (Result<WorkspaceResult, Error>) -> Void)
    func mount(_ mount: WorkspaceMountID, completion: @escaping (Result<WorkspaceResult, Error>) -> Void)
    func umount(_ mount: WorkspaceMountID, force: Bool, completion: @escaping (Result<WorkspaceResult, Error>) -> Void)
    func stop(force: Bool, completion: @escaping (Result<Void, Error>) -> Void)
}
public extension WorkspaceProductRuntime { var failureMessage: String { "" } }

/// The SMAppService executable retains this owner. No menu-app or CLI lifetime
/// owns it. All power/VZ transitions remain in the existing coordinator.
@MainActor public final class WorkspaceVMRuntime: WorkspaceProductRuntime {
    public let state: WorkspaceState
    public let vm: WorkspaceMachine
    public let channel: WorkspaceVsockChannel
    public let coordinator: WorkspaceCoordinator
    private let power = WorkspaceSystemPower()
    private let clock = WorkspaceSystemClock()
    private let random = WorkspaceRandom()
    private let bridge: WorkspaceSSHBridge
    private let hello: WorkspaceHello
    public var phase: WorkspacePhase { coordinator.phase }
    public var bootID: Data { hello.bootID }
    public private(set) var ready = false
    public private(set) var failureMessage = ""
    public var onChange: (() -> Void)?
    public var onStatus: ((WorkspaceStatusReply) throws -> Void)?
    private var seeded = false
    private var hostKey = ""
    private var updateQueued = false
    private var sshProbe: Process?
    private let sshHome: URL
    public init(artifact: WorkspaceArtifact, directory: URL, executionReference: WorkspaceFileLock, sshHome: URL) throws {
        self.sshHome = sshHome
        guard artifact.release.commit == WorkspaceArtifact.hostBuildCommit else { throw WorkspaceVMError("Workspace image failed verification") }
        state = try WorkspaceState(directory: directory, ownership: executionReference)
        vm = try WorkspaceMachine(artifact: artifact, dataDisk: directory.appendingPathComponent("data.ext4"), serialLog: directory.appendingPathComponent("serial.log"), machineID: state.machineID, macAddress: state.macAddress, executionReference: executionReference.fileHandle)
        channel = WorkspaceVsockChannel(vm: vm); bridge = WorkspaceSSHBridge(vm: vm, socket: state.socket)
        var hello = WorkspaceHello(); hello.release = artifact.release; hello.bootID = random.next(); hello.hostServiceID = random.next(); self.hello = hello
        coordinator = try WorkspaceCoordinator(host: hello, oldInstanceAbsent: true, vm: vm, power: power, channel: channel, clock: clock, nonces: random, startBudget: 150_000_000_000)
        vm.onSeed = { [weak self] in self?.seed($0) }
        vm.onStopped = { [weak self] in self?.coordinator.vmStopped(reason: $0) }
        channel.onFailure = { [weak self] in self?.coordinator.channelLost($0) }
        power.onRecord = { [weak vm] in vm?.record($0) }
        coordinator.onChange = { [weak self] in self?.scheduleUpdate() }
        let consume = channel.statusObserver
        channel.statusObserver = { [weak self] status in
            guard let self, let persist = self.onStatus else { throw WorkspaceControlError.transition }
            // Durably retain retirement/loss before coordinator acknowledgement.
            try persist(status); try consume?(status)
        }
    }
    public func start() throws { try coordinator.start() }
    private func seed(_ event: [String: String]) {
        do {
            switch event["event"] {
            case "seed-ready": try vm.seed(["boot_id": hex(hello.bootID), "host_service_id": hex(hello.hostServiceID), "authorized_key": state.authorizedKey, "format_authorized": state.formatAuthorized])
            case "seeded":
                guard event["boot_id"] == hex(hello.bootID), event["format_complete"] == "8", let key = event["host_key"] else { throw WorkspaceVMError("guest bootstrap identity mismatch") }
                try state.formatCompleted(); seeded = true; hostKey = key; scheduleUpdate()
            case "control-ready": channel.controlReady()
            default: throw WorkspaceVMError("guest bootstrap failed")
            }
        } catch { coordinator.channelLost(String(describing: error)) }
    }
    private func hex(_ data: Data) -> String { data.map { String(format: "%02x", $0) }.joined() }
    private func scheduleUpdate() {
        guard !updateQueued else { return }; updateQueued = true
        DispatchQueue.main.async { [weak self] in self?.updateQueued = false; self?.update() }
    }
    private func update() {
        if phase == .running, seeded, !ready, sshProbe == nil {
            do {
                let config = try state.pin(hostKey: hostKey)
                try PortableFSWorkspaceSSH.install(home: sshHome, stanza: Data(contentsOf: config))
                try bridge.start()
                let probe = Process(); probe.executableURL = URL(fileURLWithPath: "/usr/bin/ssh")
                probe.arguments = ["-F", config.path, "portablefs-workspace", "true"]
                probe.standardInput = FileHandle.nullDevice; probe.standardOutput = FileHandle.nullDevice; probe.standardError = FileHandle.nullDevice
                probe.terminationHandler = { [weak self] process in
                    let success = process.terminationStatus == 0
                    Task { @MainActor in
                        guard let self else { return }; self.sshProbe = nil
                        if success, self.phase == .running { self.ready = true; self.onChange?() }
                        else { self.coordinator.channelLost("pinned SSH endpoint failed") }
                    }
                }
                sshProbe = probe; try probe.run()
            } catch { failureMessage = String(describing: error); coordinator.channelLost(String(describing: error)) }
        }
        if phase == .stopped || phase == .unknown || phase == .stopping { ready = false; bridge.close() }
        onChange?()
    }
    public func identity(_ request: WorkspaceIdentityRequest, completion: @escaping (Result<WorkspaceIdentityReply, Error>) -> Void) { channel.identity(request, deadline: clock.now + 20_000_000_000, completion: completion) }
    public func provision(_ provision: WorkspaceProvision, completion: @escaping (Result<WorkspaceResult, Error>) -> Void) { channel.provision(provision, deadline: clock.now + 20_000_000_000, completion: completion) }
    public func mount(_ mount: WorkspaceMountID, completion: @escaping (Result<WorkspaceResult, Error>) -> Void) { coordinator.mount(mount, completion: completion) }
    public func umount(_ mount: WorkspaceMountID, force: Bool, completion: @escaping (Result<WorkspaceResult, Error>) -> Void) { channel.umount(mount, force: force, deadline: clock.now + 20_000_000_000, completion: completion) }
    public func stop(force: Bool, completion: @escaping (Result<Void, Error>) -> Void) {
        bridge.close(); ready = false
        if force { if phase == .unknown { coordinator.discardUnknown() } else { coordinator.channelLost("explicit Force Stop") }; completion(.success(())) }
        else { coordinator.stopOrderly { [weak self] result in self?.scheduleUpdate(); completion(result) } }
    }
}
