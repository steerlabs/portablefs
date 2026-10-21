import Foundation
import Darwin
import PortableFSWorkspaceVM
import PortableFSWorkspaceCore

// Native probe observation belongs to the development executable. The product
// channel retains no tokens or public replay/test hooks.
@MainActor private final class ObservedChannel: WorkspaceGuestChannel {
    let base: WorkspaceVsockChannel
    var lastResume: WorkspaceResumeToken?
    var onHelloFailure: ((String) -> Void)?
    init(_ base: WorkspaceVsockChannel) { self.base = base }
    var isIdle: Bool { base.isIdle }
    func hello(_ host: WorkspaceHello, deadline: UInt64, completion: @escaping (Result<WorkspaceHello, Error>) -> Void) {
        base.hello(host, deadline: deadline) { [weak self] result in
            if case .failure(let error) = result { self?.onHelloFailure?(String(describing: error)) }
            completion(result)
        }
    }
    func suspend(_ request: WorkspaceSuspension, deadline: UInt64, completion: @escaping (Result<WorkspaceSuspendAck, Error>) -> Void) { base.suspend(request, deadline: deadline, completion: completion) }
    func resume(_ token: WorkspaceResumeToken, deadline: UInt64, completion: @escaping (Result<WorkspaceResumeAck, Error>) -> Void) { lastResume = token; base.resume(token, deadline: deadline, completion: completion) }
    func acknowledgeRetired(through sequence: UInt64, deadline: UInt64, completion: @escaping (Result<Void, Error>) -> Void) { base.acknowledgeRetired(through: sequence, deadline: deadline, completion: completion) }
    func status(deadline: UInt64, completion: @escaping (Result<WorkspaceStatusReply, Error>) -> Void) { base.status(deadline: deadline, completion: completion) }
}

@MainActor final class Driver {
    let state: WorkspaceDevState
    let vm: WorkspaceMachine
    let power = WorkspaceSystemPower()
    let clock = WorkspaceSystemClock()
    let random = WorkspaceRandom()
    let channel: WorkspaceVsockChannel
    private let observed: ObservedChannel
    let coordinator: WorkspaceCoordinator
    let bridge: WorkspaceSSHBridge
    let boot: WorkspaceHello
    var seeded = false
    var hostKey = ""
    var ready = false
    var stopping = false
    var exitCode: Int32 = 0
    var started: UInt64 = 0
    var inputBuffer = Data()
    var pendingCommand: String?
    var signals: [DispatchSourceSignal] = []
    var updateQueued = false
    init(image: URL, stateDirectory: URL, pairingMismatch: String? = nil) throws {
        let artifact = try WorkspaceArtifact(directory: image)
        guard artifact.release.commit == WorkspaceArtifact.hostBuildCommit, artifact.release.appVersion == "dev" else { throw WorkspaceVMError("host executable and guest release differ; rebuild the paired dev executable") }
        state = try WorkspaceDevState(directory: stateDirectory)
        vm = try WorkspaceMachine(artifact: artifact, dataDisk: stateDirectory.appendingPathComponent("data.ext4"), serialLog: stateDirectory.appendingPathComponent("serial.log"), machineID: state.machineID, macAddress: state.macAddress)
        channel = WorkspaceVsockChannel(vm: vm); observed = ObservedChannel(channel); bridge = WorkspaceSSHBridge(vm: vm, socket: state.socket)
        var hello = WorkspaceHello(); hello.release = artifact.release; hello.bootID = random.next(); hello.hostServiceID = random.next()
        switch pairingMismatch {
        case "version": hello.release.appVersion += "-mismatch"
        case "commit": hello.release.commit = String(repeating: hello.release.commit == String(repeating: "a", count: 40) ? "b" : "a", count: 40)
        case "digest": hello.release.imageDigest[hello.release.imageDigest.startIndex] ^= 1
        case nil: break
        default: throw WorkspaceVMError("invalid pairing mismatch field")
        }
        boot = hello
        coordinator = try WorkspaceCoordinator(host: hello, oldInstanceAbsent: true, vm: vm, power: power, channel: observed, clock: clock, nonces: random, startBudget: 150_000_000_000)
        vm.onSeed = { [weak self] event in self?.seedEvent(event) }
        power.onRecord = { [weak vm] in vm?.record($0) }
        vm.onStopped = { [weak self] in self?.coordinator.vmStopped(reason: $0) }
        observed.onHelloFailure = { [weak self] in self?.event("hello-refused", ["reason": $0]) }
        channel.onFailure = { [weak self] in self?.coordinator.channelLost($0) }
        coordinator.onChange = { [weak self] in self?.scheduleUpdate() }
    }
    func event(_ name: String, _ fields: [String: Any] = [:]) {
        var value = fields; value["event"] = name; value["continuous_ns"] = clock.now
        if let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) { FileHandle.standardOutput.write(data); FileHandle.standardOutput.write(Data([10])) }
    }
    func seedEvent(_ value: [String: String]) {
        do {
            switch value["event"] {
            case "seed-ready": try vm.seed(["boot_id": hex(boot.bootID), "host_service_id": hex(boot.hostServiceID), "authorized_key": state.authorizedKey, "format_authorized": state.formatAuthorized])
            case "seeded":
                guard value["boot_id"] == hex(boot.bootID), value["format_complete"] == "8", let key = value["host_key"] else { throw WorkspaceVMError("seed identity or format mismatch") }
                try state.formatCompleted(); hostKey = key; seeded = true; scheduleUpdate()
            case "control-ready": event("control-ready"); channel.controlReady()
            case "boot-failed": throw WorkspaceVMError(value["reason"] ?? "guest bootstrap failed")
            default: throw WorkspaceVMError("invalid boot console message")
            }
        } catch { fail(error) }
    }
    func start() throws {
        for number in [SIGINT, SIGTERM] {
            signal(number, SIG_IGN)
            let source = DispatchSource.makeSignalSource(signal: number, queue: .main)
            source.setEventHandler { [weak self] in self?.stop(exitCode: 0) }
            source.resume(); signals.append(source)
        }
        started = clock.now
        try coordinator.start()
        event("starting", ["pid": getpid(), "image_digest": hex(boot.release.imageDigest), "operations": vm.operations])
        FileHandle.standardInput.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            if data.isEmpty { handle.readabilityHandler = nil }
            Task { @MainActor in self?.input(data) }
        }

    }
    func scheduleUpdate() {
        guard !updateQueued else { return }; updateQueued = true
        DispatchQueue.main.async { self.updateQueued = false; self.update() }
    }
    func update() {
        if stopping, coordinator.phase == .stopped {
            channel.close(); event("stopped", ["operations": vm.operations]); exit(exitCode)
        }
        if coordinator.phase == .running, seeded, !ready, !stopping {
            do {
                let config = try state.pin(hostKey: hostKey)
                try bridge.start(); ready = true
                event("ready", ["ssh_config": config.path, "ssh_stanza": try String(contentsOf: config, encoding: .utf8), "boot_ns": clock.now - started, "mounts": coordinator.mountStatus.count, "host_key": hostKey])
            } catch { fail(error) }
        }
        if let command = pendingCommand {
            if command == "pause", coordinator.phase == .pausedCold {
                pendingCommand = nil
                event("paused", ["generation": coordinator.generation, "fenced": power.lastAcknowledgement?.1 == true, "attach_allowed": coordinator.attachAllowed, "operations": vm.operations])
            } else if command == "resume", coordinator.phase == .running {
                pendingCommand = nil
                event("resumed", ["generation": coordinator.generation, "operations": vm.operations, "mount_states": coordinator.mountStatus.map(\.state)])
            }
        }
        if !stopping, [.unknown, .pausedDiscard, .stopped].contains(coordinator.phase) { fail(WorkspaceVMError("VM unavailable: \(coordinator.phase): \(coordinator.reason)")) }
    }
    func input(_ data: Data) {
        if data.isEmpty { stop(exitCode: 0); return }
        inputBuffer.append(data)
        guard inputBuffer.count <= 8192 else { fail(WorkspaceVMError("oversized dev command")); return }
        while let newline = inputBuffer.firstIndex(of: 10) {
            let line = inputBuffer.prefix(upTo: newline); inputBuffer.removeSubrange(...newline)
            guard let value = try? JSONSerialization.jsonObject(with: line) as? [String: String], let command = value["command"] else { fail(WorkspaceVMError("invalid dev command")); return }
            switch command {
            case "pause":
                guard ready, coordinator.phase == .running, pendingCommand == nil else { event("refused", ["command": command]); continue }
                pendingCommand = command; power.controlledSleep()
            case "resume":
                guard coordinator.phase == .pausedCold, pendingCommand == nil else { event("refused", ["command": command]); continue }
                pendingCommand = command; coordinator.powerEvent(.wake)
            case "replay-resume":
                guard let token = observed.lastResume else { event("refused", ["command": command]); continue }
                channel.resume(token, deadline: clock.now + 20_000_000_000) { [weak self] result in
                    if case .failure(let error) = result { self?.event("replay-refused", ["generation": token.suspension.generation, "reason": String(describing: error)]) }
                    else { self?.fail(WorkspaceVMError("guest accepted consumed token")) }
                }
            case "status": coordinator.refreshStatus(); event("status", ["phase": coordinator.phase.rawValue, "generation": coordinator.generation, "attach_allowed": coordinator.attachAllowed])
            case "stop": stop(exitCode: 0)
            default: event("refused", ["command": command])
            }
        }
    }
    func fail(_ error: Error) { event("failure", ["error": String(describing: error)]); stop(exitCode: 1) }
    func stop(exitCode: Int32) {
        guard !stopping else { coordinator.discardUnknown(); return }; stopping = true; self.exitCode = exitCode
        FileHandle.standardInput.readabilityHandler = nil
        bridge.close(); channel.onFailure = nil
        coordinator.stop(); scheduleUpdate()
    }
}

@main struct WorkspaceDev {
    @MainActor static func main() {
        if CommandLine.arguments.count == 3, CommandLine.arguments[1] == "--verify-artifact" {
            do { _ = try WorkspaceArtifact(directory: URL(fileURLWithPath: CommandLine.arguments[2])); exit(0) }
            catch { fputs("artifact refused: \(error)\n", stderr); exit(1) }
        }
        if CommandLine.arguments == [CommandLine.arguments[0], "--check-virtualization"] {
            guard WorkspaceMachine.virtualizationSupported else { fputs("UNAVAILABLE: native-workspace-virtualization\n", stderr); exit(3) }
            exit(0)
        }
        let args = CommandLine.arguments
        guard args.count == 3 || (args.count == 5 && args[3] == "--pairing-mismatch") else { fputs("usage: portablefs-workspace-dev IMAGE_DIRECTORY STATE_DIRECTORY [--pairing-mismatch version|commit|digest]\n", stderr); exit(2) }
        do {
            let driver = try Driver(image: URL(fileURLWithPath: args[1]), stateDirectory: URL(fileURLWithPath: args[2]), pairingMismatch: args.count == 5 ? args[4] : nil)
            try driver.start(); RunLoop.main.run(); withExtendedLifetime(driver) {}
        } catch { fputs("portablefs-workspace-dev: \(error)\n", stderr); exit(1) }
    }
}
