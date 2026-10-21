import Foundation
import Darwin
import PortableFSWorkspaceVM
import PortableFSWorkspaceCore

@MainActor final class Driver {
    let state: WorkspaceDevState
    let vm: WorkspaceMachine
    let power = WorkspaceSystemPower()
    let clock = WorkspaceSystemClock()
    let random = WorkspaceRandom()
    let channel: WorkspaceVsockChannel
    let coordinator: WorkspaceCoordinator
    let bridge: WorkspaceSSHBridge
    let boot: WorkspaceHello
    var seeded = false
    var hostKey = ""
    var ready = false
    var stopping = false
    var started: UInt64 = 0
    var inputBuffer = Data()
    var pendingCommand: String?
    init(image: URL, stateDirectory: URL) throws {
        let artifact = try WorkspaceArtifact(directory: image)
        guard artifact.release.commit == WorkspaceArtifact.hostBuildCommit, artifact.release.appVersion == "dev" else { throw WorkspaceVMError("host executable and guest release differ; rebuild the paired dev executable") }
        state = try WorkspaceDevState(directory: stateDirectory)
        vm = try WorkspaceMachine(artifact: artifact, dataDisk: stateDirectory.appendingPathComponent("data.ext4"), serialLog: stateDirectory.appendingPathComponent("serial.log"))
        channel = WorkspaceVsockChannel(vm: vm); bridge = WorkspaceSSHBridge(vm: vm)
        var hello = WorkspaceHello(); hello.release = artifact.release; hello.bootID = random.next(); hello.hostServiceID = random.next()
        boot = hello
        coordinator = try WorkspaceCoordinator(host: hello, oldInstanceAbsent: true, vm: vm, power: power, channel: channel, clock: clock, nonces: random)
        vm.onSeed = { [weak self] event in self?.seedEvent(event) }
        channel.onFailure = { [weak self] in self?.coordinator.powerEvent(.unknown) }
    }
    func event(_ name: String, _ fields: [String: Any] = [:]) {
        var value = fields; value["event"] = name; value["continuous_ns"] = clock.now
        if let data = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) { FileHandle.standardOutput.write(data); FileHandle.standardOutput.write(Data([10])) }
    }
    func seedEvent(_ value: [String: String]) {
        do {
            switch value["event"] {
            case "seed-ready": try vm.seed(["boot_id": hex(boot.bootID), "host_service_id": hex(boot.hostServiceID), "authorized_key": state.authorizedKey])
            case "seeded":
                guard value["boot_id"] == hex(boot.bootID), let key = value["host_key"] else { throw WorkspaceVMError("seed identity mismatch") }
                hostKey = key; seeded = true
            default: throw WorkspaceVMError("invalid boot console message")
            }
        } catch { fail(error) }
    }
    func start() throws {
        started = clock.now
        try coordinator.start()
        event("starting", ["pid": getpid(), "image_digest": hex(boot.release.imageDigest), "power_registered": power.registered])
        FileHandle.standardInput.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            Task { @MainActor in self?.input(data) }
        }
        tick()
    }
    func tick() {
        if coordinator.phase == .running, seeded, !ready {
            ready = true
            channel.status { [weak self] result in
                guard let self else { return }
                do {
                    let status = try result.get()
                    try self.coordinator.setRoster(status.mounts.map(\.mount))
                    // Verify the pin before creating a host TCP listener.
                    _ = try self.state.pin(hostKey: self.hostKey, port: 0)
                    try self.bridge.start()
                    let config = try self.state.pin(hostKey: self.hostKey, port: self.bridge.port)
                    self.event("ready", ["ssh_config": config.path, "ssh_stanza": try String(contentsOf: config, encoding: .utf8), "port": self.bridge.port, "boot_ns": self.clock.now - self.started, "mounts": status.mounts.count])
                } catch { self.fail(error) }
            }
        }
        if let pendingCommand {
            if pendingCommand == "pause", coordinator.phase == .pausedCold {
                self.pendingCommand = nil
                event("paused", ["generation": coordinator.generation, "fenced": power.acknowledgements.last?.1 == true, "attach_allowed": coordinator.attachAllowed, "operations": vm.operations])
            } else if pendingCommand == "resume", coordinator.phase == .running {
                self.pendingCommand = nil
                event("resumed", ["generation": coordinator.generation, "operations": vm.operations, "mount_states": coordinator.mountStatus.map(\.state)])
            }
        }
        if [.unknown, .pausedDiscard].contains(coordinator.phase) { fail(WorkspaceVMError("unsafe VM state: \(coordinator.phase): \(coordinator.reason)")); return }
        if !ready, clock.now - started > 150_000_000_000 { fail(WorkspaceVMError("boot timed out")); return }
        if !stopping, coordinator.phase == .stopped { fail(WorkspaceVMError("coordinator stopped: \(coordinator.reason)")); return }
        if !stopping { DispatchQueue.main.asyncAfter(deadline: .now() + .milliseconds(20)) { self.tick() } }
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
                pendingCommand = command; coordinator.powerEvent(.sleep)
            case "resume":
                guard coordinator.phase == .pausedCold, pendingCommand == nil else { event("refused", ["command": command]); continue }
                pendingCommand = command; coordinator.powerEvent(.wake)
            case "status":
                event("status", ["phase": coordinator.phase.rawValue, "generation": coordinator.generation, "attach_allowed": coordinator.attachAllowed])
            case "stop": stop(exitCode: 0)
            default: event("refused", ["command": command])
            }
        }
    }
    func fail(_ error: Error) { event("failure", ["error": String(describing: error)]); stop(exitCode: 1) }
    func stop(exitCode: Int32) {
        guard !stopping else { return }; stopping = true
        bridge.close(); channel.onFailure = nil
        let finished: (Result<Void, Error>) -> Void = { [self] result in
            channel.close()
            power.close()
            switch result {
            case .success: event("stopped", ["operations": vm.operations]); exit(exitCode)
            case .failure(let error): event("failure", ["error": String(describing: error)]); exit(1)
            }
        }
        if exitCode == 0, coordinator.phase == .running { vm.shutdown(completion: finished) }
        else { vm.stop(completion: finished) }
    }
}

@main struct WorkspaceDev {
    @MainActor static func main() {
        if CommandLine.arguments == [CommandLine.arguments[0], "--check-virtualization"] {
            guard WorkspaceMachine.virtualizationSupported else { fputs("UNAVAILABLE: native-workspace-virtualization\n", stderr); exit(3) }
            exit(0)
        }
        guard CommandLine.arguments.count == 3 else { fputs("usage: portablefs-workspace-dev IMAGE_DIRECTORY STATE_DIRECTORY\n", stderr); exit(2) }
        do {
            let driver = try Driver(image: URL(fileURLWithPath: CommandLine.arguments[1]), stateDirectory: URL(fileURLWithPath: CommandLine.arguments[2]))
            try driver.start()
            RunLoop.main.run()
            withExtendedLifetime(driver) {}
        } catch { fputs("portablefs-workspace-dev: \(error)\n", stderr); exit(1) }
    }
}
