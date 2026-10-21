import Foundation
import Darwin
@preconcurrency import Virtualization
import PortableFSWorkspaceCore

@MainActor public final class WorkspaceMachine: NSObject, WorkspaceVirtualMachine, @preconcurrency VZVirtualMachineDelegate {
    public static var virtualizationSupported: Bool { VZVirtualMachine.isSupported }
    public let machine: VZVirtualMachine
    private let seedInput = Pipe()
    private let seedOutput = Pipe()
    private let serialInput = Pipe()
    private let serialOutput = Pipe()
    private var seedBuffer = Data()
    public var onSeed: (([String: String]) -> Void)?
    public private(set) var operations: [String] = []
    public var onStopped: ((String) -> Void)?
    public func record(_ operation: String) {
        if operations.count == 256 { operations.removeFirst() }
        operations.append(operation)
    }
    // VZ rejects overlapping lifecycle operations even on its serial owner
    // queue. Completion, not submission order, releases the next operation.
    private var operationQueue: [() -> Void] = []
    private var operationActive = false
    private func enqueue(_ operation: @escaping (@escaping () -> Void) -> Void) {
        operationQueue.append { operation {
            self.operationActive = false; self.advance()
        } }
        advance()
    }
    private func advance() {
        guard !operationActive, !operationQueue.isEmpty else { return }
        operationActive = true
        operationQueue.removeFirst()()
    }
    private var shutdownID: UUID?
    private var shutdownCompletion: ((Result<Void, Error>) -> Void)?

    public init(artifact: WorkspaceArtifact, dataDisk: URL, serialLog: URL, machineID: String, macAddress: String) throws {
        guard VZVirtualMachine.isSupported else { throw WorkspaceVMError("UNAVAILABLE: native-workspace-virtualization") }
        #if !arch(arm64)
        throw WorkspaceVMError("UNAVAILABLE: native-workspace-apple-silicon")
        #endif
        let config = VZVirtualMachineConfiguration()
        let boot = VZLinuxBootLoader(kernelURL: artifact.directory.appendingPathComponent("kernel"))
        boot.initialRamdiskURL = artifact.directory.appendingPathComponent("initramfs")
        boot.commandLine = "console=hvc0 root=/dev/vda ro rootfstype=ext4 panic=-1 systemd.show_status=1 systemd.machine_id=\(machineID)"
        config.bootLoader = boot
        config.platform = VZGenericPlatformConfiguration()
        let large = ProcessInfo.processInfo.physicalMemory >= 16 * 1024 * 1024 * 1024
        config.cpuCount = min(large ? 4 : 2, VZVirtualMachineConfiguration.maximumAllowedCPUCount)
        config.memorySize = min(UInt64(large ? 4 : 2) * 1024 * 1024 * 1024, VZVirtualMachineConfiguration.maximumAllowedMemorySize)
        config.storageDevices = try [
            VZVirtioBlockDeviceConfiguration(attachment: VZDiskImageStorageDeviceAttachment(url: artifact.directory.appendingPathComponent("system.ext4"), readOnly: true)),
            VZVirtioBlockDeviceConfiguration(attachment: VZDiskImageStorageDeviceAttachment(url: dataDisk, readOnly: false))
        ]
        let network = VZVirtioNetworkDeviceConfiguration()
        guard let address = VZMACAddress(string: macAddress) else { throw WorkspaceVMError("invalid persistent MAC") }
        network.macAddress = address
        network.attachment = VZNATNetworkDeviceAttachment()
        config.networkDevices = [network]
        config.socketDevices = [VZVirtioSocketDeviceConfiguration()]
        config.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
        let serial = VZVirtioConsoleDeviceSerialPortConfiguration()
        serial.attachment = VZFileHandleSerialPortAttachment(fileHandleForReading: serialInput.fileHandleForReading, fileHandleForWriting: serialOutput.fileHandleForWriting)
        let seed = VZVirtioConsoleDeviceSerialPortConfiguration()
        seed.attachment = VZFileHandleSerialPortAttachment(fileHandleForReading: seedInput.fileHandleForReading, fileHandleForWriting: seedOutput.fileHandleForWriting)
        config.serialPorts = [serial, seed]
        try config.validate()
        machine = VZVirtualMachine(configuration: config, queue: .main)
        super.init()
        machine.delegate = self
        FileManager.default.createFile(atPath: serialLog.path, contents: nil)
        let log = try FileHandle(forWritingTo: serialLog)
        serialOutput.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            if data.isEmpty { handle.readabilityHandler = nil; try? log.close(); return }
            // The serial transcript is diagnostic, never an unbounded disk sink.
            if let offset = try? log.offset(), offset < 8 * 1024 * 1024 { try? log.write(contentsOf: data.prefix(Int(8 * 1024 * 1024 - offset))) }
        }
        seedOutput.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            if data.isEmpty { handle.readabilityHandler = nil; return }
            Task { @MainActor in self?.receiveSeed(data) }
        }
    }
    private func receiveSeed(_ data: Data) {
        seedBuffer.append(data)
        guard seedBuffer.count <= 8192 else { onSeed?(["event":"invalid"]); seedBuffer.removeAll(); return }
        while let newline = seedBuffer.firstIndex(of: 10) {
            let line = seedBuffer.prefix(upTo: newline)
            seedBuffer.removeSubrange(...newline)
            if let object = try? JSONSerialization.jsonObject(with: line) as? [String: String] { onSeed?(object) }
        }
    }
    public func seed(_ payload: [String: String]) throws {
        var data = try JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]); data.append(10)
        try seedInput.fileHandleForWriting.write(contentsOf: data)
    }
    public func connect(port: UInt32, completion: @escaping (Result<VZVirtioSocketConnection, Error>) -> Void) {
        guard let socket = machine.socketDevices.first as? VZVirtioSocketDevice else { completion(.failure(WorkspaceVMError("missing vsock"))); return }
        socket.connect(toPort: port) { result in Task { @MainActor in completion(result) } }
    }
    public func start(completion: @escaping (Result<Void, Error>) -> Void) {
        record("start-request")
        enqueue { done in self.machine.start { result in self.record("start-completed"); completion(result); done() } }
    }
    public func pause(completion: @escaping (Result<Void, Error>) -> Void) {
        record("pause-request")
        enqueue { done in self.machine.pause { result in self.record("pause-completed"); completion(result); done() } }
    }
    public func resume(completion: @escaping (Result<Void, Error>) -> Void) {
        record("resume-request")
        enqueue { done in self.machine.resume { result in self.record("resume-completed"); completion(result); done() } }
    }
    public func stop(completion: @escaping (Result<Void, Error>) -> Void) {
        record("stop-request")
        enqueue { done in
            if self.machine.state == .stopped { completion(.success(())); done(); return }
            self.machine.stop { error in
                self.record("stop-completed")
                completion(error.map { .failure($0) } ?? .success(())); done()
            }
        }
    }
    public func inspect(completion: @escaping (WorkspaceVMState) -> Void) {
        switch machine.state {
        case .stopped: completion(.stopped)
        case .running: completion(.running)
        case .paused: completion(.paused)
        default: completion(.unknown)
        }
    }
    public func shutdown(completion: @escaping (Result<Void, Error>) -> Void) {
        enqueue { done in self.requestShutdown { result in completion(result); done() } }
    }
    private func requestShutdown(completion: @escaping (Result<Void, Error>) -> Void) {
        guard machine.canRequestStop, shutdownCompletion == nil else { completion(.failure(WorkspaceVMError("guest shutdown unavailable"))); return }
        let id = UUID(); shutdownID = id
        shutdownCompletion = completion
        do {
            record("shutdown-request")
            try machine.requestStop()
            DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(20)) { [weak self] in
                guard let self, self.shutdownID == id, let callback = self.shutdownCompletion else { return }
                self.shutdownCompletion = nil
                callback(.failure(WorkspaceVMError("clean guest shutdown timed out")))
            }
        } catch { shutdownCompletion = nil; completion(.failure(error)) }
    }
    public func guestDidStop(_ virtualMachine: VZVirtualMachine) {
        guard virtualMachine === machine else { return }
        let callback = shutdownCompletion; shutdownCompletion = nil; shutdownID = nil
        record(callback == nil ? "vm-stopped" : "shutdown-completed")
        if let callback { callback(.success(())) } else { onStopped?("guest stopped unexpectedly") }
    }
    public func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error) {
        guard virtualMachine === machine else { return }
        record("vm-stopped-error")
        let callback = shutdownCompletion; shutdownCompletion = nil; shutdownID = nil
        callback?(.failure(error)); onStopped?("VM stopped: \(error)")
    }
}
