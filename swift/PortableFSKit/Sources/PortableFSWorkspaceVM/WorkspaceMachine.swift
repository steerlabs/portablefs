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
    private var shutdownCompletion: ((Result<Void, Error>) -> Void)?

    public init(artifact: WorkspaceArtifact, dataDisk: URL, serialLog: URL) throws {
        guard VZVirtualMachine.isSupported else { throw WorkspaceVMError("UNAVAILABLE: native-workspace-virtualization") }
        #if !arch(arm64)
        throw WorkspaceVMError("UNAVAILABLE: native-workspace-apple-silicon")
        #endif
        let config = VZVirtualMachineConfiguration()
        let boot = VZLinuxBootLoader(kernelURL: artifact.directory.appendingPathComponent("kernel"))
        boot.initialRamdiskURL = artifact.directory.appendingPathComponent("initramfs")
        boot.commandLine = "console=hvc0 root=/dev/vda ro rootfstype=ext4 panic=-1 systemd.show_status=1"
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
            if !data.isEmpty { try? log.write(contentsOf: data) }
        }
        seedOutput.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
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
        socket.connect(toPort: port, completionHandler: completion)
    }
    public func start(completion: @escaping (Result<Void, Error>) -> Void) {
        operations.append("start-request")
        machine.start { [weak self] result in self?.operations.append("start-completed"); completion(result) }
    }
    public func pause(completion: @escaping (Result<Void, Error>) -> Void) {
        operations.append("pause-request")
        machine.pause { [weak self] result in self?.operations.append("pause-completed"); completion(result) }
    }
    public func resume(completion: @escaping (Result<Void, Error>) -> Void) {
        operations.append("resume-request")
        machine.resume { [weak self] result in self?.operations.append("resume-completed"); completion(result) }
    }
    public func stop(completion: @escaping (Result<Void, Error>) -> Void) {
        if machine.state == .stopped { completion(.success(())); return }
        operations.append("stop-request")
        machine.stop { [weak self] error in
            self?.operations.append("stop-completed")
            if let error { completion(.failure(error)) } else { completion(.success(())) }
        }
    }
    public func shutdown(completion: @escaping (Result<Void, Error>) -> Void) {
        guard machine.canRequestStop, shutdownCompletion == nil else { completion(.failure(WorkspaceVMError("guest shutdown unavailable"))); return }
        shutdownCompletion = completion
        do {
            operations.append("shutdown-request")
            try machine.requestStop()
            DispatchQueue.main.asyncAfter(deadline: .now() + .seconds(20)) { [weak self] in
                guard let self, let callback = self.shutdownCompletion else { return }
                self.shutdownCompletion = nil
                self.stop { _ in callback(.failure(WorkspaceVMError("clean guest shutdown timed out"))) }
            }
        } catch { shutdownCompletion = nil; completion(.failure(error)) }
    }
    public func guestDidStop(_ virtualMachine: VZVirtualMachine) {
        guard virtualMachine === machine else { return }
        operations.append("shutdown-completed")
        let callback = shutdownCompletion; shutdownCompletion = nil
        callback?(.success(()))
    }
    public func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error) {
        let callback = shutdownCompletion; shutdownCompletion = nil
        callback?(.failure(error))
    }
}

enum WorkspaceSocket {
    static func wait(_ fd: Int32, _ event: Int16, deadline: UInt64) throws {
        while true {
            let now = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)
            guard now < deadline else { throw WorkspaceVMError("vsock operation timed out") }
            var p = pollfd(fd: fd, events: event, revents: 0)
            let result = poll(&p, 1, Int32(min((deadline - now) / 1_000_000 + 1, 1000)))
            if result > 0 { return }
            if result < 0 && errno != EINTR { throw WorkspaceVMError("vsock poll failed: \(errno)") }
        }
    }
    static func read(_ fd: Int32, count: Int, deadline: UInt64) throws -> Data {
        var data = Data(count: count)
        var offset = 0
        while offset < count {
            try wait(fd, Int16(POLLIN), deadline: deadline)
            let n = data.withUnsafeMutableBytes { Darwin.read(fd, $0.baseAddress?.advanced(by: offset), count - offset) }
            if n < 0 && [EINTR, EAGAIN].contains(errno) { continue }
            guard n > 0 else { throw WorkspaceVMError("control channel closed") }; offset += n
        }
        return data
    }
    static func write(_ fd: Int32, data: Data, deadline: UInt64) throws {
        var offset = 0
        while offset < data.count {
            try wait(fd, Int16(POLLOUT), deadline: deadline)
            let n = data.withUnsafeBytes { Darwin.write(fd, $0.baseAddress?.advanced(by: offset), data.count - offset) }
            if n < 0 && [EINTR, EAGAIN].contains(errno) { continue }
            guard n > 0 else { throw WorkspaceVMError("control write failed: \(errno)") }; offset += n
        }
    }
}
