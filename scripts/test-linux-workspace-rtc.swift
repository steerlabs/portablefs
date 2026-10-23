import Foundation
import Virtualization

// No network, persistent disk, seed, or service runs in this qualification VM.
// Its initramfs contains only the test binary and empty mount points.
final class RTCQualificationVM: NSObject, VZVirtualMachineDelegate {
    let machine: VZVirtualMachine
    let output = Pipe()
    let input = Pipe()
    var transcript = Data()
    var stopping = false

    init(kernel: URL, initramfs: URL) throws {
        let configuration = VZVirtualMachineConfiguration()
        let boot = VZLinuxBootLoader(kernelURL: kernel)
        boot.initialRamdiskURL = initramfs
        boot.commandLine = "console=hvc0 rdinit=/init panic=-1"
        configuration.bootLoader = boot
        configuration.platform = VZGenericPlatformConfiguration()
        configuration.cpuCount = 4
        configuration.memorySize = 512 * 1024 * 1024
        configuration.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
        let console = VZVirtioConsoleDeviceSerialPortConfiguration()
        console.attachment = VZFileHandleSerialPortAttachment(fileHandleForReading: input.fileHandleForReading, fileHandleForWriting: output.fileHandleForWriting)
        configuration.serialPorts = [console]
        try configuration.validate()
        machine = VZVirtualMachine(configuration: configuration)
        super.init()
        machine.delegate = self
        output.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            DispatchQueue.main.async { self?.receive(data) }
        }
    }
    func receive(_ data: Data) {
        guard !stopping else { return }
        transcript.append(data)
        FileHandle.standardOutput.write(data)
        if transcript.count > 1024 * 1024 { finish(1); return }
        if String(decoding: transcript, as: UTF8.self).contains("PASS: rtc-contention-qualification\r\n") || String(decoding: transcript, as: UTF8.self).contains("PASS: rtc-contention-qualification\n") {
            finish(0)
        }
    }
    func finish(_ status: Int32) {
        guard !stopping else { return }
        stopping = true
        machine.stop { result in
            if let error = result { fputs("stop RTC VM: \(error)\n", stderr); exit(1) }
            exit(status)
        }
    }
    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error) {
        fputs("RTC VM failed: \(error)\n", stderr); exit(1)
    }
    func guestDidStop(_ virtualMachine: VZVirtualMachine) { exit(1) }
}

let runner: RTCQualificationVM
 do {
    guard CommandLine.arguments.count == 3 else { throw NSError(domain: "RTC qualification arguments", code: 1) }
    runner = try RTCQualificationVM(kernel: URL(fileURLWithPath: CommandLine.arguments[1]), initramfs: URL(fileURLWithPath: CommandLine.arguments[2]))
    runner.machine.start { result in
        if case .failure(let error) = result { fputs("start RTC VM: \(error)\n", stderr); exit(1) }
    }
    DispatchQueue.main.asyncAfter(deadline: .now() + 90) { runner.finish(1) }
    RunLoop.main.run()
} catch {
    fputs("RTC qualification: \(error)\n", stderr); exit(1)
}
