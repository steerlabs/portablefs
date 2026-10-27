import Foundation
import Darwin
import Virtualization

// No network, persistent disk, seed, or service runs in this qualification VM.
// Its initramfs contains only the test binary and empty mount points.
final class RTCQualificationVM: NSObject, VZVirtualMachineDelegate {
    let machine: VZVirtualMachine
    let output = Pipe()
    let input = Pipe()
    var transcript = Data()
    var stopping = false
    var pauseRequested = false
    var referenceProcess: Process?
    var reference: [String: Any]?
    var resumeBegan: UInt64 = 0
    var referenceEmitted = false

    func resumeAfterReference() {
        resumeBegan = clock_gettime_nsec_np(CLOCK_UPTIME_RAW)
        machine.resume { result in
            if case .failure = result { self.finish(1) }
        }
    }

    func collectReference() {
        guard let path = ProcessInfo.processInfo.environment["PFS_RTC_NTS_REFERENCE"] else {
            resumeAfterReference(); return
        }
        let process = Process(), output = Pipe()
        process.executableURL = URL(fileURLWithPath: path)
        process.standardOutput = output
        let began = clock_gettime_nsec_np(CLOCK_UPTIME_RAW)
        process.terminationHandler = { [weak self] process in
            let ended = clock_gettime_nsec_np(CLOCK_UPTIME_RAW)
            let bytes = output.fileHandleForReading.readDataToEndOfFile()
            DispatchQueue.main.async {
                guard let self else { return }
                guard process.terminationStatus == 0,
                      let value = try? JSONSerialization.jsonObject(with: bytes) as? [String: Any],
                      let references = value["references"] else { self.finish(1); return }
                self.reference = ["references": references, "reference_began_ns": began, "reference_ended_ns": ended]
                self.resumeAfterReference()
            }
        }
        referenceProcess = process
        do { try process.run() } catch { finish(1) }
    }

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
        if !pauseRequested, String(decoding: transcript, as: UTF8.self).contains("RTC_PAUSE_ARMED") {
            pauseRequested = true
            machine.pause { [weak self] result in
                guard let self else { return }
                if case .failure = result { self.finish(1); return }
                self.input.fileHandleForWriting.write(Data("probe\n".utf8))
                DispatchQueue.main.asyncAfter(deadline: .now() + 2) {
                    self.collectReference()
                }
            }
        }
        if var reference, !referenceEmitted,
           let line = String(decoding: transcript, as: UTF8.self).components(separatedBy: .newlines).first(where: { $0.hasPrefix("RTC_RESUME_QUALIFICATION=") }),
           let value = try? JSONSerialization.jsonObject(with: Data(line.dropFirst("RTC_RESUME_QUALIFICATION=".count).utf8)) as? [String: Any] {
            referenceEmitted = true
            reference["sample_began_ns"] = resumeBegan
            reference["sample_ended_ns"] = clock_gettime_nsec_np(CLOCK_UPTIME_RAW)
            reference["rtc"] = value["first_after_resume"]
            reference["sample_age_ns"] = value["read_age_ns"]
            if let raw = try? JSONSerialization.data(withJSONObject: reference, options: [.sortedKeys]) {
                print("RTC_NTS_REFERENCE=" + String(decoding: raw, as: UTF8.self))
            } else { finish(1); return }
        }
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
