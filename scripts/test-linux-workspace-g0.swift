import Foundation
import Virtualization

// Test-only owner: one exact VM, no persistent disk, network or product power
// owner. The prestarted guest operation is queued only after confirmed pause.
final class G0VM: NSObject, VZVirtualMachineDelegate {
    let machine: VZVirtualMachine
    let output = Pipe(), input = Pipe()
    var buffer = Data(), stopped = false, pausing = false
    var pending: [String:Any]?
    init(kernel: URL, initramfs: URL) throws {
        let c = VZVirtualMachineConfiguration()
        let boot = VZLinuxBootLoader(kernelURL: kernel)
        boot.initialRamdiskURL = initramfs; boot.commandLine = "console=hvc0 rdinit=/init panic=-1"
        c.bootLoader = boot; c.platform = VZGenericPlatformConfiguration()
        c.cpuCount = 4; c.memorySize = 1024 * 1024 * 1024
        c.entropyDevices = [VZVirtioEntropyDeviceConfiguration()]
        let console = VZVirtioConsoleDeviceSerialPortConfiguration()
        console.attachment = VZFileHandleSerialPortAttachment(fileHandleForReading: input.fileHandleForReading, fileHandleForWriting: output.fileHandleForWriting)
        c.serialPorts = [console]; try c.validate()
        machine = VZVirtualMachine(configuration: c); super.init(); machine.delegate = self
        output.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            DispatchQueue.main.async { self?.receive(data) }
        }
    }
    func receive(_ data: Data) {
        guard !stopped else { return }
        FileHandle.standardOutput.write(data); buffer.append(data)
        guard buffer.count < 2 * 1024 * 1024 else { finish(1); return }
        while let end = buffer.firstIndex(of: 10) {
            let line = String(decoding: buffer.prefix(upTo: end), as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)
            buffer.removeSubrange(...end)
            if line == "G0_NATIVE_DONE=0" { finish(0); return }
            if line.hasPrefix("G0_NATIVE_DONE=") { finish(1); return }
            guard line.hasPrefix("G0_PAUSE_ARMED="),
                  let raw = String(line.dropFirst("G0_PAUSE_ARMED=".count)).data(using: .utf8),
                  let value = try? JSONSerialization.jsonObject(with: raw) as? [String: Any],
                  let duration = value["pause_ns"] as? NSNumber, let name = value["case"] as? String else { continue }
            if pausing { pending = value; continue }
            pause(value, name, duration)
        }
    }
    func pause(_ value: [String:Any], _ name: String, _ duration: NSNumber) {
            pausing = true
            machine.pause { [weak self] result in
                guard let self else { return }
                if case .failure = result { self.finish(1); return }
                self.input.fileHandleForWriting.write(Data("probe\n".utf8))
                self.hostEvent("paused", name)
                if name == "g0-vz-schedule-1" {
                    DispatchQueue.main.asyncAfter(deadline: .now()+1.5) { self.hostEvent("authority-expired", name) }
                    DispatchQueue.main.asyncAfter(deadline: .now()+1.75) { self.hostEvent("peer-completion-cut", name) }
                }
                DispatchQueue.main.asyncAfter(deadline: .now()+duration.doubleValue/1_000_000_000) {
                    self.machine.resume { result in
                        if case .failure = result { self.finish(1); return }
                        self.pausing = false; self.hostEvent("resumed", name)
                        if let next = self.pending, let nextName = next["case"] as? String, let nextDuration = next["pause_ns"] as? NSNumber {
                            self.pending = nil; self.pause(next, nextName, nextDuration)
                        }
                    }
                }
            }
    }
    func hostEvent(_ event: String, _ name: String) {
        let value: [String:Any] = ["event":event,"case":name,"host_uptime":ProcessInfo.processInfo.systemUptime]
        if let raw = try? JSONSerialization.data(withJSONObject: value, options: [.sortedKeys]) {
            FileHandle.standardOutput.write(Data("G0_HOST=".utf8)+raw+Data("\n".utf8))
        }
    }
    func finish(_ code: Int32) {
        guard !stopped else { return }; stopped = true
        machine.stop { error in if error != nil { exit(1) }; exit(code) }
    }
    func virtualMachine(_ virtualMachine: VZVirtualMachine, didStopWithError error: Error) { finish(1) }
    func guestDidStop(_ virtualMachine: VZVirtualMachine) { finish(1) }
}
let owner: G0VM
do {
    guard CommandLine.arguments.count == 3 else { exit(2) }
    owner = try G0VM(kernel: URL(fileURLWithPath: CommandLine.arguments[1]), initramfs: URL(fileURLWithPath: CommandLine.arguments[2]))
    owner.machine.start { result in if case .failure = result { owner.finish(1) } }
    DispatchQueue.main.asyncAfter(deadline: .now()+180) { owner.finish(1) }
    RunLoop.main.run()
} catch { fputs("G0 native VM: \(error)\n",stderr); exit(1) }
