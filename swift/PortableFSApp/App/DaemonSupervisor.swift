import Foundation
import Observation
import PortableFSAppCore

/// Spawns and supervises `portablefsd` as a child process: locates the exact
/// binary, validates its control identity, and reports health for the menu.
/// A crash is a visible terminal failure for this app run; it is never
/// restarted automatically.
///
/// If a daemon is already answering on the control socket at startup (for
/// example one started by hand), the supervisor
/// adopts it instead of spawning a second instance, and leaves it running on
/// quit.
@MainActor
@Observable
final class DaemonSupervisor {
    enum Status: Equatable {
        case stopped
        case starting
        case running(pid: Int32)
        case runningExternal
        case failed(message: String)
    }

    private(set) var status: Status = .stopped
    private(set) var healthy = false
    private(set) var binaryPath: String?
    private(set) var lastExitDescription: String?

    var binaryOverride: String = ""

    let frontendSocketPath = PortableFSAppPaths.devFrontendSocketPath
    let controlSocketPath = PortableFSAppPaths.devControlSocketPath
    let stateDirectory = PortableFSAppPaths.defaultStateDirectory()

    var control: DaemonControlClient {
        DaemonControlClient(socketPath: controlSocketPath)
    }

    private var process: Process?
    private var startedAt: Date?
    private var expectedIdentity: DaemonBinaryIdentity?
    private var suppressedExitPIDs: Set<Int32> = []

    var statusLabel: String {
        switch status {
        case .stopped:
            return "Stopped"
        case .starting:
            return "Starting…"
        case let .running(pid):
            return healthy ? "Running (pid \(pid))" : "Running (pid \(pid), not answering)"
        case .runningExternal:
            return healthy ? "Running (external)" : "External daemon stopped answering"
        case .failed:
            return "Failed"
        }
    }

    var statusDetail: String {
        switch status {
        case let .failed(message):
            return message
        default:
            return ""
        }
    }

    func start() async {
        if case .running = status {
            return
        }
        if process?.isRunning == true {
            return
        }

        let locator = DaemonBinaryLocator(
            userOverride: binaryOverride.isEmpty ? nil : binaryOverride,
            infoPlistPath: Bundle.main.object(forInfoDictionaryKey: "PFSPortableFSDBinaryPath") as? String,
            bundledPath: Bundle.main.resourceURL?.appendingPathComponent("portablefsd").path
        )
        guard let binary = locator.locate() else {
            status = .failed(
                message: "portablefsd not found. Searched:\n" + locator.candidates.joined(separator: "\n") +
                    "\n\nBuild it with: go build -o ~/bin/portablefsd ./cmd/portablefsd (in the Go repo's vcs directory), " +
                    "or set an explicit path in PortableFS Settings."
            )
            healthy = false
            return
        }
        binaryPath = binary
        let targetIdentity: DaemonBinaryIdentity
        do {
            targetIdentity = try DaemonBinaryIdentity(path: binary)
            expectedIdentity = targetIdentity
        } catch {
            status = .failed(message: "Could not inspect \(binary): \(error.localizedDescription)")
            healthy = false
            return
        }

        // Adopt only the exact installed daemon build. Liveness alone is not
        // compatibility: an older in-memory process can keep answering after
        // its on-disk binary has been replaced.
        if await control.healthz() {
            do {
                let running = try await control.identity()
                guard targetIdentity.matches(running) else {
                    status = .failed(
                        message: "A different portablefsd build owns the control socket. " +
                            "Cleanly unmount it with its matching release; PortableFS will not replace it automatically."
                    )
                    healthy = false
                    return
                }
                status = .runningExternal
                healthy = true
                return
            } catch {
                status = .failed(message: "The running portablefsd has no compatible control identity: \(error)")
                healthy = false
                return
            }
        }

        status = .starting

        do {
            try FileManager.default.createDirectory(
                atPath: PortableFSAppPaths.devSocketDirectory,
                withIntermediateDirectories: true
            )
            try FileManager.default.createDirectory(
                atPath: stateDirectory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        } catch {
            status = .failed(message: "Could not create daemon directories: \(error.localizedDescription)")
            healthy = false
            return
        }

        let child = Process()
        child.executableURL = URL(fileURLWithPath: binary)
        child.arguments = [
            "-frontend-socket", frontendSocketPath,
            "-control-socket", controlSocketPath,
            "-state-dir", stateDirectory
        ]
        let log: FileHandle
        do {
            log = try openLogHandle()
        } catch {
            status = .failed(message: "Could not open daemon log \(logPath): \(error.localizedDescription)")
            healthy = false
            return
        }
        child.standardOutput = log
        child.standardError = log
        child.terminationHandler = { [weak self] finished in
            let reason = finished.terminationReason == .uncaughtSignal
                ? "signal \(finished.terminationStatus)"
                : "exit code \(finished.terminationStatus)"
            Task { @MainActor [weak self] in
                self?.handleExit(pid: finished.processIdentifier, reason: reason)
            }
        }
        do {
            try child.run()
        } catch {
            status = .failed(message: "Could not start \(binary): \(error.localizedDescription)")
            healthy = false
            return
        }
        process = child
        startedAt = Date()
        status = .running(pid: child.processIdentifier)

        // Give the sockets a moment to come up, then report health.
        for _ in 0..<20 {
            if await control.healthz() {
                if let running = try? await control.identity(), targetIdentity.matches(running) {
                    healthy = true
                    return
                }
                await rejectSpawned(
                    child,
                    message: "The daemon that answered after startup does not match \(binary)."
                )
                return
            }
            try? await Task.sleep(for: .milliseconds(250))
        }
        await rejectSpawned(
            child,
            message: "portablefsd did not present its exact control identity within 5 seconds."
        )
    }

    private func rejectSpawned(_ child: Process, message: String) async {
        suppressedExitPIDs.insert(child.processIdentifier)
        if child.isRunning {
            child.terminate()
            let deadline = Date().addingTimeInterval(35)
            while child.isRunning && Date() < deadline {
                try? await Task.sleep(for: .milliseconds(100))
            }
        }
        if child.isRunning {
            status = .failed(
                message: message + " The child did not stop within its drain budget and was left running."
            )
        } else {
            if process?.processIdentifier == child.processIdentifier {
                process = nil
            }
            status = .failed(message: message)
        }
        healthy = false
    }

    private func handleExit(pid: Int32, reason: String) {
        if suppressedExitPIDs.remove(pid) != nil {
            if process?.processIdentifier == pid {
                process = nil
            }
            return
        }
        process = nil
        healthy = false
        let uptime = startedAt.map { Date().timeIntervalSince($0) } ?? 0
        let detail = "portablefsd exited (\(reason)) after \(Int(uptime))s; log: \(logPath)"
        lastExitDescription = detail
        status = .failed(
            message: detail + "\nPortableFS did not restart it automatically. " +
                "Inspect the log, cleanly unmount any surviving volume, then relaunch the app."
        )
    }

    @discardableResult
    func checkHealth() async -> Bool {
        if await control.healthz(),
           let expectedIdentity,
           let running = try? await control.identity(),
           expectedIdentity.matches(running) {
            healthy = true
        } else {
            healthy = false
        }
        if healthy {
            // A daemon someone else started (or one that outlived a previous
            // app run) counts as running for the menu and mount flow.
            switch status {
            case .stopped, .failed:
                status = .runningExternal
            default:
                break
            }
        }
        return healthy
    }

    var logPath: String {
        (NSHomeDirectory() as NSString).appendingPathComponent("Library/Logs/PortableFS/portablefsd.log")
    }

    private func openLogHandle() throws -> FileHandle {
        let directory = (logPath as NSString).deletingLastPathComponent
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        if !FileManager.default.fileExists(atPath: logPath) {
            guard FileManager.default.createFile(atPath: logPath, contents: nil) else {
                throw CocoaError(.fileWriteUnknown)
            }
        }
        let handle = try FileHandle(forWritingTo: URL(fileURLWithPath: logPath))
        try handle.seekToEnd()
        return handle
    }
}
