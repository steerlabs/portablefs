import Foundation
import Observation
import PortableFSAppCore

/// Spawns and supervises `portablefsd` as a child process: locates the
/// binary, restarts it with backoff when it crashes, terminates it on quit,
/// and reports health for the menu.
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
        case waitingToRestart(delaySeconds: Int)
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
    private var backoff = RestartBackoff()
    private var startedAt: Date?
    private var stopping = false
    private var restartTask: Task<Void, Never>?

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
        case let .waitingToRestart(delaySeconds):
            return "Crashed; restarting in \(delaySeconds)s"
        case .failed:
            return "Failed"
        }
    }

    var statusDetail: String {
        switch status {
        case let .failed(message):
            return message
        case .waitingToRestart:
            return lastExitDescription ?? ""
        default:
            return ""
        }
    }

    func start() async {
        stopping = false
        if case .running = status {
            return
        }
        if process?.isRunning == true {
            return
        }

        // Adopt an already-running daemon rather than fight over the sockets.
        if await control.healthz() {
            status = .runningExternal
            healthy = true
            return
        }

        status = .starting
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
        if let log = openLogHandle() {
            child.standardOutput = log
            child.standardError = log
        }
        child.terminationHandler = { [weak self] finished in
            let reason = finished.terminationReason == .uncaughtSignal
                ? "signal \(finished.terminationStatus)"
                : "exit code \(finished.terminationStatus)"
            Task { @MainActor [weak self] in
                self?.handleExit(reason: reason)
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
                healthy = true
                return
            }
            try? await Task.sleep(for: .milliseconds(250))
        }
        healthy = await control.healthz()
    }

    private func handleExit(reason: String) {
        process = nil
        healthy = false
        if stopping {
            status = .stopped
            return
        }
        let uptime = startedAt.map { Date().timeIntervalSince($0) } ?? 0
        lastExitDescription = "portablefsd exited (\(reason)) after \(Int(uptime))s; log: \(logPath)"
        let delay = backoff.delayAfterExit(uptime: uptime)
        status = .waitingToRestart(delaySeconds: Int(delay.rounded()))
        restartTask?.cancel()
        restartTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(delay))
            guard let self, !Task.isCancelled else {
                return
            }
            await self.start()
        }
    }

    @discardableResult
    func checkHealth() async -> Bool {
        healthy = await control.healthz()
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

    func restart() async {
        await stop()
        backoff.reset()
        await start()
    }

    /// SIGTERM (portablefsd flushes and detaches on it), escalate to SIGKILL
    /// after 5 seconds, mirroring the Go CLI's stopMountDaemon.
    func stop() async {
        stopping = true
        restartTask?.cancel()
        restartTask = nil
        guard let child = process, child.isRunning else {
            if case .runningExternal = status {
                // We did not spawn it; leave it alone.
            } else {
                status = .stopped
            }
            healthy = await control.healthz()
            return
        }
        child.terminate()
        let deadline = Date().addingTimeInterval(5)
        while child.isRunning && Date() < deadline {
            try? await Task.sleep(for: .milliseconds(100))
        }
        if child.isRunning {
            kill(child.processIdentifier, SIGKILL)
        }
        process = nil
        status = .stopped
        healthy = false
    }

    var logPath: String {
        (NSHomeDirectory() as NSString).appendingPathComponent("Library/Logs/PortableFS/portablefsd.log")
    }

    private func openLogHandle() -> FileHandle? {
        let directory = (logPath as NSString).deletingLastPathComponent
        try? FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        if !FileManager.default.fileExists(atPath: logPath) {
            FileManager.default.createFile(atPath: logPath, contents: nil)
        }
        guard let handle = FileHandle(forWritingAtPath: logPath) else {
            return nil
        }
        _ = try? handle.seekToEnd()
        return handle
    }
}
