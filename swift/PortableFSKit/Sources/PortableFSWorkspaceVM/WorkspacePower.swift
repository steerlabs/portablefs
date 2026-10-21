import Foundation
import Darwin
import IOKit
import IOKit.pwr_mgt
import CWorkspacePower
import PortableFSWorkspaceCore
import Security

@MainActor public final class WorkspaceSystemClock: WorkspaceContinuousClock {
    public init() {}
    public var now: UInt64 { clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) }
    public func schedule(at deadline: UInt64, action: @escaping () -> Void) {
        let remaining = deadline > now ? deadline - now : 0
        Task { @MainActor in
            try? await Task.sleep(for: .nanoseconds(Int64(min(remaining, UInt64(Int64.max)))), clock: .continuous)
            if self.now < deadline { self.schedule(at: deadline, action: action) } else { action() }
        }
    }
}
@MainActor public final class WorkspaceRandom: WorkspaceNonceSource {
    public init() {}
    public func next() -> Data {
        var bytes = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else { return Data() }
        return Data(bytes)
    }
}

@MainActor public final class WorkspaceSystemPower: WorkspacePowerNotifications {
    private var connection: io_connect_t = 0
    private var port: IONotificationPortRef?
    private var notifier: io_object_t = 0
    private var pending: Int?
    private var handler: ((WorkspacePowerEvent) -> Void)?
    public private(set) var registered = false
    public private(set) var acknowledgements: [(UInt64, Bool)] = []
    public init() {}
    public func register(handler: @escaping (WorkspacePowerEvent) -> Void) throws {
        guard !registered else { throw WorkspaceVMError("power notifications already registered") }
        self.handler = handler
        connection = IORegisterForSystemPower(Unmanaged.passUnretained(self).toOpaque(), &port, { context, _, message, argument in
            guard let context else { return }
            MainActor.assumeIsolated {
                Unmanaged<WorkspaceSystemPower>.fromOpaque(context).takeUnretainedValue().receive(message, argument)
            }
        }, &notifier)
        guard connection != 0, let port else { close(); throw WorkspaceVMError("IORegisterForSystemPower unavailable") }
        IONotificationPortSetDispatchQueue(port, .main)
        registered = true
    }
    private func receive(_ message: UInt32, _ argument: UnsafeMutableRawPointer?) {
        let notification = Int(bitPattern: argument)
        switch message {
        case PFSCanSystemSleep: IOAllowPowerChange(connection, notification)
        case PFSSystemWillSleep:
            if let pending { IOAllowPowerChange(connection, pending) }
            pending = notification
            handler?(.sleep)
            // Release participation even when the coordinator is stalled. This
            // timeout is not a fence and makes no unfenced-sleep safety claim.
            let clock = WorkspaceSystemClock()
            clock.schedule(at: clock.now + 21_000_000_000) { [weak self] in
                guard let self, self.pending == notification else { return }
                self.releasePending()
            }
        case PFSSystemWillPowerOn: handler?(.darkWake)
        case PFSSystemHasPoweredOn: handler?(.wake)
        case PFSSystemWillNotSleep: handler?(.cancelledSleep)
        default: break
        }
    }
    public func acknowledgeSleep(generation: UInt64, fenced: Bool) {
        acknowledgements.append((generation, fenced)); releasePending()
    }
    private func releasePending() {
        if let pending { IOAllowPowerChange(connection, pending); self.pending = nil }
    }
    public func close() {
        releasePending()
        if notifier != 0 { IODeregisterForSystemPower(&notifier); notifier = 0 }
        if let port { IONotificationPortDestroy(port); self.port = nil }
        if connection != 0 { IOServiceClose(connection); connection = 0 }
        registered = false; handler = nil
    }
}
