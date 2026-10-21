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
    private var pending: [UInt64: Int] = [:]
    private var nextID: UInt64 = 0
    public var onRecord: ((String) -> Void)?
    private var handler: ((WorkspacePowerEvent) -> Void)?
    public private(set) var registered = false
    public private(set) var lastAcknowledgement: (UInt64, Bool)?
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
        guard connection != 0, let port else { unregister(); throw WorkspaceVMError("IORegisterForSystemPower unavailable") }
        IONotificationPortSetDispatchQueue(port, .main)
        registered = true; onRecord?("power-registered")
    }
    private func receive(_ message: UInt32, _ argument: UnsafeMutableRawPointer?) {
        let notification = Int(bitPattern: argument)
        switch message {
        case PFSCanSystemSleep: IOAllowPowerChange(connection, notification)
        case PFSSystemWillSleep:
            let arrivedAt = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)
            guard nextID < UInt64.max else { handler?(.unknown); IOAllowPowerChange(connection, notification); return }
            nextID += 1; pending[nextID] = notification
            handler?(.sleep(WorkspaceSleepNotification(id: nextID, arrivedAt: arrivedAt)))
        case PFSSystemWillPowerOn: break // This is advance wake notice, not evidence of dark wake.
        case PFSSystemHasPoweredOn: handler?(.wake)
        case PFSSystemWillNotSleep: handler?(.cancelledSleep)
        default: break
        }
    }
    public func acknowledgeSleep(notificationID: UInt64, fenced: Bool) {
        lastAcknowledgement = (notificationID, fenced)
        onRecord?(fenced ? "sleep-fenced" : "sleep-released-unfenced")
        if let notification = pending.removeValue(forKey: notificationID) { IOAllowPowerChange(connection, notification) }
    }
    // Development controlled pauses share the adapter's monotone ID space.
    public func controlledSleep() {
        nextID += 1
        handler?(.sleep(WorkspaceSleepNotification(id: nextID, arrivedAt: clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW))))
    }
    public func unregister() {
        for id in pending.keys.sorted() { acknowledgeSleep(notificationID: id, fenced: false) }
        if notifier != 0 { IODeregisterForSystemPower(&notifier); notifier = 0 }
        if let port { IONotificationPortDestroy(port); self.port = nil }
        if connection != 0 { IOServiceClose(connection); connection = 0 }
        registered = false; handler = nil
    }
}
