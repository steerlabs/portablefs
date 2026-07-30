import Foundation

/// Lifecycle of one volume's mount as the app drives it.
///
/// The happy paths are:
/// mount:   unmounted -> mintingSession -> attaching -> mounting -> mounted
/// unmount: mounted -> unmounting -> detaching -> unmounted
///
/// `observedMounted` / `observedUnmounted` reconcile with reality (kernel
/// mount table + daemon attach list) so externally created or removed mounts
/// are reflected without going through the app's own flow.
public enum VolumeMountState: Equatable, Sendable {
    case unmounted
    case mintingSession
    case attaching
    case mounting(attachRef: String)
    case mounted(attachRef: String, mountPath: String)
    case cleanupRequired(mountPath: String, operationPhase: String)
    case unmounting(attachRef: String, mountPath: String)
    case detaching(attachRef: String)
    case failed(message: String)

    public var isBusy: Bool {
        switch self {
        case .mintingSession, .attaching, .mounting, .unmounting, .detaching:
            return true
        case .unmounted, .mounted, .cleanupRequired, .failed:
            return false
        }
    }

    public var isMounted: Bool {
        if case .mounted = self {
            return true
        }
        return false
    }

    public var mountPath: String? {
        switch self {
        case let .mounted(_, path), let .cleanupRequired(path, _), let .unmounting(_, path):
            return path
        default:
            return nil
        }
    }

    public var attachRef: String? {
        switch self {
        case let .mounting(ref), let .detaching(ref),
             let .mounted(ref, _), let .unmounting(ref, _):
            return ref
        default:
            return nil
        }
    }

    public var menuStatusLabel: String {
        switch self {
        case .unmounted:
            return "Not mounted"
        case .mintingSession:
            return "Requesting session…"
        case .attaching:
            return "Attaching…"
        case .mounting:
            return "Mounting…"
        case .mounted:
            return "Mounted"
        case let .cleanupRequired(_, phase):
            return phase.isEmpty ? "Cleanup required" : "Cleanup required (\(phase))"
        case .unmounting:
            return "Unmounting…"
        case .detaching:
            return "Detaching…"
        case let .failed(message):
            return "Failed: \(message)"
        }
    }
}

public enum VolumeMountEvent: Equatable, Sendable {
    case mountRequested
    case sessionMinted
    case attachEnsured(attachRef: String)
    case mountCompleted(mountPath: String)
    case unmountRequested
    case unmountCompleted
    case detachCompleted
    case failed(message: String)
    case observedMounted(attachRef: String, mountPath: String)
    case observedUnmounted
}

public struct MountStateMachine: Equatable, Sendable {
    public private(set) var state: VolumeMountState

    public init(state: VolumeMountState = .unmounted) {
        self.state = state
    }

    /// Applies `event`; returns false (leaving state unchanged) for
    /// transitions that make no sense from the current state, so racing
    /// refreshes cannot corrupt an in-flight operation.
    @discardableResult
    public mutating func apply(_ event: VolumeMountEvent) -> Bool {
        switch (state, event) {
        case (.unmounted, .mountRequested), (.failed, .mountRequested):
            state = .mintingSession
        case (.mintingSession, .sessionMinted):
            state = .attaching
        case let (.attaching, .attachEnsured(ref)):
            state = .mounting(attachRef: ref)
        case let (.mounting(ref), .mountCompleted(path)):
            state = .mounted(attachRef: ref, mountPath: path)
        case let (.mounted(ref, path), .unmountRequested):
            state = .unmounting(attachRef: ref, mountPath: path)
        case let (.unmounting(ref, _), .unmountCompleted):
            state = .detaching(attachRef: ref)
        case (.detaching, .detachCompleted):
            state = .unmounted
        case let (_, .failed(message)) where state.isBusy:
            state = .failed(message: message)
        case let (.unmounted, .observedMounted(ref, path)),
             let (.failed, .observedMounted(ref, path)),
             let (.mounted, .observedMounted(ref, path)):
            state = .mounted(attachRef: ref, mountPath: path)
        case (.mounted, .observedUnmounted), (.cleanupRequired, .observedUnmounted),
             (.failed, .observedUnmounted):
            state = .unmounted
        default:
            return false
        }
        return true
    }
}
