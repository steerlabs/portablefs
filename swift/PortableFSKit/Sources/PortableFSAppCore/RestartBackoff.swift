import Foundation

/// Crash-restart policy for the supervised daemon: exponential backoff capped
/// at `maximumDelay`, reset once a run stays healthy for `healthyRunThreshold`.
public struct RestartBackoff: Equatable, Sendable {
    public var baseDelay: TimeInterval
    public var multiplier: Double
    public var maximumDelay: TimeInterval
    public var healthyRunThreshold: TimeInterval
    public private(set) var consecutiveFailures: Int

    public init(
        baseDelay: TimeInterval = 0.5,
        multiplier: Double = 2,
        maximumDelay: TimeInterval = 30,
        healthyRunThreshold: TimeInterval = 30
    ) {
        self.baseDelay = baseDelay
        self.multiplier = multiplier
        self.maximumDelay = maximumDelay
        self.healthyRunThreshold = healthyRunThreshold
        consecutiveFailures = 0
    }

    /// Records a daemon exit after `uptime` seconds and returns how long to
    /// wait before the next restart attempt.
    public mutating func delayAfterExit(uptime: TimeInterval) -> TimeInterval {
        if uptime >= healthyRunThreshold {
            consecutiveFailures = 0
        }
        let delay = min(maximumDelay, baseDelay * pow(multiplier, Double(consecutiveFailures)))
        consecutiveFailures += 1
        return delay
    }

    public mutating func reset() {
        consecutiveFailures = 0
    }
}
