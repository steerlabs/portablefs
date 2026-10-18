import Foundation
import os
import Synchronization

/// One record of the correlation trace for the measured LAN workload.
///
/// The trace joins an FSKit callback to the pfslocal requests it issued,
/// their replies, ownership dispositions and publication verdicts, and its
/// OPEN decisions by explicit labels, never by timing or thread:
///
/// - Every record names its connection by an opaque label, the connection's
///   UUID. Request IDs restart at 1 in every client and operation IDs at 1 on
///   every connection, so when several volumes share one extension process
///   only (connection, request) and (connection, operation) pairs are unique.
/// - Every FSKit callback carries a process-unique callback label. Its
///   requests and OPEN decisions repeat that label, and the operation it binds
///   is announced exactly once by a CallbackOperation record.
///
/// Records carry labels, IDs, request kinds, errnos and access modes only: no
/// names, contents or credentials.
struct PfsTraceRecord: Sendable, Equatable {
    enum Event: String, Sendable {
        case callbackBegan = "CallbackBegan"
        case callbackFinished = "CallbackFinished"
        case callbackOperation = "CallbackOperation"
        case dispatched = "Dispatched"
        case replied = "Replied"
        case disposition = "Disposition"
        case publicationAck = "PublicationAck"
        case openDecision = "OpenDecision"
    }

    struct Field: Sendable, Equatable {
        let key: String
        let value: String
    }

    let event: Event
    let connection: String
    let fields: [Field]

    init(_ event: Event, connection: String, _ fields: KeyValuePairs<String, Any>) {
        self.event = event
        self.connection = connection
        self.fields = fields.map { Field(key: $0.key, value: String(describing: $0.value)) }
    }

    func value(_ key: String) -> String? {
        fields.first { $0.key == key }?.value
    }

    var message: String {
        (["connection=\(connection)"] + fields.map { "\($0.key)=\($0.value)" })
            .joined(separator: " ")
    }
}

/// The trace's single emission point for one pfslocal client and the volume
/// above it. Inactive unless a signpost collector is attached or a test
/// installed an observer; a record is only built when something consumes it.
struct PfsTrace: Sendable {
    typealias Observer = @Sendable (PfsTraceRecord) -> Void

    /// The deterministic seam the trace-join tests read. Nil in production.
    let observer: Observer?

    private static let requestSignposter = OSSignposter(
        subsystem: "dev.portablefs.fskit",
        category: "PfsLocalRequest"
    )
    private static let openSignposter = OSSignposter(
        subsystem: "dev.portablefs.fskit",
        category: "OpenAttribution"
    )
    fileprivate static let callbackSignposter = OSSignposter(
        subsystem: "dev.portablefs.fskit",
        category: "CallbackLifecycle"
    )
    private static let nextCallbackLabel = Atomic<UInt64>(1)

    var isActive: Bool {
        observer != nil
            || Self.requestSignposter.isEnabled
            || Self.openSignposter.isEnabled
            || Self.callbackSignposter.isEnabled
    }

    func emit(_ build: () -> PfsTraceRecord) {
        guard isActive else { return }
        let record = build()
        switch record.event {
        case .openDecision:
            if Self.openSignposter.isEnabled {
                Self.openSignposter.emitEvent("OpenDecision", "\(record.message, privacy: .public)")
            }
        case .callbackBegan, .callbackFinished:
            // Signposts carry these as the callback interval's own begin and
            // end; see PfsCallbackTrace.
            break
        default:
            if Self.requestSignposter.isEnabled {
                let message = record.message
                switch record.event {
                case .callbackOperation:
                    Self.requestSignposter.emitEvent("CallbackOperation", "\(message, privacy: .public)")
                case .dispatched:
                    Self.requestSignposter.emitEvent("Dispatched", "\(message, privacy: .public)")
                case .replied:
                    Self.requestSignposter.emitEvent("Replied", "\(message, privacy: .public)")
                case .disposition:
                    Self.requestSignposter.emitEvent("Disposition", "\(message, privacy: .public)")
                case .publicationAck:
                    Self.requestSignposter.emitEvent("PublicationAck", "\(message, privacy: .public)")
                case .openDecision, .callbackBegan, .callbackFinished:
                    break
                }
            }
        }
        observer?(record)
    }

    /// A process-unique callback label, or zero while the trace is inactive.
    func allocateCallbackLabel() -> UInt64 {
        guard isActive else { return 0 }
        return Self.nextCallbackLabel.wrappingAdd(1, ordering: .relaxed).oldValue
    }
}

/// One FSKit callback's trace interval. Its label is what the callback's
/// requests and OPEN decisions repeat.
struct PfsCallbackTrace: Sendable {
    let label: UInt64
    let kind: String
    private let connection: String
    private let trace: PfsTrace
    private let interval: (OSSignpostID, OSSignpostIntervalState)?

    init(kind: StaticString, connection: String, trace: PfsTrace) {
        let kind = String(describing: kind)
        let label = trace.allocateCallbackLabel()
        self.label = label
        self.kind = kind
        self.connection = connection
        self.trace = trace
        let began = PfsTraceRecord(
            .callbackBegan,
            connection: connection,
            ["callback": label, "kind": kind]
        )
        if PfsTrace.callbackSignposter.isEnabled {
            let id = PfsTrace.callbackSignposter.makeSignpostID()
            let state = PfsTrace.callbackSignposter.beginInterval(
                "FSKitCallback",
                id: id,
                "\(began.message, privacy: .public)"
            )
            interval = (id, state)
        } else {
            interval = nil
        }
        trace.emit { began }
    }

    func emit(_ name: StaticString) {
        guard let (id, _) = interval else { return }
        PfsTrace.callbackSignposter.emitEvent(
            name,
            id: id,
            "callback=\(label) kind=\(kind, privacy: .public)"
        )
    }

    func finish(outcome: String) {
        let finished = PfsTraceRecord(
            .callbackFinished,
            connection: connection,
            ["callback": label, "outcome": outcome]
        )
        if let (_, state) = interval {
            PfsTrace.callbackSignposter.endInterval(
                "FSKitCallback",
                state,
                "\(finished.message, privacy: .public)"
            )
        }
        trace.emit { finished }
    }
}
