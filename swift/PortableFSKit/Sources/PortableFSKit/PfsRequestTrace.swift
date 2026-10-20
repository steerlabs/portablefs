import Foundation
import CryptoKit
import os
import Synchronization

/// One local Instruments signpost record, also exposed to the test observer.
///
/// Process-local labels connect FSKit callbacks with their pfslocal requests,
/// replies, ownership dispositions, publication verdicts, and OPEN decisions.
/// A CallbackOperation record binds each callback to its logical operation.
/// These records provide no complete callback inventory, loss accounting, or
/// cross-process correlation guarantee.
///
/// Names use a process-keyed, bounded token: repeated names can be joined
/// inside one capture without publishing names or permitting dictionary probes.
/// Item IDs/file numbers/incarnations carry identity, never capabilities.
/// FSKitContext exposes uid/gid only; caller PID is unavailable.
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

    init(
        _ event: Event,
        connection: String,
        _ fields: KeyValuePairs<String, Any>,
        context: [Field] = []
    ) {
        self.event = event
        self.connection = connection
        self.fields = context + fields.map { Field(key: $0.key, value: String(describing: $0.value)) }
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

    private let fields: [PfsTraceRecord.Field]

    init(kind: StaticString, connection: String, trace: PfsTrace, fields: [PfsTraceRecord.Field] = []) {
        self.fields = fields
        let kind = String(describing: kind)
        let label = trace.allocateCallbackLabel()
        self.label = label
        self.kind = kind
        self.connection = connection
        self.trace = trace
        let began = PfsTraceRecord(
            .callbackBegan,
            connection: connection,
            ["callback": label, "kind": kind], context: fields
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

    func finish(outcome: String, errno: Int? = nil, resultFields: [PfsTraceRecord.Field] = []) {
        let errnoFields = errno.map { [PfsTraceRecord.Field(key: "errno", value: String($0))] } ?? []
        let finished = PfsTraceRecord(
            .callbackFinished,
            connection: connection,
            ["callback": label, "outcome": outcome], context: fields + errnoFields + resultFields
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

/// Fixed-size identity fields only, built when trace collection is active.
enum PfsMetadataTrace {
    private static let nameKey = SymmetricKey(size: .bits256)

    static func identity(_ item: PortableFSItem?, role: String) -> [PfsTraceRecord.Field] {
        guard let item else { return [.init(key: role, value: "unavailable")] }
        return [
            .init(key: "\(role)_local", value: String(item.identity.itemID)),
            .init(key: "\(role)_generation", value: String(item.identity.generation)),
            .init(key: "\(role)_file", value: String(item.fileID)),
        ]
    }

    static func name(_ bytes: Data) -> [PfsTraceRecord.Field] {
        let mac = HMAC<SHA256>.authenticationCode(for: bytes, using: nameKey)
        return [
            .init(key: "name_token", value: mac.prefix(16).map { String(format: "%02x", $0) }.joined()),
            .init(key: "name_bytes", value: String(bytes.count)),
        ]
    }
}
