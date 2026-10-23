import Foundation
import SwiftProtobuf

public enum WorkspaceControlError: Error { case grammar, pairing, transition }

public enum WorkspaceControl {
    public static let version: UInt32 = 8
    public static let maxFrame = 2 << 20
    public static let maxLosses = 32
    public static let maxReason = 256
    public static let maxDrainBudget: UInt64 = 15_000_000_000
    public static let aggregateReason = "additional accepted-tail loss (aggregated)"
    public static func id(_ value: Data) -> Bool { value.count == 16 && value.contains { $0 != 0 } }
    public static func digest(_ value: Data) -> Bool { value.count == 32 && value.contains { $0 != 0 } }
    public static func mountKey(_ mount: WorkspaceMountID) -> String {
        mount.authorityID.map { String(format: "%02x", $0) }.joined() + "/" + mount.volumeID + "/" +
        mount.incarnation.map { String(format: "%02x", $0) }.joined()
    }
    public static func validMount(_ mount: WorkspaceMountID) -> Bool {
        digest(mount.authorityID) && id(mount.incarnation) && !mount.volumeID.isEmpty &&
        mount.volumeID.utf8.count <= 128 && mount.volumeID.utf8.allSatisfy {
            (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0) || [45, 46, 95].contains($0)
        } && mount.volumeID != "." && mount.volumeID != ".." &&
        !mount.volumeID.contains("/") && !mount.volumeID.contains("\0")
    }
    public static func validRoster(_ roster: [WorkspaceMountID]) -> Bool {
        guard roster.count <= 64, roster.allSatisfy(validMount) else { return false }
        let keys = roster.map(mountKey)
        let volumes = roster.map { $0.authorityID.base64EncodedString() + "/" + $0.volumeID }
        return keys == keys.sorted() && Set(keys).count == keys.count && Set(volumes).count == volumes.count
    }
    public static func validSuspension(_ s: WorkspaceSuspension) -> Bool {
        id(s.bootID) && id(s.hostServiceID) && id(s.guestServiceID) && s.generation > 0 && id(s.nonce) && validRoster(s.roster)
    }
    public static func validRelease(_ r: WorkspaceRelease) -> Bool {
        r.authorityMajor == 8 && !r.appVersion.isEmpty && r.appVersion.utf8.count <= 128 && r.appVersion.utf8.allSatisfy { (33...126).contains($0) } &&
        r.commit.utf8.count == 40 && r.commit.utf8.allSatisfy { (48...57).contains($0) || (97...102).contains($0) } && digest(r.imageDigest)
    }
    private static func validLoss(_ loss: [WorkspaceLoss]) -> Bool {
        var sequence: UInt64 = 0
        guard loss.count <= maxLosses else { return false }
        for (index, item) in loss.enumerated() {
            guard item.sequence > sequence, !item.reason.isEmpty, item.reason.utf8.count <= maxReason,
                  !item.aggregated || (index == maxLosses - 1 && index == loss.count - 1 && item.reason == aggregateReason) else { return false }
            sequence = item.sequence
        }
        return true
    }
    public static func validRenewal(_ r: WorkspaceRenewalReadiness) -> Bool {
        switch r.state {
        case "pending", "not-required": return r.installedSequence == 0
        case "installed": return r.installedSequence > 0
        default: return false
        }
    }
    public static func validOutcome(_ o: WorkspaceMountOutcome) -> Bool {
        ["durable", "lost", "unresolved"].contains(o.durability) &&
        ["observed", "unobserved"].contains(o.observation) &&
        ["released", "expired", "abandoned", "unresolved"].contains(o.release) &&
        (o.observation != "unobserved" || (o.durability == "unresolved" && o.release == "unresolved"))
    }
    public static func validColdAck(_ ack: WorkspaceSuspendAck) -> Bool {
        validSuspension(ack.suspension) && ack.mounts.map(\.mount) == ack.suspension.roster && ack.mounts.allSatisfy { validLoss($0.loss) && $0.hasOutcome && validOutcome($0.outcome) }
    }
    private static func validStatuses(_ mounts: [WorkspaceMountStatus]) -> Bool {
        validRoster(mounts.map(\.mount)) && mounts.allSatisfy {
            $0.hasOutcome && validOutcome($0.outcome) &&
            (!$0.hasRenewal || validRenewal($0.renewal)) &&
            ($0.state != "ready" || ($0.hasRenewal && $0.renewal.state != "pending")) &&
            ["closed", "ready", "suspended-cold", "recovering", "terminal", "authorization-required"].contains($0.state) &&
            ["retained", "process-exited", "kernel-absent", "complete"].contains($0.cleanup) &&
            $0.reason.utf8.count <= maxReason && validLoss($0.loss) &&
            ((["terminal", "authorization-required"].contains($0.state) && !$0.reason.isEmpty) ||
             (!["terminal", "authorization-required"].contains($0.state) && ($0.reason.isEmpty || $0.state == "closed"))) &&
            ($0.cleanup == "retained" || ["terminal", "authorization-required"].contains($0.state))
        }
    }
    public static func validRetired(_ outcomes: [WorkspaceRetiredOutcome]) -> Bool {
        guard outcomes.count <= 16,
              zip(outcomes, outcomes.dropFirst()).allSatisfy({ $0.retirementSequence < UInt64.max && $1.retirementSequence == $0.retirementSequence + 1 }) else { return false }
        var mounts = Set<String>(), jobs = Set<String>()
        return outcomes.allSatisfy { outcome in
            guard outcome.retirementSequence > 0, outcome.hasMountStatus || outcome.hasJob else { return false }
            if outcome.hasMountStatus {
                let m = outcome.mountStatus
                guard validStatuses([m]), m.cleanup == "complete", ["terminal", "authorization-required"].contains(m.state),
                      mounts.insert(mountKey(m.mount)).inserted else { return false }
            }
            if outcome.hasJob {
                let j = outcome.job
                guard validJob(j, generation: UInt64.max), ["complete", "failed"].contains(j.phase),
                      !outcome.hasMountStatus || outcome.mountStatus.mount == j.mount,
                      jobs.insert(mountKey(j.mount) + "/" + String(j.requestID)).inserted else { return false }
            }
            return true
        }
    }
    public static func validResumeAck(_ ack: WorkspaceResumeAck) -> Bool {
        validToken(ack.token) && ack.mounts.map(\.mount) == ack.token.suspension.roster && validStatuses(ack.mounts) && ack.mounts.allSatisfy { $0.state != "suspended-cold" }
    }
    public static func acknowledges(_ fixed: WorkspaceSuspension, request: WorkspaceSuspension) -> Bool {
        var identity = fixed; identity.roster = []
        return request.roster.isEmpty && identity == request
    }
    public static func retainsLoss(_ current: [WorkspaceLoss], prior: [WorkspaceLoss]) -> Bool {
        guard current.count >= prior.count else { return false }
        for (index, old) in prior.enumerated() {
            let next = current[index]
            if old == next { continue }
            guard index == maxLosses - 1, next.aggregated, next.reason == aggregateReason,
                  next.sequence >= old.sequence, next.acceptedEntries >= old.acceptedEntries,
                  next.acceptedBytes >= old.acceptedBytes else { return false }
        }
        return true
    }
    public static func validStatus(_ status: WorkspaceStatusReply) -> Bool {
        guard id(status.bootID), id(status.hostServiceID), id(status.guestServiceID),
              ["running", "suspending", "suspended-cold", "discard-only"].contains(status.state), validStatuses(status.mounts), validRetired(status.retired), validJobs(status),
              !["suspending", "suspended-cold"].contains(status.state) || status.generation > 0 else { return false }
        return status.mounts.allSatisfy { mount in
            if ["terminal", "authorization-required"].contains(mount.state) { return true }
            switch status.state {
            case "suspended-cold": return mount.state == "suspended-cold"
            case "suspending": return ["closed", "suspended-cold"].contains(mount.state)
            case "discard-only": return mount.state == "closed"
            case "running": return mount.state != "suspended-cold"
            default: return true
            }
        }
    }
    private static func validJobs(_ status: WorkspaceStatusReply) -> Bool {
        guard validRoster(status.jobs.map(\.mount)) else { return false }
        var volumes: [String: String] = [:]
        for mount in status.mounts.map(\.mount) + status.jobs.map(\.mount) {
            let volume = mount.authorityID.base64EncodedString() + "/" + mount.volumeID
            let key = mountKey(mount)
            if let old = volumes[volume], old != key { return false }
            volumes[volume] = key
        }
        guard volumes.count <= 64,
              status.retired.allSatisfy({ !$0.hasJob || $0.job.generation <= status.generation }) else { return false }
        return status.jobs.allSatisfy { validJob($0, generation: status.generation) }
    }
    private static func validJob(_ job: WorkspaceMountJob, generation: UInt64) -> Bool {
        guard validMount(job.mount), job.requestID > 0, job.generation <= generation,
              ["provision", "mount", "umount"].contains(job.operation) else { return false }
        switch job.phase {
        case "offered", "running", "complete": guard job.failure.isEmpty && job.reason.isEmpty else { return false }
        case "failed": guard ["unavailable", "refused", "authorization-required", "stopped", "deadline", "handler-failed"].contains(job.failure) && !job.reason.isEmpty && job.reason.utf8.count <= maxReason else { return false }
        default: return false
        }
        guard job.prior.count <= 21 else { return false }
        var previous = "", count: UInt64 = 0
        for summary in job.prior {
            let first = summary.first, category = summary.first.operation + "/" + summary.first.failure
            guard summary.hasFirst, first.prior.isEmpty, validJob(first, generation: job.generation),
                  first.mount == job.mount, ["complete", "failed"].contains(first.phase), summary.count > 0,
                  summary.lastRequestID >= first.requestID, summary.lastRequestID < job.requestID,
                  summary.count <= summary.lastRequestID - first.requestID + 1,
                  summary.count <= job.requestID - 1 - count, previous.isEmpty || category > previous else { return false }
            previous = category; count += summary.count
        }
        return true
    }
    // A successor can only start after its predecessor joins. Its cumulative
    // counters preserve every operation/failure category and the first exact
    // diagnostic in each category, without a per-attempt history.
    public static func retainsJob(_ current: WorkspaceMountJob, prior old: WorkspaceMountJob) -> Bool {
        guard current.mount == old.mount, current.requestID >= old.requestID, current.generation >= old.generation else { return false }
        if current.requestID == old.requestID {
            return current.generation == old.generation && current.operation == old.operation && current.prior == old.prior &&
                (!["complete", "failed"].contains(old.phase) || current == old)
        }
        guard old.prior.allSatisfy({ before in current.prior.contains { after in
            after.first == before.first && after.count >= before.count && after.lastRequestID >= before.lastRequestID
        } }) else { return false }
        if ["complete", "failed"].contains(old.phase) {
            let before = old.prior.first { $0.first.operation == old.operation && $0.first.failure == old.failure }
            var exact = old; exact.prior = []
            return current.prior.contains { $0.first.operation == old.operation && $0.first.failure == old.failure &&
                (before != nil || $0.first == exact) && $0.lastRequestID >= old.requestID && $0.count > (before?.count ?? 0) }
        }
        return current.prior.contains { $0.lastRequestID >= old.requestID }
    }
    public static func validToken(_ token: WorkspaceResumeToken) -> Bool { validSuspension(token.suspension) && id(token.wakeNonce) }
    public static func validate(_ e: WorkspaceEnvelope) throws {
        if case .suspend = e.body {
            guard e.drainBudgetNanos > 0, e.drainBudgetNanos <= maxDrainBudget else { throw WorkspaceControlError.grammar }
        } else if e.drainBudgetNanos != 0 { throw WorkspaceControlError.grammar }
        var ok = false
        switch e.body {
        case .hello(let h): ok = validRelease(h.release) && id(h.bootID) && id(h.hostServiceID) && h.guestServiceID.isEmpty
        case .helloAck(let h): ok = validRelease(h.release) && id(h.bootID) && id(h.hostServiceID) && id(h.guestServiceID)
        case .suspend(let s): ok = validSuspension(s) && s.roster.isEmpty
        case .suspendAck(let a): ok = validColdAck(a)
        case .resume(let t): ok = validToken(t)
        case .resumeAck(let a): ok = validResumeAck(a)
        case .status: ok = true
        case .statusReply(let s):
            ok = validStatus(s)
        case .retireAck(let ack): ok = ack.throughSequence > 0
        case .provision(let p):
            let material = [p.caCertificate, p.clientCertificate, p.capability, p.publicKey]
            ok = validMount(p.mount) && !p.authorityEndpoint.isEmpty && p.authorityEndpoint.utf8.count <= 4096 &&
                digest(p.routesRevision) && material.allSatisfy { !$0.isEmpty && $0.count <= 65536 }
        case .mount(let m): ok = validMount(m.mount)
        case .umount(let m): ok = validMount(m.mount)
        case .result(let r): ok = ["accepted", "unavailable", "authorization-required", "refused"].contains(r.code) && r.reason.utf8.count <= maxReason
        case nil: break
        }
        guard e.version == version, e.requestID > 0, ok else { throw WorkspaceControlError.grammar }
    }
    public static func pair(host: WorkspaceHello, guest: WorkspaceHello) throws {
        guard validRelease(host.release), host.release == guest.release, id(host.bootID), host.bootID == guest.bootID,
              id(host.hostServiceID), host.hostServiceID == guest.hostServiceID, host.guestServiceID.isEmpty,
              id(guest.guestServiceID) else { throw WorkspaceControlError.pairing }
    }
    public static func encode(_ envelope: WorkspaceEnvelope) throws -> Data {
        try validate(envelope)
        let payload = try envelope.serializedData()
        guard !payload.isEmpty, payload.count <= maxFrame else { throw WorkspaceControlError.grammar }
        try WorkspaceWireGrammar.check(payload)
        let count = UInt32(payload.count)
        var result = Data([UInt8(count >> 24), UInt8((count >> 16) & 255), UInt8((count >> 8) & 255), UInt8(count & 255)])
        result.append(payload)
        return result
    }
    public static func decode(_ frame: Data) throws -> WorkspaceEnvelope {
        guard frame.count >= 4 else { throw WorkspaceControlError.grammar }
        let count = frame.prefix(4).reduce(0) { ($0 << 8) | Int($1) }
        guard count > 0, count <= maxFrame, count == frame.count - 4 else { throw WorkspaceControlError.grammar }
        let payload = Data(frame.dropFirst(4))
        try WorkspaceWireGrammar.check(payload)
        let envelope = try WorkspaceEnvelope(serializedBytes: payload)
        guard try encode(envelope) == frame else { throw WorkspaceControlError.grammar }
        return envelope
    }
}
