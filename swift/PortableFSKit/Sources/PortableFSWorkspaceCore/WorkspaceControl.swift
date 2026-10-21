import Foundation
import SwiftProtobuf

public enum WorkspaceControlError: Error { case grammar, pairing, transition }

public enum WorkspaceControl {
    public static let version: UInt32 = 8
    public static let maxFrame = 1 << 20
    public static let maxLosses = 32
    public static let maxReason = 256
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
    public static func validColdAck(_ ack: WorkspaceSuspendAck) -> Bool {
        validSuspension(ack.suspension) && ack.mounts.map(\.mount) == ack.suspension.roster && ack.mounts.allSatisfy { validLoss($0.loss) }
    }
    private static func validStatuses(_ mounts: [WorkspaceMountStatus]) -> Bool {
        validRoster(mounts.map(\.mount)) && mounts.allSatisfy {
            ["closed", "ready", "suspended-cold", "recovering", "terminal", "authorization-required"].contains($0.state) &&
            ["retained", "process-exited", "kernel-absent", "complete"].contains($0.cleanup) &&
            $0.reason.utf8.count <= maxReason && validLoss($0.loss) &&
            ((["terminal", "authorization-required"].contains($0.state) && !$0.reason.isEmpty) ||
             (!["terminal", "authorization-required"].contains($0.state) && ($0.reason.isEmpty || $0.state == "closed"))) &&
            ($0.cleanup == "retained" || ["terminal", "authorization-required"].contains($0.state))
        }
    }
    public static func validRetired(_ mounts: [WorkspaceMountStatus]) -> Bool {
        mounts.count <= 16 && Set(mounts.map { mountKey($0.mount) }).count == mounts.count && mounts.allSatisfy {
            validStatuses([$0]) && $0.cleanup == "complete" && ["terminal", "authorization-required"].contains($0.state)
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
              ["running", "suspending", "suspended-cold", "discard-only"].contains(status.state), validStatuses(status.mounts), validRetired(status.retired),
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
    public static func validToken(_ token: WorkspaceResumeToken) -> Bool { validSuspension(token.suspension) && id(token.wakeNonce) }
    public static func validate(_ e: WorkspaceEnvelope) throws {
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
        case .retireAck(let ack): ok = !ack.outcomes.isEmpty && validRetired(ack.outcomes)
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
