import Foundation
import Testing
@testable import PortableFSWorkspaceCore

func workspaceGolden(_ name: String) throws -> Data {
    let path = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("Goldens").appendingPathComponent(name + ".hex")
    let text = try String(contentsOf: path, encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
    var bytes = Data()
    var index = text.startIndex
    while index < text.endIndex {
        let end = text.index(index, offsetBy: 2)
        bytes.append(try #require(UInt8(text[index..<end], radix: 16)))
        index = end
    }
    return bytes
}
@Test func workspaceGoldensCoverEveryMessageAndRejectMalformedFrames() throws {
    let names = ["hello", "hello_ack", "suspend", "suspend_ack", "resume", "resume_ack", "status", "status_reply", "provision", "mount", "umount", "result", "retire_ack", "renewal_pending", "renewal_installed", "renewal_not_required", "job_offered", "job_running", "job_complete", "job_failed", "retired_job_complete", "retired_job_failed", "retired_mount_with_job", "job_with_joined_summary"]
    for name in names {
        let raw = try workspaceGolden(name)
        let envelope = try WorkspaceControl.decode(raw)
        #expect(envelope.version == 8)
        #expect(try WorkspaceControl.encode(envelope) == raw)
    }
    let invalid = ["unequal_version", "unknown_body", "duplicate_version", "multiple_body", "nonminimal_varint", "explicit_default", "unknown_nested", "oversized_length", "truncated", "trailing", "out_of_order", "wrong_wire_type", "zero_length", "zero_request_id", "invalid_utf8", "excessive_nesting", "excessive_repeated", "missing_outcome", "missing_renewal", "zero_installed_sequence", "pending_with_sequence", "not_required_with_sequence", "unobserved_durable", "invalid_release_outcome", "ready_with_pending_renewal", "cold_missing_outcome", "suspend_missing_budget", "suspend_excess_budget", "budget_outside_suspend", "job_zero_request", "job_future_generation", "job_unknown_operation", "job_unknown_phase", "job_missing_failure", "job_unknown_failure", "job_missing_reason", "job_running_failure", "job_incarnation_conflict", "job_duplicate", "job_excess_capacity", "retired_empty", "retired_running_job", "retired_future_job", "retired_sequence_gap", "retired_mismatched_job", "retired_duplicate_job", "active_excess_capacity", "summary_zero_count", "summary_future_request", "summary_wrong_mount", "summary_unjoined", "summary_duplicate", "summary_recursive"]
    for name in invalid {
        let raw = try workspaceGolden(name + ".invalid")
        #expect(throws: (any Error).self) { try WorkspaceControl.decode(raw) }
    }
}
@Test func workspacePairingRejectsEveryReleaseAndBootMismatch() throws {
    let host = try WorkspaceControl.decode(workspaceGolden("hello")).hello
    let guest = try WorkspaceControl.decode(workspaceGolden("hello_ack")).helloAck
    try WorkspaceControl.pair(host: host, guest: guest)
    for field in ["version", "commit", "image", "authority", "boot", "host", "guest"] {
        var bad = guest
        switch field {
        case "version": bad.release.appVersion = "other"
        case "commit": bad.release.commit = String(repeating: "b", count: 40)
        case "image": bad.release.imageDigest = Data(repeating: 12, count: 32)
        case "authority": bad.release.authorityMajor = 7
        case "boot": bad.bootID = Data(repeating: 12, count: 16)
        case "host": bad.hostServiceID = Data(repeating: 12, count: 16)
        default: bad.guestServiceID = Data()
        }
        #expect(throws: (any Error).self) { try WorkspaceControl.pair(host: host, guest: bad) }
    }
}
@Test func workspaceSemanticBoundsUseStructuralProvisioningGrammar() throws {
    var envelope = try WorkspaceControl.decode(workspaceGolden("provision"))
    var provision = envelope.provision
    provision.publicKey = Data("-----BEGIN PRIVATE KEY-----".utf8)
    envelope.body = .provision(provision)
    _ = try WorkspaceControl.encode(envelope)
    var s = try WorkspaceControl.decode(workspaceGolden("suspend_ack")).suspendAck.suspension
    s.roster.append(s.roster[0])
    #expect(!WorkspaceControl.validSuspension(s))
    s.roster = Array(repeating: s.roster[0], count: 65)
    #expect(!WorkspaceControl.validSuspension(s))
}

@Test func workspaceMaximumStatusFitsFrameAndConstrainsStateCombinations() throws {
    let template = try WorkspaceControl.decode(workspaceGolden("status_reply")).statusReply
    var status = template
    status.mounts = (0..<64).map { index in
        var m = template.mounts[0]
        m.mount.volumeID = String(format: "%03d", index) + String(repeating: "v", count: 125)
        m.reason = String(repeating: "r", count: WorkspaceControl.maxReason)
        m.cleanup = "complete"
        m.loss = (1...WorkspaceControl.maxLosses).map { sequence in
            var loss = WorkspaceLoss(); loss.sequence = UInt64(sequence)
            loss.acceptedEntries = UInt64.max; loss.acceptedBytes = UInt64.max
            loss.reason = String(repeating: "r", count: WorkspaceControl.maxReason); return loss
        }
        return m
    }
    status.retired = Array(status.mounts.prefix(16)).enumerated().map { index, old in
        var retired = old; retired.mount.incarnation = Data(repeating: 99, count: 16); return retiredTestOutcome(retired, sequence: UInt64(index + 1))
    }
    status.jobs = status.mounts.map { mount in
        var job = WorkspaceMountJob(); job.mount = mount.mount; job.requestID = UInt64.max; job.generation = status.generation
        job.operation = "provision"; job.phase = "failed"; job.failure = "authorization-required"; job.reason = String(repeating: "r", count: WorkspaceControl.maxReason)
        for operation in ["mount", "provision", "umount"] {
            for failure in ["", "authorization-required", "deadline", "handler-failed", "refused", "stopped", "unavailable"] {
                var first = job; first.prior = []; first.requestID = UInt64(job.prior.count + 1)
                first.operation = operation; first.failure = failure
                if failure.isEmpty { first.phase = "complete"; first.reason = "" }
                var summary = WorkspaceJoinedJobSummary(); summary.first = first; summary.count = (UInt64.max - 1) / 21; summary.lastRequestID = UInt64.max - UInt64(21 - job.prior.count)
                job.prior.append(summary)
            }
        }
        return job
    }
    for index in status.retired.indices {
        var job = status.jobs[index]; job.mount = status.retired[index].mountStatus.mount
        for summary in job.prior.indices { job.prior[summary].first.mount = job.mount }
        status.retired[index].job = job
    }
    var envelope = WorkspaceEnvelope(); envelope.version = 8; envelope.requestID = UInt64.max; envelope.body = .statusReply(status)
    let frame = try WorkspaceControl.encode(envelope)
    #expect(frame.count <= WorkspaceControl.maxFrame + 4)
    #expect(try WorkspaceControl.decode(frame) == envelope)
    var bad = template; bad.state = "suspended-cold"; bad.mounts[0].state = "ready"
    #expect(!WorkspaceControl.validStatus(bad))
    bad = template; bad.mounts[0].state = "ready"; bad.mounts[0].cleanup = "complete"
    #expect(!WorkspaceControl.validStatus(bad))
    bad = template; bad.mounts[0].reason = ""
    #expect(!WorkspaceControl.validStatus(bad))
}

func unknownTestOutcome() -> WorkspaceMountOutcome {
    var o = WorkspaceMountOutcome(); o.durability = "unresolved"; o.observation = "unobserved"; o.release = "unresolved"; return o
}
func installedTestRenewal() -> WorkspaceRenewalReadiness {
    var r = WorkspaceRenewalReadiness(); r.state = "installed"; r.installedSequence = 1; return r
}
@Test func workspaceTypedReadinessAndOutcomeCombinations() throws {
    var e = try WorkspaceControl.decode(workspaceGolden("status_reply"))
    var s = e.statusReply; s.retired = []; s.mounts[0].state = "ready"; s.mounts[0].reason = ""
    #expect(!WorkspaceControl.validStatus(s))
    for state in ["pending", "installed", "not-required"] {
        for sequence: UInt64 in [0, 1] {
            var r = WorkspaceRenewalReadiness(); r.state = state; r.installedSequence = sequence
            s.mounts[0].renewal = r
            #expect(WorkspaceControl.validStatus(s) == ((state == "installed" && sequence == 1) || (state == "not-required" && sequence == 0)))
        }
    }
    s.mounts[0].outcome.durability = "durable"
    #expect(!WorkspaceControl.validStatus(s))
    s.mounts[0].outcome.observation = "observed"
    s.mounts[0].renewal = installedTestRenewal()
    #expect(WorkspaceControl.validStatus(s))
    e.body = .statusReply(s); _ = try WorkspaceControl.encode(e)
}

func retiredTestOutcome(_ mount: WorkspaceMountStatus, sequence: UInt64) -> WorkspaceRetiredOutcome {
    var outcome = WorkspaceRetiredOutcome(); outcome.retirementSequence = sequence; outcome.mountStatus = mount; return outcome
}

@Test func workspaceJoinedSummaryRetainsObservedResultsAndCounters() throws {
    let current = try WorkspaceControl.decode(workspaceGolden("job_with_joined_summary")).statusReply.jobs[0]
    let old = current.prior[0].first
    #expect(WorkspaceControl.retainsJob(current, prior: old))
    var altered = current; altered.prior[0].first.reason += "changed"
    #expect(!WorkspaceControl.retainsJob(altered, prior: old))
    var next = current; next.requestID += 1
    next.prior[0].count += 1; next.prior[0].lastRequestID = current.requestID
    #expect(WorkspaceControl.retainsJob(next, prior: current))
    next.prior[0].count = current.prior[0].count
    #expect(!WorkspaceControl.retainsJob(next, prior: current))
    next.prior = []
    #expect(!WorkspaceControl.retainsJob(next, prior: current))
}
