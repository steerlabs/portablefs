import Foundation
import Darwin
import Testing
import PortableFSWorkspaceCore
@testable import PortableFSWorkspaceVM

@MainActor private func readEnvelope(_ stream: WorkspaceStream, deadline: UInt64) async throws -> WorkspaceEnvelope {
    let h: Data = try await withCheckedThrowingContinuation { c in stream.read(count: 4, deadline: deadline) { c.resume(with: $0) } }
    let n = h.reduce(0) { ($0 << 8) | Int($1) }
    let b: Data = try await withCheckedThrowingContinuation { c in stream.read(count: n, deadline: deadline) { c.resume(with: $0) } }
    return try WorkspaceControl.decode(h+b)
}
@MainActor private func replyEnvelope(_ body: WorkspaceEnvelope.OneOf_Body, to request: WorkspaceEnvelope, on stream: WorkspaceStream, deadline: UInt64) async throws {
    var e = WorkspaceEnvelope(); e.version = 8; e.requestID = request.requestID; e.body = body
    let frame = try WorkspaceControl.encode(e)
    try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in stream.write(frame, deadline: deadline) { c.resume(with: $0) } }
}

@Test @MainActor func astraR4AutoRetryMustPreserveDesiredFIFO() async throws {
    try await desiredFIFO(mountFirst: false)
}
@Test @MainActor func workspaceAutoRetryPreservesMountThenUmountFIFO() async throws {
    try await desiredFIFO(mountFirst: true)
}
@MainActor private func desiredFIFO(mountFirst: Bool) async throws {
    var fds: [Int32] = [-1, -1]
    try #require(socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0)
    defer { close(fds[0]); close(fds[1]) }
    let ch = try WorkspaceVsockChannel(fd: fds[0]); defer { ch.close() }
    let peer = try WorkspaceStream(fd: fds[1], label: "workspace.fifo.peer", onLost: { _ in }); defer { peer.close() }
    let deadline = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) + 2_000_000_000
    var status = try WorkspaceControl.decode(workspaceGolden("job_complete")).statusReply
    status.retired = []; status.jobs[0].requestID = 1
    let id = status.jobs[0].mount
    let first = mountFirst ? "mount" : "umount", last = mountFirst ? "umount" : "mount"
    var observed: [UInt64] = [], completed: [String] = [], dispatched: [String] = [], admitted: [String] = []
    var mounted = !mountFirst
    ch.statusObserver = { observed.append($0.jobs[0].requestID) }
    func submit(_ name: String) {
        let completion: (Result<WorkspaceResult, Error>) -> Void = { result in
            #expect((try? result.get().code) == "accepted")
            completed.append(name)
        }
        if name == "mount" { ch.mount(id, deadline: deadline, completion: completion) }
        else { ch.umount(id, deadline: deadline, completion: completion) }
    }
    submit(first)
    ch.status(deadline: deadline) { #expect((try? $0.get()) != nil) }
    submit(last)
    for index in 0..<5 {
        let request = try await readEnvelope(peer, deadline: deadline)
        #expect(request.requestID == UInt64(index + 1))
        var result = WorkspaceResult(); result.code = "accepted"
        switch request.body {
        case .mount, .umount:
            let name: String
            if case .mount = request.body { name = "mount" } else { name = "umount" }
            dispatched.append(name)
            if index == 0 {
                result.code = "predecessor-unobserved"; result.reason = "observe predecessor result with Status before retry"
            } else {
                #expect(observed == (index == 2 ? [1] : [1, 3]), "consume terminal evidence before dispatch")
                admitted.append(name); mounted = name == "mount"
                status.jobs[0].requestID = request.requestID; status.jobs[0].operation = name
            }
            try await replyEnvelope(.result(result), to: request, on: peer, deadline: deadline)
        case .status:
            dispatched.append("status")
            try await replyEnvelope(.statusReply(status), to: request, on: peer, deadline: deadline)
        default: Issue.record("unexpected exchange"); return
        }
    }
    for _ in 0..<100 where completed.count < 2 { try await Task.sleep(for: .milliseconds(1)) }
    #expect(dispatched == [first, "status", first, "status", last])
    #expect(admitted == [first, last] && completed == [first, last])
    #expect(mounted == !mountFirst, "last desired operation determines membership")
    #expect(ch.isIdle)
}

@Test @MainActor func astraR4RepeatedRefusalKeepsOriginalDeadline() async throws {
    var fds:[Int32]=[-1,-1]
    try #require(socketpair(AF_UNIX,SOCK_STREAM,0,&fds)==0)
    defer {close(fds[0]);close(fds[1])}
    let ch=try WorkspaceVsockChannel(fd:fds[0]); defer {ch.close()}
    let peer=try WorkspaceStream(fd:fds[1],label:"astra.r4.deadline.peer",onLost:{_ in});defer{peer.close()}
    var status=try WorkspaceControl.decode(workspaceGolden("job_complete")).statusReply
    status.retired=[]
    ch.statusObserver={_ in}
    let start=clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW), deadline=start+1_000_000_000
    var completedAt:UInt64=0, completions=0, refused=0
    ch.mount(status.jobs[0].mount,deadline:deadline){r in
        completions+=1;completedAt=clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)
        if case .success=r {Issue.record("noncompliant repeated refusal somehow accepted")}
    }
    do {
        while completions==0 {
            let req=try await readEnvelope(peer,deadline:deadline+100_000_000)
            if case .status=req.body {try await replyEnvelope(.statusReply(status),to:req,on:peer,deadline:deadline+100_000_000)}
            else {
                refused+=1
                var r=WorkspaceResult();r.code="predecessor-unobserved";r.reason="observe predecessor result with Status before retry"
                try await replyEnvelope(.result(r),to:req,on:peer,deadline:deadline+100_000_000)
            }
        }
    } catch {}
    for _ in 0..<100 where completions==0 {try await Task.sleep(for:.milliseconds(1))}
    #expect(refused>1 && completions==1 && completedAt>=deadline && completedAt<deadline+500_000_000)
}
