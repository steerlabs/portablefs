//go:build linux

package fusev3

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"google.golang.org/protobuf/proto"
)

func openWriteTransactionTestHandle(t *testing.T, fixture *strictFixture) (uint64, uint64) {
	t.Helper()
	fixture.rpc.byName = map[string]*authoritypb.Item{"file": testItem(7, authoritypb.Attr_REGULAR, 7)}
	entry := fixture.lookup(t, fuse.FUSE_ROOT_ID, "file")
	out := &fuse.OpenOut{}
	status := fixture.rawCall(func(unique uint64) fuse.Status {
		return fixture.raw.Open(nil, &fuse.OpenIn{
			InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId},
			Flags:    syscall.O_WRONLY | syscall.O_APPEND,
		}, out)
	})
	if !status.Ok() {
		t.Fatalf("open write-transaction test handle: %v", status)
	}
	if out.OpenFlags != coherentOpenFlags {
		t.Fatalf("authority open flags = %#x, want %#x", out.OpenFlags, coherentOpenFlags)
	}
	return entry.NodeId, out.Fh
}

func writeTransactionInput(nodeID, handle, kernelTxid, requested uint64, phase uint32) *fuse.PFSWriteIn {
	return &fuse.PFSWriteIn{
		InHeader:      fuse.InHeader{NodeId: nodeID},
		Fh:            handle,
		Txid:          kernelTxid,
		RequestedSize: requested,
		RlimitFsize:   kernelMaxRWCount(),
		FileMaxSize:   kernelMaxRWCount(),
		LockOwner:     91,
		WriteFlags:    fuse.WRITE_LOCKOWNER,
		Flags:         uint32(syscall.O_APPEND),
		Phase:         phase,
	}
}

func callWriteTransaction(fixture *strictFixture, input *fuse.PFSWriteIn, data []byte, out *fuse.PFSWriteOut) fuse.Status {
	return fixture.rawCall(func(unique uint64) fuse.Status {
		input.Unique = unique
		return fixture.raw.PFSWrite(nil, input, data, out)
	})
}

func oneShotWriteInput(nodeID, handle uint64, size uint32) *fuse.PFSWriteIn {
	return &fuse.PFSWriteIn{
		InHeader:      fuse.InHeader{NodeId: nodeID},
		Fh:            handle,
		RequestedSize: uint64(size),
		RlimitFsize:   kernelMaxRWCount(),
		FileMaxSize:   kernelMaxRWCount(),
		LockOwner:     91,
		WriteFlags:    fuse.WRITE_LOCKOWNER,
		Flags:         uint32(syscall.O_APPEND),
		Size:          size,
		Phase:         fuse.PFS_WRITE_ONE_SHOT,
	}
}

func TestPFSWriteOneShotUsesOneRetainedMutationWithoutTransactionID(t *testing.T) {
	fixture := newStrictFixture(t)
	nodeID, handle := openWriteTransactionTestHandle(t, fixture)
	consumption := &recordingResponseConsumption{}
	fixture.rpc.mu.Lock()
	fixture.rpc.retainedConsumption = consumption
	beforeMutations := fixture.rpc.mutationCalls
	beforeAssignments := fixture.rpc.assignments
	fixture.rpc.mu.Unlock()
	fixture.raw.writeMu.Lock()
	nextBefore := fixture.raw.nextWriteTx
	fixture.raw.writeMu.Unlock()

	input := oneShotWriteInput(nodeID, handle, 4)
	input.Unique = fixture.unique.Add(2)
	out := &fuse.PFSWriteOut{}
	// BEGIN serialization must be irrelevant to ordinary one-shot mutations.
	fixture.raw.writeBeginMu.Lock()
	result := make(chan fuse.Status, 1)
	go func() { result <- fixture.raw.PFSWrite(nil, input, []byte("data"), out) }()
	select {
	case status := <-result:
		if !status.Ok() {
			fixture.raw.writeBeginMu.Unlock()
			t.Fatalf("one-shot PFS_WRITE = %v", status)
		}
	case <-time.After(2 * time.Second):
		fixture.raw.writeBeginMu.Unlock()
		t.Fatal("one-shot write blocked on BEGIN transaction serialization")
	}
	fixture.raw.writeBeginMu.Unlock()

	if out.Txid != 0 || out.Flags != fuse.PFS_WRITE_OUT_COMMITTED || out.CommittedSize != 4 ||
		out.AssignedOffset != 100 || out.PostSize != 104 || out.Sequence != 17 || out.Error != 0 {
		t.Fatalf("one-shot result = %+v", out)
	}
	fixture.rpc.snapshot(func(rpc *fakeRPC) {
		if rpc.mutationCalls != beforeMutations+1 || rpc.assignments != beforeAssignments+1 || len(rpc.oneShotWrites) != 1 || len(rpc.writeTransactions) != 0 {
			t.Fatalf("one-shot authority calls = mutations %d (before %d), assignments %d (before %d), one-shot %d, transactions %d",
				rpc.mutationCalls, beforeMutations, rpc.assignments, beforeAssignments, len(rpc.oneShotWrites), len(rpc.writeTransactions))
		}
		request := rpc.oneShotRequests[0]
		if request.GetFrontendOperationId() != input.Unique ||
			!bytes.Equal(request.GetOneShotWrite().GetData(), []byte("data")) || request.GetOneShotWrite().GetSize() != 4 ||
			len(request.GetSourcePublicationGate().GetTargets()) != 1 {
			t.Fatalf("one-shot retained mutation request = %+v", request)
		}
	})
	fixture.raw.writeMu.Lock()
	if fixture.raw.nextWriteTx != nextBefore || len(fixture.raw.writeTx) != 0 {
		fixture.raw.writeMu.Unlock()
		t.Fatal("one-shot write consumed or registered a transaction ID")
	}
	fixture.raw.writeMu.Unlock()
	if consumption.calls.Load() != 0 || !fixture.raw.ReplyWriteOrdered(input.Unique) ||
		!fixture.raw.ReplyPublishMarked(input.Unique, nodeID, fuse.PFS_WRITE_OPCODE) {
		t.Fatal("one-shot response did not retain its mutation through post-VFS publication")
	}
	fixture.raw.ReplyWritten(input.Unique, fuse.OK)
	if consumption.calls.Load() != 0 {
		t.Fatal("one-shot response was consumed before PFS_PUBLISH")
	}
	publishUnique := fixture.unique.Add(2)
	publishOut := &fuse.PFSPublishOut{}
	status := fixture.raw.PFSPublish(nil, &fuse.PFSPublishIn{
		InHeader: fuse.InHeader{Unique: publishUnique}, RequestUnique: input.Unique,
		PublicationID: 1, Nodeid: nodeID, Opcode: fuse.PFS_WRITE_OPCODE,
	}, publishOut)
	if !status.Ok() {
		t.Fatalf("one-shot PFS_PUBLISH = %v", status)
	}
	fixture.raw.ReplyWritten(publishUnique, fuse.OK)
	if consumption.calls.Load() != 1 {
		t.Fatalf("one-shot retained response consumption = %d, want 1", consumption.calls.Load())
	}
}

func TestPFSWriteOneShotBoundaryAndDefiniteRejection(t *testing.T) {
	fixture := newStrictFixture(t)
	nodeID, handle := openWriteTransactionTestHandle(t, fixture)
	atLimit := oneShotWriteInput(nodeID, handle, fixture.raw.maxWrite)
	payload := make([]byte, fixture.raw.maxWrite)
	if !validOneShotWriteMetadata(func() *fuse.PFSWriteIn { atLimit.Unique = 2; return atLimit }(), payload, fixture.raw.maxWrite) {
		t.Fatal("one-shot metadata rejected payload exactly at max_write")
	}
	overLimit := oneShotWriteInput(nodeID, handle, fixture.raw.maxWrite+1)
	overLimit.Unique = 2
	if validOneShotWriteMetadata(overLimit, make([]byte, overLimit.Size), fixture.raw.maxWrite) {
		t.Fatal("one-shot metadata accepted payload above max_write")
	}

	consumption := &recordingResponseConsumption{}
	fixture.rpc.mu.Lock()
	fixture.rpc.retainedConsumption = consumption
	fixture.rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
		if request.GetOneShotWrite() == nil {
			return nil, errors.New("unexpected non-one-shot request")
		}
		return &authoritypb.Response{Body: &authoritypb.Response_OneShotWrite{OneShotWrite: &authoritypb.OneShotWriteReply{
			Flags: fuse.PFS_WRITE_OUT_REJECTED, Error: -int32(syscall.ENOSPC),
		}}}, nil
	}
	fixture.rpc.mu.Unlock()
	input := oneShotWriteInput(nodeID, handle, 1)
	input.Unique = fixture.unique.Add(2)
	out := &fuse.PFSWriteOut{}
	if status := fixture.raw.PFSWrite(nil, input, []byte("x"), out); !status.Ok() ||
		out.Flags != fuse.PFS_WRITE_OUT_REJECTED || out.Error != -int32(syscall.ENOSPC) {
		t.Fatalf("definite one-shot rejection = (%v, %+v)", status, out)
	}
	if fixture.raw.ReplyPublishMarked(input.Unique, nodeID, fuse.PFS_WRITE_OPCODE) {
		t.Fatal("definite one-shot rejection requested post-VFS publication")
	}
	fixture.raw.ReplyWritten(input.Unique, fuse.OK)
	if consumption.calls.Load() != 1 {
		t.Fatalf("rejected one-shot retained consumption = %d, want 1", consumption.calls.Load())
	}
}

func TestPFSWriteInertPhasesRetainAuthorityResponseUntilPhysicalReply(t *testing.T) {
	fixture := newStrictFixture(t)
	nodeID, handle := openWriteTransactionTestHandle(t, fixture)
	const kernelTxid = uint64(0x7611)

	phase := func(input *fuse.PFSWriteIn, data []byte, wantFlag uint32, writeStatus fuse.Status) {
		t.Helper()
		consumption := &recordingResponseConsumption{}
		fixture.rpc.mu.Lock()
		fixture.rpc.retainedConsumption = consumption
		fixture.rpc.mu.Unlock()
		unique := fixture.unique.Add(2)
		input.Unique = unique
		out := &fuse.PFSWriteOut{}
		if status := fixture.raw.PFSWrite(nil, input, data, out); !status.Ok() || out.Flags != wantFlag {
			t.Fatalf("phase %d = (%v,%+v)", input.Phase, status, out)
		}
		if got := consumption.calls.Load(); got != 0 {
			t.Fatalf("phase %d consumed response at callback return: %d", input.Phase, got)
		}
		if !fixture.raw.ReplyWriteOrdered(unique) {
			t.Fatalf("phase %d did not join the physical reply boundary", input.Phase)
		}
		if fixture.raw.ReplyPublishMarked(unique, nodeID, fuse.PFS_WRITE_OPCODE) {
			t.Fatalf("inert phase %d requested post-VFS publication", input.Phase)
		}
		fixture.raw.ReplyWritten(unique, writeStatus)
		if got := consumption.calls.Load(); got != 1 {
			t.Fatalf("phase %d response consumption after ReplyWritten = %d, want 1", input.Phase, got)
		}
	}

	begin := writeTransactionInput(nodeID, handle, kernelTxid, 3, fuse.PFS_WRITE_BEGIN)
	phase(begin, nil, fuse.PFS_WRITE_OUT_BEGUN, fuse.OK)
	data := writeTransactionInput(nodeID, handle, kernelTxid, 3, fuse.PFS_WRITE_DATA)
	data.Size = 3
	phase(data, []byte("abc"), fuse.PFS_WRITE_OUT_STAGED, fuse.OK)
	abort := writeTransactionInput(nodeID, handle, kernelTxid, 3, fuse.PFS_WRITE_ABORT)
	phase(abort, nil, fuse.PFS_WRITE_OUT_ABORTED, fuse.EIO)
	if !fixture.mount.isRevoked() {
		t.Fatal("failed physical ABORT reply did not revoke the strict mount")
	}
}

func TestPFSWriteStagesAppendFragmentsThenPublishesOneServerPositionedCommit(t *testing.T) {
	fixture := newStrictFixture(t)
	nodeID, handle := openWriteTransactionTestHandle(t, fixture)
	const kernelTxid = 0x7edcba9876543210

	begin := writeTransactionInput(nodeID, handle, kernelTxid, 6, fuse.PFS_WRITE_BEGIN)
	var out fuse.PFSWriteOut
	if status := callWriteTransaction(fixture, begin, nil, &out); !status.Ok() || out.Txid != kernelTxid || out.Flags != fuse.PFS_WRITE_OUT_BEGUN {
		t.Fatalf("BEGIN = (%v, %+v)", status, out)
	}

	fragments := []struct {
		offset  uint64
		payload []byte
	}{{0, []byte("abc")}, {3, []byte("def")}}
	for _, fragment := range fragments {
		data := writeTransactionInput(nodeID, handle, kernelTxid, 6, fuse.PFS_WRITE_DATA)
		data.FragmentOffset, data.Size = fragment.offset, uint32(len(fragment.payload))
		out = fuse.PFSWriteOut{}
		if status := callWriteTransaction(fixture, data, fragment.payload, &out); !status.Ok() || out.Flags != fuse.PFS_WRITE_OUT_STAGED {
			t.Fatalf("DATA@%d = (%v, %+v)", fragment.offset, status, out)
		}
	}

	commit := writeTransactionInput(nodeID, handle, kernelTxid, 6, fuse.PFS_WRITE_COMMIT)
	commit.FragmentOffset = 6
	out = fuse.PFSWriteOut{}
	commitUnique := fixture.unique.Add(2)
	commit.Unique = commitUnique
	if status := fixture.raw.PFSWrite(nil, commit, nil, &out); !status.Ok() {
		t.Fatalf("COMMIT = %v", status)
	}
	if out.Txid != kernelTxid || out.Flags != fuse.PFS_WRITE_OUT_COMMITTED || out.CommittedSize != 6 ||
		out.AssignedOffset != 100 || out.PostSize != 106 || out.Sequence != 17 || out.Error != 0 {
		t.Fatalf("COMMIT result = %+v", out)
	}
	if !fixture.raw.ReplyPublishMarked(commitUnique, nodeID, fuse.PFS_WRITE_OPCODE) {
		t.Fatal("COMMIT response was not marked for post-VFS publication")
	}

	// The kernel may wake, finish postprocessing and issue PFS_PUBLISH after
	// go-fuse unlocks writeMu but before ReplyWritten observes write(2) return.
	// This valid early receipt must wait, never fence.
	publishUnique := fixture.unique.Add(2)
	publishIn := &fuse.PFSPublishIn{
		InHeader:      fuse.InHeader{Unique: publishUnique},
		RequestUnique: commitUnique,
		PublicationID: 1,
		Nodeid:        nodeID,
		Opcode:        fuse.PFS_WRITE_OPCODE,
	}
	publishOut := &fuse.PFSPublishOut{}
	publishDone := make(chan fuse.Status, 1)
	go func() { publishDone <- fixture.raw.PFSPublish(nil, publishIn, publishOut) }()
	select {
	case status := <-publishDone:
		t.Fatalf("early PFS_PUBLISH returned before original physical write: %v", status)
	case <-time.After(25 * time.Millisecond):
	}
	fixture.raw.ReplyWritten(commitUnique, fuse.OK)
	if status := <-publishDone; !status.Ok() {
		t.Fatalf("PFS_PUBLISH after physical COMMIT write = %v", status)
	}
	if publishOut.RequestUnique != commitUnique || publishOut.PublicationID != 1 || publishOut.Nodeid != nodeID ||
		publishOut.Opcode != fuse.PFS_WRITE_OPCODE || publishOut.Flags != fuse.PFS_PUBLISH_ACK {
		t.Fatalf("PFS_PUBLISH ACK = %+v", publishOut)
	}
	fixture.raw.ReplyWritten(publishUnique, fuse.OK)
	fixture.raw.writeMu.Lock()
	_, retained := fixture.raw.writeTx[kernelTxid]
	fixture.raw.writeMu.Unlock()
	if retained {
		t.Fatal("transaction survived the physical generic publication acknowledgment")
	}

	fixture.rpc.snapshot(func(rpc *fakeRPC) {
		wantPhases := []authoritypb.WriteTransactionPhase{
			authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_BEGIN,
			authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA,
			authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA,
			authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_COMMIT,
		}
		if len(rpc.writeTransactions) != len(wantPhases) {
			t.Fatalf("generic PFS_PUBLISH crossed the authority transport: %+v", rpc.writeTransactions)
		}
		for index, request := range rpc.writeTransactions {
			if request.GetTransactionId() != 1 || request.GetPhase() != wantPhases[index] {
				t.Fatalf("authority write transaction[%d] = %+v", index, request)
			}
		}
	})
}

func TestPFSWriteConsumesItemRetryInternallyAndReusesOneStagedTransaction(t *testing.T) {
	fixture := newStrictFixture(t)
	nodeID, handle := openWriteTransactionTestHandle(t, fixture)
	const kernelTxid = uint64(0x7612)

	begin := writeTransactionInput(nodeID, handle, kernelTxid, 3, fuse.PFS_WRITE_BEGIN)
	if status := callWriteTransaction(fixture, begin, nil, &fuse.PFSWriteOut{}); !status.Ok() {
		t.Fatalf("BEGIN = %v", status)
	}
	data := writeTransactionInput(nodeID, handle, kernelTxid, 3, fuse.PFS_WRITE_DATA)
	data.Size = 3
	if status := callWriteTransaction(fixture, data, []byte("abc"), &fuse.PFSWriteOut{}); !status.Ok() {
		t.Fatalf("DATA = %v", status)
	}

	internal := &recordingResponseConsumption{}
	committed := &recordingResponseConsumption{}
	firstRetry := make(chan struct{})
	secondCommit := make(chan struct{})
	fixture.rpc.mu.Lock()
	fixture.rpc.retainedConsumptions = []authorityrpc.ResponseConsumption{internal, committed}
	var commitCalls int
	var frontendOperationIDs []uint64
	var retryAfterSequences []uint64
	fixture.rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
		write := request.GetWriteTransaction()
		if write == nil || write.GetPhase() != authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_COMMIT {
			return nil, errors.New("unexpected request while testing item-only COMMIT retry")
		}
		fixture.rpc.writeTransactions = append(fixture.rpc.writeTransactions, proto.Clone(write).(*authoritypb.WriteTransactionRequest))
		frontendOperationIDs = append(frontendOperationIDs, request.GetFrontendOperationId())
		retryAfterSequences = append(retryAfterSequences, request.GetVisibilityRetryAfterSequence())
		commitCalls++
		if commitCalls == 1 {
			close(firstRetry)
			return &authoritypb.Response{
				Errno: int32(syscall.EINTR), Failure: authoritypb.FailureClass_FAILURE_CLASS_VISIBILITY_RETRY,
				VisibilityRetrySequence: 17,
			}, nil
		}
		close(secondCommit)
		reply := &authoritypb.WriteTransactionReply{
			TransactionId: write.GetTransactionId(), Flags: fuse.PFS_WRITE_OUT_COMMITTED,
			CommittedSize: 3, AssignedOffset: 100, PostSize: 103, VisibilitySequence: 17,
		}
		return &authoritypb.Response{
			Body:     &authoritypb.Response_WriteTransaction{WriteTransaction: reply},
			PostAttr: &authoritypb.Attr{Inode: fixture.rpc.item.GetAttr().GetInode(), Kind: authoritypb.Attr_REGULAR, Mode: 0o600, Size: 103},
		}, nil
	}
	fixture.rpc.mu.Unlock()

	commit := writeTransactionInput(nodeID, handle, kernelTxid, 3, fuse.PFS_WRITE_COMMIT)
	commit.FragmentOffset = 3
	unique := fixture.unique.Add(2)
	commit.Unique = unique
	out := &fuse.PFSWriteOut{}
	result := make(chan fuse.Status, 1)
	go func() { result <- fixture.raw.PFSWrite(nil, commit, nil, out) }()
	select {
	case <-firstRetry:
	case <-time.After(2 * time.Second):
		t.Fatal("first COMMIT did not reach the internal retry response")
	}
	select {
	case <-secondCommit:
		t.Fatal("COMMIT resubmitted before the matching local visibility repair completed")
	case <-time.After(25 * time.Millisecond):
	}
	fixture.raw.mu.Lock()
	fixture.raw.completedVisibilitySequence = 17
	fixture.raw.signalSourceChangedLocked()
	fixture.raw.mu.Unlock()
	var status fuse.Status
	select {
	case status = <-result:
	case <-time.After(2 * time.Second):
		t.Fatal("COMMIT did not resume after the matching local visibility repair")
	}
	if !status.Ok() {
		t.Fatalf("internally retried COMMIT = %v", status)
	}
	if out.Flags != fuse.PFS_WRITE_OUT_COMMITTED || out.CommittedSize != 3 || out.AssignedOffset != 100 || out.PostSize != 103 {
		t.Fatalf("internally retried COMMIT result = %+v", out)
	}
	if got := internal.calls.Load(); got != 1 {
		t.Fatalf("internal retry response consumption = %d, want immediate 1", got)
	}
	if got := committed.calls.Load(); got != 0 {
		t.Fatalf("committed response consumed before publication = %d", got)
	}
	fixture.rpc.snapshot(func(rpc *fakeRPC) {
		want := []authoritypb.WriteTransactionPhase{
			authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_BEGIN,
			authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA,
			authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_COMMIT,
			authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_COMMIT,
		}
		if len(rpc.writeTransactions) != len(want) {
			t.Fatalf("authority write phases = %+v", rpc.writeTransactions)
		}
		for index, phase := range want {
			if rpc.writeTransactions[index].GetPhase() != phase || rpc.writeTransactions[index].GetTransactionId() != 1 {
				t.Fatalf("authority write phase[%d] = %+v", index, rpc.writeTransactions[index])
			}
		}
		if len(frontendOperationIDs) != 2 || frontendOperationIDs[0] == 0 || frontendOperationIDs[0] != frontendOperationIDs[1] {
			t.Fatalf("COMMIT frontend operation identities = %v", frontendOperationIDs)
		}
		if len(retryAfterSequences) != 2 || retryAfterSequences[0] != 0 || retryAfterSequences[1] != 17 {
			t.Fatalf("COMMIT visibility retry proofs = %v, want [0 17]", retryAfterSequences)
		}
	})
	if !fixture.raw.ReplyPublishMarked(unique, nodeID, fuse.PFS_WRITE_OPCODE) {
		t.Fatal("internally retried COMMIT was not publication-marked")
	}
	fixture.raw.ReplyWritten(unique, fuse.OK)
	if fixture.mount.isRevoked() {
		t.Fatalf("mount revoked after committed reply write: %v", fixture.mount.fatalError())
	}
	if got := committed.calls.Load(); got != 0 {
		t.Fatalf("committed response consumed at original reply = %d", got)
	}
	publishUnique := fixture.unique.Add(2)
	publishOut := &fuse.PFSPublishOut{}
	if status := fixture.raw.PFSPublish(nil, &fuse.PFSPublishIn{
		InHeader: fuse.InHeader{Unique: publishUnique}, RequestUnique: unique,
		PublicationID: 1, Nodeid: nodeID, Opcode: fuse.PFS_WRITE_OPCODE,
	}, publishOut); !status.Ok() {
		t.Fatalf("PFS_PUBLISH after internally retried COMMIT = %v (fatal=%v)", status, fixture.mount.fatalError())
	}
	if publishOut.RequestUnique != unique || publishOut.PublicationID != 1 || publishOut.Nodeid != nodeID ||
		publishOut.Opcode != fuse.PFS_WRITE_OPCODE || publishOut.Flags != fuse.PFS_PUBLISH_ACK {
		t.Fatalf("PFS_PUBLISH ACK = %+v", publishOut)
	}
	fixture.raw.ReplyWritten(publishUnique, fuse.OK)
	if got := committed.calls.Load(); got != 1 {
		t.Fatalf("committed response consumption after publication = %d, want 1", got)
	}
}

func TestPFSWritePositionedModeFreezesAndCommitsExactPosition(t *testing.T) {
	fixture := newStrictFixture(t)
	nodeID, handle := openWriteTransactionTestHandle(t, fixture)
	const (
		kernelTxid = uint64(9001)
		position   = uint64(150)
	)
	begin := writeTransactionInput(nodeID, handle, kernelTxid, 6, fuse.PFS_WRITE_BEGIN)
	begin.Flags, begin.Position = 0, position
	if status := callWriteTransaction(fixture, begin, nil, &fuse.PFSWriteOut{}); !status.Ok() {
		t.Fatalf("positioned BEGIN = %v", status)
	}
	data := writeTransactionInput(nodeID, handle, kernelTxid, 6, fuse.PFS_WRITE_DATA)
	data.Flags, data.Position, data.Size = 0, position, 6
	if status := callWriteTransaction(fixture, data, []byte("abcdef"), &fuse.PFSWriteOut{}); !status.Ok() {
		t.Fatalf("positioned DATA = %v", status)
	}
	commit := writeTransactionInput(nodeID, handle, kernelTxid, 6, fuse.PFS_WRITE_COMMIT)
	commit.Flags, commit.Position, commit.FragmentOffset = 0, position, 6
	out := &fuse.PFSWriteOut{}
	if status := callWriteTransaction(fixture, commit, nil, out); !status.Ok() {
		t.Fatalf("positioned COMMIT = %v", status)
	}
	if out.Flags != fuse.PFS_WRITE_OUT_COMMITTED || out.CommittedSize != 6 ||
		out.AssignedOffset != position || out.PostSize != position+6 || out.Sequence != 17 {
		t.Fatalf("positioned COMMIT result = %+v", out)
	}
	fixture.rpc.snapshot(func(rpc *fakeRPC) {
		if len(rpc.writeTransactions) != 3 {
			t.Fatalf("positioned authority phases = %+v", rpc.writeTransactions)
		}
		for index, request := range rpc.writeTransactions {
			if request.GetPosition() != position || request.GetFlags() != 0 || request.GetTransactionId() != 1 {
				t.Fatalf("positioned authority phase %d = %+v", index, request)
			}
		}
	})
}

func TestPFSWriteRejectsNoncanonicalOperationFlagsBeforeDispatch(t *testing.T) {
	fixture := newStrictFixture(t)
	nodeID, handle := openWriteTransactionTestHandle(t, fixture)
	tests := []struct {
		name   string
		change func(*fuse.PFSWriteIn)
	}{
		{name: "append carries position", change: func(in *fuse.PFSWriteIn) { in.Position = 1 }},
		{name: "position reaches RLIMIT", change: func(in *fuse.PFSWriteIn) {
			in.Flags, in.Position, in.RlimitFsize = 0, 10, 10
		}},
		{name: "position reaches zero RLIMIT", change: func(in *fuse.PFSWriteIn) {
			in.Flags, in.Position, in.RlimitFsize = 0, 0, 0
		}},
		{name: "position reaches file maximum", change: func(in *fuse.PFSWriteIn) {
			in.Flags, in.Position, in.FileMaxSize = 0, 10, 10
		}},
		{name: "cache write flag", change: func(in *fuse.PFSWriteIn) { in.WriteFlags |= fuse.WRITE_CACHE }},
		{name: "unknown file flag", change: func(in *fuse.PFSWriteIn) { in.Flags |= uint32(syscall.O_NONBLOCK) }},
		{name: "owner without lockowner", change: func(in *fuse.PFSWriteIn) { in.WriteFlags = 0 }},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			in := writeTransactionInput(nodeID, handle, uint64(9100+index), 2, fuse.PFS_WRITE_BEGIN)
			test.change(in)
			if status := callWriteTransaction(fixture, in, nil, &fuse.PFSWriteOut{}); status != writeTransactionProtocolError {
				t.Fatalf("malformed BEGIN = %v, want EPROTO", status)
			}
		})
	}
	fixture.rpc.snapshot(func(rpc *fakeRPC) {
		if len(rpc.writeTransactions) != 0 {
			t.Fatalf("noncanonical metadata reached authority: %+v", rpc.writeTransactions)
		}
	})
}

func TestPFSWriteRejectsOddKernelRequestIdentityBeforeDispatch(t *testing.T) {
	fixture := newStrictFixture(t)
	nodeID, handle := openWriteTransactionTestHandle(t, fixture)
	in := writeTransactionInput(nodeID, handle, 9199, 1, fuse.PFS_WRITE_BEGIN)
	in.Unique = 11
	if status := fixture.raw.PFSWrite(nil, in, nil, &fuse.PFSWriteOut{}); status != writeTransactionProtocolError {
		t.Fatalf("odd PFS_WRITE request identity = %v, want EPROTO", status)
	}
	fixture.rpc.snapshot(func(rpc *fakeRPC) {
		if len(rpc.writeTransactions) != 0 {
			t.Fatalf("odd request identity reached authority: %+v", rpc.writeTransactions)
		}
	})
}

func TestPFSWriteAppendMayStageMoreThanAbsoluteEndLimit(t *testing.T) {
	fixture := newStrictFixture(t)
	nodeID, handle := openWriteTransactionTestHandle(t, fixture)
	begin := writeTransactionInput(nodeID, handle, 9201, 100, fuse.PFS_WRITE_BEGIN)
	begin.FileMaxSize = 10
	if status := callWriteTransaction(fixture, begin, nil, &fuse.PFSWriteOut{}); !status.Ok() {
		t.Fatalf("append BEGIN above absolute end limit = %v; authority must be able to short-commit at EOF", status)
	}
	abort := writeTransactionInput(nodeID, handle, 9201, 100, fuse.PFS_WRITE_ABORT)
	abort.FileMaxSize = 10
	if status := callWriteTransaction(fixture, abort, nil, &fuse.PFSWriteOut{}); !status.Ok() {
		t.Fatalf("cleanup ABORT = %v", status)
	}
}

func TestPFSWritePreservesRawRLIMITForAuthorityDecision(t *testing.T) {
	fixture := newStrictFixture(t)
	nodeID, handle := openWriteTransactionTestHandle(t, fixture)
	tests := []struct {
		name     string
		rlimit   uint64
		flags    uint32
		position uint64
	}{
		{name: "zero finite append ceiling", rlimit: 0, flags: uint32(syscall.O_APPEND)},
		{name: "one-byte positioned ceiling", rlimit: 1, position: 0},
		{name: "infinite positioned ceiling", rlimit: ^uint64(0), position: 1},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			txid := uint64(9207 + index)
			begin := writeTransactionInput(nodeID, handle, txid, 1, fuse.PFS_WRITE_BEGIN)
			begin.RlimitFsize, begin.Flags, begin.Position = test.rlimit, test.flags, test.position
			if status := callWriteTransaction(fixture, begin, nil, &fuse.PFSWriteOut{}); !status.Ok() {
				t.Fatalf("BEGIN with raw RLIMIT_FSIZE %#x = %v", test.rlimit, status)
			}
			abort := writeTransactionInput(nodeID, handle, txid, 1, fuse.PFS_WRITE_ABORT)
			abort.RlimitFsize, abort.Flags, abort.Position = test.rlimit, test.flags, test.position
			if status := callWriteTransaction(fixture, abort, nil, &fuse.PFSWriteOut{}); !status.Ok() {
				t.Fatalf("cleanup ABORT with raw RLIMIT_FSIZE %#x = %v", test.rlimit, status)
			}
		})
	}
	fixture.rpc.snapshot(func(rpc *fakeRPC) {
		requests := rpc.writeTransactions[len(rpc.writeTransactions)-2*len(tests):]
		for index, request := range requests {
			want := tests[index/2].rlimit
			if request.GetRlimitFsize() != want || request.GetFileMaxSize() == 0 {
				t.Fatalf("raw RLIMIT authority metadata %d = %+v, want %#x", index, request, want)
			}
		}
	})
}

func TestPFSWriteCommitsExactStagedPrefixAfterShortCopy(t *testing.T) {
	fixture := newStrictFixture(t)
	nodeID, handle := openWriteTransactionTestHandle(t, fixture)
	const kernelTxid = 9202
	begin := writeTransactionInput(nodeID, handle, kernelTxid, 6, fuse.PFS_WRITE_BEGIN)
	if status := callWriteTransaction(fixture, begin, nil, &fuse.PFSWriteOut{}); !status.Ok() {
		t.Fatalf("BEGIN = %v", status)
	}
	data := writeTransactionInput(nodeID, handle, kernelTxid, 6, fuse.PFS_WRITE_DATA)
	data.Size = 3
	if status := callWriteTransaction(fixture, data, []byte("abc"), &fuse.PFSWriteOut{}); !status.Ok() {
		t.Fatalf("short DATA prefix = %v", status)
	}
	commit := writeTransactionInput(nodeID, handle, kernelTxid, 6, fuse.PFS_WRITE_COMMIT)
	commit.FragmentOffset = 3
	out := &fuse.PFSWriteOut{}
	if status := callWriteTransaction(fixture, commit, nil, out); !status.Ok() {
		t.Fatalf("prefix COMMIT = %v", status)
	}
	if out.Flags != fuse.PFS_WRITE_OUT_COMMITTED || out.CommittedSize != 3 || out.AssignedOffset != 100 || out.PostSize != 103 {
		t.Fatalf("prefix COMMIT result = %+v", out)
	}
	fixture.rpc.snapshot(func(rpc *fakeRPC) {
		last := rpc.writeTransactions[len(rpc.writeTransactions)-1]
		if last.GetPhase() != authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_COMMIT || last.GetFragmentOffset() != 3 || last.GetRequestedSize() != 6 {
			t.Fatalf("authority prefix COMMIT = %+v", last)
		}
	})
}

func TestPFSWriteRejectedCommitUsesOnlyPhysicalNoChangeBoundary(t *testing.T) {
	fixture := newStrictFixture(t)
	nodeID, handle := openWriteTransactionTestHandle(t, fixture)
	const kernelTxid = 9203
	begin := writeTransactionInput(nodeID, handle, kernelTxid, 3, fuse.PFS_WRITE_BEGIN)
	if status := callWriteTransaction(fixture, begin, nil, &fuse.PFSWriteOut{}); !status.Ok() {
		t.Fatalf("BEGIN = %v", status)
	}
	data := writeTransactionInput(nodeID, handle, kernelTxid, 3, fuse.PFS_WRITE_DATA)
	data.Size = 3
	if status := callWriteTransaction(fixture, data, []byte("abc"), &fuse.PFSWriteOut{}); !status.Ok() {
		t.Fatalf("DATA = %v", status)
	}
	fixture.rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
		writeRequest := request.GetWriteTransaction()
		fixture.rpc.writeTransactions = append(fixture.rpc.writeTransactions, writeRequest)
		return &authoritypb.Response{Body: &authoritypb.Response_WriteTransaction{WriteTransaction: &authoritypb.WriteTransactionReply{
			TransactionId: writeRequest.GetTransactionId(),
			Flags:         fuse.PFS_WRITE_OUT_REJECTED,
			Error:         -int32(syscall.ENOSPC),
		}}}, nil
	}
	commit := writeTransactionInput(nodeID, handle, kernelTxid, 3, fuse.PFS_WRITE_COMMIT)
	commit.FragmentOffset = 3
	commitUnique := fixture.unique.Add(2)
	commit.Unique = commitUnique
	out := &fuse.PFSWriteOut{}
	if status := fixture.raw.PFSWrite(nil, commit, nil, out); !status.Ok() {
		t.Fatalf("REJECTED COMMIT transport = %v", status)
	}
	if out.Txid != kernelTxid || out.Flags != fuse.PFS_WRITE_OUT_REJECTED || out.Error != -int32(syscall.ENOSPC) ||
		out.CommittedSize != 0 || out.AssignedOffset != 0 || out.PostSize != 0 || out.Sequence != 0 {
		t.Fatalf("REJECTED COMMIT result = %+v", out)
	}
	if !fixture.raw.ReplyWriteOrdered(commitUnique) {
		t.Fatal("REJECTED COMMIT did not retain its source gate through physical response delivery")
	}
	if fixture.raw.ReplyPublishMarked(commitUnique, nodeID, fuse.PFS_WRITE_OPCODE) {
		t.Fatal("definite pre-apply rejection requested a post-VFS publication")
	}
	fixture.raw.writeMu.Lock()
	_, retainedBeforeWrite := fixture.raw.writeTx[kernelTxid]
	fixture.raw.writeMu.Unlock()
	if !retainedBeforeWrite {
		t.Fatal("REJECTED transaction retired before physical response delivery")
	}
	fixture.raw.ReplyWritten(commitUnique, fuse.OK)
	fixture.raw.writeMu.Lock()
	_, retainedAfterWrite := fixture.raw.writeTx[kernelTxid]
	fixture.raw.writeMu.Unlock()
	if retainedAfterWrite || fixture.mount.isRevoked() {
		t.Fatalf("REJECTED physical completion retained=%t revoked=%t fatal=%v", retainedAfterWrite, fixture.mount.isRevoked(), fixture.mount.fatalError())
	}
}

func TestPFSWritePeerFirstCommitWaitsWithoutLeakingEINTR(t *testing.T) {
	fixture := newStrictFixture(t)
	nodeID, handle := openWriteTransactionTestHandle(t, fixture)
	const kernelTxid = 9204
	begin := writeTransactionInput(nodeID, handle, kernelTxid, 3, fuse.PFS_WRITE_BEGIN)
	if status := callWriteTransaction(fixture, begin, nil, &fuse.PFSWriteOut{}); !status.Ok() {
		t.Fatalf("BEGIN = %v", status)
	}
	data := writeTransactionInput(nodeID, handle, kernelTxid, 3, fuse.PFS_WRITE_DATA)
	data.Size = 3
	if status := callWriteTransaction(fixture, data, []byte("abc"), &fuse.PFSWriteOut{}); !status.Ok() {
		t.Fatalf("DATA = %v", status)
	}
	targets := []*authoritypb.VisibilityTarget{
		inodeVisibilityTarget(authoritypb.VisibilityScope_VISIBILITY_SCOPE_DATA, 7, 3),
	}
	if err := fixture.raw.prepareVisibility(context.Background(), targets, false); err != nil {
		t.Fatalf("install peer-first PREPARE: %v", err)
	}

	commit := writeTransactionInput(nodeID, handle, kernelTxid, 3, fuse.PFS_WRITE_COMMIT)
	commit.FragmentOffset = 3
	commit.Unique = fixture.unique.Add(2)
	out := &fuse.PFSWriteOut{}
	commitDone := make(chan fuse.Status, 1)
	go func() { commitDone <- fixture.raw.PFSWrite(nil, commit, nil, out) }()
	select {
	case status := <-commitDone:
		t.Fatalf("item-only COMMIT overtook the prior peer repair: %v", status)
	case <-time.After(50 * time.Millisecond):
	}
	fixture.rpc.snapshot(func(rpc *fakeRPC) {
		phases := make([]authoritypb.WriteTransactionPhase, 0, len(rpc.writeTransactions))
		for _, request := range rpc.writeTransactions {
			phases = append(phases, request.GetPhase())
		}
		want := []authoritypb.WriteTransactionPhase{
			authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_BEGIN,
			authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA,
		}
		if !slices.Equal(phases, want) {
			t.Fatalf("authority phases before peer repair = %v, want %v", phases, want)
		}
	})

	finishPeerVisibility(t, fixture.raw, targets)
	select {
	case status := <-commitDone:
		if !status.Ok() {
			t.Fatalf("waiting COMMIT transport = %v", status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiting COMMIT did not resume after peer repair")
	}
	if out.Txid != kernelTxid || out.Flags != fuse.PFS_WRITE_OUT_COMMITTED || out.Error != 0 ||
		out.CommittedSize != 3 || out.AssignedOffset != 100 || out.PostSize != 103 || out.Sequence != 17 {
		t.Fatalf("waiting COMMIT result = %+v", out)
	}
	finishPrivatePublication(t, fixture, commit.Unique, nodeID, fuse.PFS_WRITE_OPCODE)
	fixture.rpc.snapshot(func(rpc *fakeRPC) {
		phases := make([]authoritypb.WriteTransactionPhase, 0, len(rpc.writeTransactions))
		for _, request := range rpc.writeTransactions {
			phases = append(phases, request.GetPhase())
		}
		want := []authoritypb.WriteTransactionPhase{
			authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_BEGIN,
			authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA,
			authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_COMMIT,
		}
		if !slices.Equal(phases, want) {
			t.Fatalf("authority phases after peer repair = %v, want %v", phases, want)
		}
	})
}

func TestPFSWriteRLIMITRejectionRemainsDistinctAndUnpublished(t *testing.T) {
	fixture := newStrictFixture(t)
	nodeID, handle := openWriteTransactionTestHandle(t, fixture)
	const kernelTxid = 9208
	begin := writeTransactionInput(nodeID, handle, kernelTxid, 1, fuse.PFS_WRITE_BEGIN)
	begin.RlimitFsize = 0
	if status := callWriteTransaction(fixture, begin, nil, &fuse.PFSWriteOut{}); !status.Ok() {
		t.Fatalf("BEGIN = %v", status)
	}
	data := writeTransactionInput(nodeID, handle, kernelTxid, 1, fuse.PFS_WRITE_DATA)
	data.RlimitFsize, data.Size = 0, 1
	if status := callWriteTransaction(fixture, data, []byte("x"), &fuse.PFSWriteOut{}); !status.Ok() {
		t.Fatalf("DATA = %v", status)
	}
	fixture.rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
		writeRequest := request.GetWriteTransaction()
		fixture.rpc.writeTransactions = append(fixture.rpc.writeTransactions, writeRequest)
		return &authoritypb.Response{Body: &authoritypb.Response_WriteTransaction{WriteTransaction: &authoritypb.WriteTransactionReply{
			TransactionId: writeRequest.GetTransactionId(),
			Flags:         fuse.PFS_WRITE_OUT_REJECTED_RLIMIT,
			Error:         -int32(syscall.EFBIG),
		}}}, nil
	}
	commit := writeTransactionInput(nodeID, handle, kernelTxid, 1, fuse.PFS_WRITE_COMMIT)
	commit.RlimitFsize, commit.FragmentOffset = 0, 1
	unique := fixture.unique.Add(2)
	commit.Unique = unique
	out := &fuse.PFSWriteOut{}
	if status := fixture.raw.PFSWrite(nil, commit, nil, out); !status.Ok() {
		t.Fatalf("RLIMIT COMMIT rejection transport = %v", status)
	}
	if out.Txid != kernelTxid || out.Flags != fuse.PFS_WRITE_OUT_REJECTED_RLIMIT || out.Error != -int32(syscall.EFBIG) ||
		out.CommittedSize != 0 || out.AssignedOffset != 0 || out.PostSize != 0 || out.Sequence != 0 {
		t.Fatalf("RLIMIT COMMIT rejection = %+v", out)
	}
	if fixture.raw.ReplyPublishMarked(unique, nodeID, fuse.PFS_WRITE_OPCODE) {
		t.Fatal("RLIMIT pre-apply rejection requested a post-VFS publication")
	}
	fixture.raw.ReplyWritten(unique, fuse.OK)
	fixture.raw.writeMu.Lock()
	_, retained := fixture.raw.writeTx[kernelTxid]
	fixture.raw.writeMu.Unlock()
	if retained || fixture.mount.isRevoked() {
		t.Fatalf("RLIMIT rejection retained=%t revoked=%t fatal=%v", retained, fixture.mount.isRevoked(), fixture.mount.fatalError())
	}

	bad := &authoritypb.WriteTransactionReply{TransactionId: 1, Flags: fuse.PFS_WRITE_OUT_REJECTED_RLIMIT, Error: -int32(syscall.ENOSPC)}
	if validWriteTransactionReply(bad, 1, fuse.PFS_WRITE_OUT_COMMITTED) {
		t.Fatal("REJECTED_RLIMIT accepted an errno other than EFBIG")
	}
}

func TestPFSWritePostapplyErrorPublishesExactCommittedState(t *testing.T) {
	fixture := newStrictFixture(t)
	nodeID, handle := openWriteTransactionTestHandle(t, fixture)
	const kernelTxid = 9204
	begin := writeTransactionInput(nodeID, handle, kernelTxid, 3, fuse.PFS_WRITE_BEGIN)
	if status := callWriteTransaction(fixture, begin, nil, &fuse.PFSWriteOut{}); !status.Ok() {
		t.Fatalf("BEGIN = %v", status)
	}
	data := writeTransactionInput(nodeID, handle, kernelTxid, 3, fuse.PFS_WRITE_DATA)
	data.Size = 3
	if status := callWriteTransaction(fixture, data, []byte("abc"), &fuse.PFSWriteOut{}); !status.Ok() {
		t.Fatalf("DATA = %v", status)
	}
	fixture.rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
		writeRequest := request.GetWriteTransaction()
		fixture.rpc.writeTransactions = append(fixture.rpc.writeTransactions, writeRequest)
		return &authoritypb.Response{
			PostAttr: &authoritypb.Attr{Inode: 7, Kind: authoritypb.Attr_REGULAR, Mode: 0o600, Size: 103},
			Body: &authoritypb.Response_WriteTransaction{WriteTransaction: &authoritypb.WriteTransactionReply{
				TransactionId:      writeRequest.GetTransactionId(),
				CommittedSize:      3,
				AssignedOffset:     100,
				PostSize:           103,
				VisibilitySequence: 18,
				Flags:              fuse.PFS_WRITE_OUT_COMMITTED | fuse.PFS_WRITE_OUT_POSTAPPLY_ERROR,
				Error:              -int32(syscall.EIO),
			}},
		}, nil
	}
	commit := writeTransactionInput(nodeID, handle, kernelTxid, 3, fuse.PFS_WRITE_COMMIT)
	commit.FragmentOffset = 3
	out := &fuse.PFSWriteOut{}
	if status := callWriteTransaction(fixture, commit, nil, out); !status.Ok() {
		t.Fatalf("post-apply COMMIT transport = %v", status)
	}
	if out.Flags != fuse.PFS_WRITE_OUT_COMMITTED|fuse.PFS_WRITE_OUT_POSTAPPLY_ERROR || out.Error != -int32(syscall.EIO) ||
		out.CommittedSize != 3 || out.AssignedOffset != 100 || out.PostSize != 103 || out.Sequence != 18 {
		t.Fatalf("post-apply COMMIT result = %+v", out)
	}
	fixture.raw.writeMu.Lock()
	_, retained := fixture.raw.writeTx[kernelTxid]
	fixture.raw.writeMu.Unlock()
	if retained || fixture.mount.isRevoked() {
		t.Fatalf("post-apply publication retained=%t revoked=%t fatal=%v", retained, fixture.mount.isRevoked(), fixture.mount.fatalError())
	}
}

func TestPFSWriteZeroBytePostapplyPublishesExactAttributeStateWithoutPosition(t *testing.T) {
	fixture := newStrictFixture(t)
	nodeID, handle := openWriteTransactionTestHandle(t, fixture)
	const kernelTxid = 9207
	begin := writeTransactionInput(nodeID, handle, kernelTxid, 3, fuse.PFS_WRITE_BEGIN)
	if status := callWriteTransaction(fixture, begin, nil, &fuse.PFSWriteOut{}); !status.Ok() {
		t.Fatalf("BEGIN = %v", status)
	}
	data := writeTransactionInput(nodeID, handle, kernelTxid, 3, fuse.PFS_WRITE_DATA)
	data.Size = 3
	if status := callWriteTransaction(fixture, data, []byte("abc"), &fuse.PFSWriteOut{}); !status.Ok() {
		t.Fatalf("DATA = %v", status)
	}
	fixture.rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
		writeRequest := request.GetWriteTransaction()
		return &authoritypb.Response{
			PostAttr: &authoritypb.Attr{Inode: 7, Kind: authoritypb.Attr_REGULAR, Mode: 0o600, Size: 100},
			Body: &authoritypb.Response_WriteTransaction{WriteTransaction: &authoritypb.WriteTransactionReply{
				TransactionId: writeRequest.GetTransactionId(), PostSize: 100, VisibilitySequence: 19,
				Flags: fuse.PFS_WRITE_OUT_COMMITTED | fuse.PFS_WRITE_OUT_POSTAPPLY_ERROR,
				Error: -int32(syscall.EIO),
			}},
		}, nil
	}
	commit := writeTransactionInput(nodeID, handle, kernelTxid, 3, fuse.PFS_WRITE_COMMIT)
	commit.FragmentOffset = 3
	out := &fuse.PFSWriteOut{}
	if status := callWriteTransaction(fixture, commit, nil, out); !status.Ok() {
		t.Fatalf("zero-byte post-apply COMMIT transport = %v", status)
	}
	want := fuse.PFSWriteOut{
		Txid: kernelTxid, PostSize: 100, Sequence: 19,
		Flags: fuse.PFS_WRITE_OUT_COMMITTED | fuse.PFS_WRITE_OUT_POSTAPPLY_ERROR,
		Error: -int32(syscall.EIO),
	}
	if *out != want {
		t.Fatalf("zero-byte post-apply COMMIT = %+v, want %+v", out, want)
	}
	if fixture.mount.isRevoked() {
		t.Fatalf("valid zero-byte post-apply result revoked mount: %v", fixture.mount.fatalError())
	}
}

func TestPFSWriteAcceptsKernelMaxRWCountWithoutAllocatingOneFrame(t *testing.T) {
	fixture := newStrictFixture(t)
	nodeID, handle := openWriteTransactionTestHandle(t, fixture)
	limit := kernelMaxRWCount()
	begin := writeTransactionInput(nodeID, handle, 9205, limit, fuse.PFS_WRITE_BEGIN)
	if status := callWriteTransaction(fixture, begin, nil, &fuse.PFSWriteOut{}); !status.Ok() {
		t.Fatalf("MAX_RW_COUNT BEGIN = %v", status)
	}
	abort := writeTransactionInput(nodeID, handle, 9205, limit, fuse.PFS_WRITE_ABORT)
	if status := callWriteTransaction(fixture, abort, nil, &fuse.PFSWriteOut{}); !status.Ok() {
		t.Fatalf("MAX_RW_COUNT ABORT = %v", status)
	}
	tooLarge := writeTransactionInput(nodeID, handle, 9206, limit+1, fuse.PFS_WRITE_BEGIN)
	if status := callWriteTransaction(fixture, tooLarge, nil, &fuse.PFSWriteOut{}); status != writeTransactionProtocolError {
		t.Fatalf("above MAX_RW_COUNT BEGIN = %v, want EPROTO", status)
	}
}

func TestPFSWriteAmbiguousBeginRetainsTranslationForAbortAndNeverReusesSequence(t *testing.T) {
	fixture := newStrictFixture(t)
	nodeID, handle := openWriteTransactionTestHandle(t, fixture)
	failFirstBegin := true
	fixture.rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
		writeRequest := request.GetWriteTransaction()
		if writeRequest == nil {
			return nil, errors.New("unexpected non-write-transaction request")
		}
		fixture.rpc.writeTransactions = append(fixture.rpc.writeTransactions, writeRequest)
		if writeRequest.GetPhase() == authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_BEGIN && failFirstBegin {
			failFirstBegin = false
			return nil, errors.New("lost BEGIN reply")
		}
		flag := uint32(fuse.PFS_WRITE_OUT_ABORTED)
		if writeRequest.GetPhase() == authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_BEGIN {
			flag = fuse.PFS_WRITE_OUT_BEGUN
		}
		return &authoritypb.Response{Body: &authoritypb.Response_WriteTransaction{WriteTransaction: &authoritypb.WriteTransactionReply{
			TransactionId: writeRequest.GetTransactionId(), Flags: flag,
		}}}, nil
	}

	first := writeTransactionInput(nodeID, handle, 1001, 1, fuse.PFS_WRITE_BEGIN)
	if status := callWriteTransaction(fixture, first, nil, &fuse.PFSWriteOut{}); status.Ok() {
		t.Fatal("ambiguous BEGIN unexpectedly succeeded")
	}
	abort := writeTransactionInput(nodeID, handle, 1001, 1, fuse.PFS_WRITE_ABORT)
	if status := callWriteTransaction(fixture, abort, nil, &fuse.PFSWriteOut{}); !status.Ok() {
		t.Fatalf("ABORT after ambiguous BEGIN = %v", status)
	}
	second := writeTransactionInput(nodeID, handle, 1002, 1, fuse.PFS_WRITE_BEGIN)
	if status := callWriteTransaction(fixture, second, nil, &fuse.PFSWriteOut{}); !status.Ok() {
		t.Fatalf("second BEGIN = %v", status)
	}

	fixture.rpc.snapshot(func(rpc *fakeRPC) {
		if len(rpc.writeTransactions) != 3 || rpc.writeTransactions[0].GetTransactionId() != 1 || rpc.writeTransactions[1].GetTransactionId() != 1 ||
			rpc.writeTransactions[1].GetPhase() != authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_ABORT || rpc.writeTransactions[2].GetTransactionId() != 2 {
			t.Fatalf("authority transaction translation = %+v", rpc.writeTransactions)
		}
	})
}

func TestPFSWriteRejectsMetadataDriftAndNoncontiguousDataLocally(t *testing.T) {
	fixture := newStrictFixture(t)
	nodeID, handle := openWriteTransactionTestHandle(t, fixture)
	begin := writeTransactionInput(nodeID, handle, 77, 4, fuse.PFS_WRITE_BEGIN)
	if status := callWriteTransaction(fixture, begin, nil, &fuse.PFSWriteOut{}); !status.Ok() {
		t.Fatalf("BEGIN = %v", status)
	}

	drift := writeTransactionInput(nodeID, handle, 77, 4, fuse.PFS_WRITE_DATA)
	drift.FragmentOffset, drift.Size, drift.LockOwner = 0, 1, begin.LockOwner+1
	if status := callWriteTransaction(fixture, drift, []byte{'x'}, &fuse.PFSWriteOut{}); status != writeTransactionProtocolError {
		t.Fatalf("metadata drift = %v, want EPROTO", status)
	}
	noncontiguous := writeTransactionInput(nodeID, handle, 77, 4, fuse.PFS_WRITE_DATA)
	noncontiguous.FragmentOffset, noncontiguous.Size = 1, 1
	if status := callWriteTransaction(fixture, noncontiguous, []byte{'x'}, &fuse.PFSWriteOut{}); status != writeTransactionProtocolError {
		t.Fatalf("noncontiguous DATA = %v, want EPROTO", status)
	}
	fixture.rpc.snapshot(func(rpc *fakeRPC) {
		if len(rpc.writeTransactions) != 1 {
			t.Fatalf("locally malformed phases reached authority: %+v", rpc.writeTransactions)
		}
	})
}
