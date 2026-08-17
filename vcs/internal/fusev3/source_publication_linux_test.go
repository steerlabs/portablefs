//go:build linux

package fusev3

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"google.golang.org/protobuf/proto"
)

func testPublicationIdentity(t *testing.T, item *authoritypb.Item) publicationIdentity {
	t.Helper()
	identity, ok := publicationIdentityFromItem(item)
	if !ok {
		t.Fatal("test item has no stable publication identity")
	}
	return identity
}

// waitSourceState waits on the state machine's own transition channel. The
// assertions which follow it are therefore ordering proofs, not sleeps which
// merely hope a competing goroutine has run.
func waitSourceState(t *testing.T, raw *rawFileSystem, what string, condition func(*rawFileSystem) bool) {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	for {
		raw.mu.Lock()
		if condition(raw) {
			raw.mu.Unlock()
			return
		}
		changed := raw.sourceChanged
		raw.mu.Unlock()
		select {
		case <-changed:
		case <-timer.C:
			t.Fatalf("timed out waiting for %s", what)
		}
	}
}

func assertNoPrepareResult(t *testing.T, done <-chan error, what string) {
	t.Helper()
	select {
	case err := <-done:
		t.Fatalf("%s completed before publication: %v", what, err)
	default:
	}
}

func awaitPrepareResult(t *testing.T, done <-chan error, what string) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		return nil
	}
}

func finishPeerVisibility(t *testing.T, raw *rawFileSystem, targets []*authoritypb.VisibilityTarget) {
	t.Helper()
	completion, blocked, err := raw.beginVisibilityComplete(targets, false)
	if err != nil {
		t.Fatal(err)
	}
	if blocked {
		t.Fatal("lockless visibility completion unexpectedly reported blocked")
	}
	if err := raw.finishVisibilityComplete(context.Background(), completion); err != nil {
		t.Fatal(err)
	}
}

func TestSourcePublicationGateCanonicalizesExactCoordinates(t *testing.T) {
	first := testPublicationIdentity(t, testItem(11, authoritypb.Attr_REGULAR, 11))
	second := testPublicationIdentity(t, testItem(22, authoritypb.Attr_REGULAR, 22))
	parent := testPublicationIdentity(t, testItem(3, authoritypb.Attr_DIRECTORY, 3))
	gate, err := sourcePublicationGate(
		[]sourceItemSpec{
			{identity: second, attributes: true},
			{identity: first, attributes: true},
			{identity: second, attributes: true, data: true},
		},
		[]sourceNamespaceSpec{
			{parent: parent, name: "z", attributes: true},
			{parent: parent, name: "a", attributes: true},
			{parent: parent, name: "z", attributes: true, data: true},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	targets := gate.GetTargets()
	if len(targets) != 4 {
		t.Fatalf("canonical targets = %d, want two items and two namespaces", len(targets))
	}
	if !bytes.Equal(targets[0].GetItem().GetIdentity(), first[:]) || targets[0].GetItem().GetData() {
		t.Fatalf("first target = %#v, want the lower item identity with attributes only", targets[0])
	}
	if !bytes.Equal(targets[1].GetItem().GetIdentity(), second[:]) || !targets[1].GetItem().GetAttributes() || !targets[1].GetItem().GetData() {
		t.Fatalf("second target = %#v, want duplicate item scopes merged by OR", targets[1])
	}
	if got := string(targets[2].GetNamespace().GetName()); got != "a" {
		t.Fatalf("first namespace = %q, want raw-byte canonical order", got)
	}
	last := targets[3].GetNamespace()
	if string(last.GetName()) != "z" || !last.GetBoundAttributes() || !last.GetBoundData() {
		t.Fatalf("last namespace = %#v, want duplicate bound scopes merged by OR", last)
	}
}

func TestSourcePublicationNamespaceDecodesNameAndUnresolvedScopes(t *testing.T) {
	f := newStrictFixture(t)
	gate := mustNamespaceSourceGate(t, f.raw.nodesByID[fuse.FUSE_ROOT_ID].node.item, "bound", true)
	coordinates, names, err := coordinatesForSourceGate(gate)
	if err != nil {
		t.Fatal(err)
	}
	parent := testPublicationIdentity(t, f.raw.nodesByID[fuse.FUSE_ROOT_ID].node.item)
	namespace := publicationNamespace{parent: parent, name: "bound"}
	if bounds, found := names[namespace]; !found || !bounds.attributes || !bounds.data {
		t.Fatalf("decoded namespace = (%+v, %t), want exact name with attrs+data", bounds, found)
	}
	if _, found := coordinates[publicationCoordinate{kind: publicationNamespaceName, parent: parent, name: "bound"}]; !found {
		t.Fatal("decoded source footprint omitted its exact namespace coordinate")
	}
	lease, err := f.raw.acquireSourcePublication(context.Background(), gate)
	if err != nil {
		t.Fatal(err)
	}
	f.raw.mu.Lock()
	attrs, data := lease.unresolvedAttributes, lease.unresolvedData
	f.raw.mu.Unlock()
	if attrs != 1 || data != 1 {
		t.Fatalf("unresolved namespace counters = attrs %d data %d, want 1/1", attrs, data)
	}
	lease.resolveAllNoBinding()
	if err := lease.markDefiniteNoChange(); err != nil {
		t.Fatal(err)
	}
	lease.release()
}

func TestUnresolvedNamespaceDrainsAlreadyAdmittedItemPublication(t *testing.T) {
	f := newStrictFixture(t)
	gate := mustNamespaceSourceGate(t, f.raw.nodesByID[fuse.FUSE_ROOT_ID].node.item, "unknown", false)
	coordinate := publicationCoordinate{kind: publicationItemAttributes, item: testPublicationIdentity(t, testItem(999, authoritypb.Attr_REGULAR, 999))}
	f.raw.mu.Lock()
	f.raw.admitSourcePublicationLocked(coordinate)
	f.raw.mu.Unlock()

	acquired := make(chan *sourcePublicationLease, 1)
	errs := make(chan error, 1)
	go func() {
		lease, err := f.raw.acquireSourcePublication(context.Background(), gate)
		if err != nil {
			errs <- err
			return
		}
		acquired <- lease
	}()
	waitSourceState(t, f.raw, "unresolved namespace wildcard to close before draining the unknown item", func(raw *rawFileSystem) bool {
		return len(raw.sourceUnresolvedAttributes) == 1
	})
	select {
	case lease := <-acquired:
		lease.revoke()
		t.Fatal("namespace gate passed an already-admitted potentially bound item publication")
	case err := <-errs:
		t.Fatalf("namespace acquisition failed: %v", err)
	default:
	}
	f.raw.mu.Lock()
	f.raw.settleSourcePublicationLocked(coordinate)
	f.raw.mu.Unlock()
	var lease *sourcePublicationLease
	select {
	case lease = <-acquired:
	case err := <-errs:
		t.Fatal(err)
	case <-time.After(2 * time.Second):
		t.Fatal("namespace gate did not finish after the admitted item publication settled")
	}
	lease.resolveAllNoBinding()
	if err := lease.markDefiniteNoChange(); err != nil {
		t.Fatal(err)
	}
	lease.release()
}

func mustSourceGate(t *testing.T, gate *authoritypb.SourcePublicationGate, err error) *authoritypb.SourcePublicationGate {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
	return gate
}

func mustItemSourceGate(t *testing.T, item *authoritypb.Item, data bool) *authoritypb.SourcePublicationGate {
	t.Helper()
	gate, err := itemSourceGate(item, data)
	return mustSourceGate(t, gate, err)
}

func mustNamespaceSourceGate(t *testing.T, parent *authoritypb.Item, name string, data bool, additional ...*authoritypb.Item) *authoritypb.SourcePublicationGate {
	t.Helper()
	gate, err := namespaceSourceGate(parent, name, data, additional...)
	return mustSourceGate(t, gate, err)
}

func mustRenameSourceGate(t *testing.T, oldParent *authoritypb.Item, oldName string, newParent *authoritypb.Item, newName string) *authoritypb.SourcePublicationGate {
	t.Helper()
	gate, err := renameSourceGate(oldParent, oldName, newParent, newName)
	return mustSourceGate(t, gate, err)
}

func TestEveryLinuxVisibleOperationDeclaresItsExactSourceFootprint(t *testing.T) {
	type operationCase struct {
		name   string
		invoke func(context.Context, *node, *node, *node) syscall.Errno
		want   func(t *testing.T, parent, otherParent, source *node) *authoritypb.SourcePublicationGate
	}
	tests := []operationCase{
		{
			name: "setattr attributes",
			invoke: func(ctx context.Context, _, _, source *node) syscall.Errno {
				in := &fuse.SetAttrIn{}
				in.Valid, in.Mode = fuse.FATTR_MODE, 0o640
				return source.Setattr(ctx, nil, in, &fuse.AttrOut{})
			},
			want: func(t *testing.T, _, _ *node, source *node) *authoritypb.SourcePublicationGate {
				return mustItemSourceGate(t, source.item, false)
			},
		},
		{
			name: "setattr size",
			invoke: func(ctx context.Context, _, _, source *node) syscall.Errno {
				in := &fuse.SetAttrIn{}
				in.Valid, in.Size = fuse.FATTR_SIZE, 9
				return source.Setattr(ctx, nil, in, &fuse.AttrOut{})
			},
			want: func(t *testing.T, _, _ *node, source *node) *authoritypb.SourcePublicationGate {
				return mustItemSourceGate(t, source.item, true)
			},
		},
		{
			name: "open truncate",
			invoke: func(ctx context.Context, _, _, source *node) syscall.Errno {
				_, _, errno := source.Open(ctx, syscall.O_WRONLY|syscall.O_TRUNC)
				return errno
			},
			want: func(t *testing.T, _, _ *node, source *node) *authoritypb.SourcePublicationGate {
				return mustItemSourceGate(t, source.item, true)
			},
		},
		{
			name: "create",
			invoke: func(ctx context.Context, parent, _, _ *node) syscall.Errno {
				_, _, _, errno := parent.Create(ctx, "new", syscall.O_RDWR, 0o640)
				return errno
			},
			want: func(t *testing.T, parent, _, _ *node) *authoritypb.SourcePublicationGate {
				return mustNamespaceSourceGate(t, parent.item, "new", false)
			},
		},
		{
			name: "create truncate",
			invoke: func(ctx context.Context, parent, _, _ *node) syscall.Errno {
				_, _, _, errno := parent.Create(ctx, "new", syscall.O_RDWR|syscall.O_TRUNC, 0o640)
				return errno
			},
			want: func(t *testing.T, parent, _, _ *node) *authoritypb.SourcePublicationGate {
				return mustNamespaceSourceGate(t, parent.item, "new", true)
			},
		},
		{
			name: "mknod",
			invoke: func(ctx context.Context, parent, _, _ *node) syscall.Errno {
				_, errno := parent.Mknod(ctx, "new", syscall.S_IFREG|0o640, 0)
				return errno
			},
			want: func(t *testing.T, parent, _, _ *node) *authoritypb.SourcePublicationGate {
				return mustNamespaceSourceGate(t, parent.item, "new", false)
			},
		},
		{
			name: "mkdir",
			invoke: func(ctx context.Context, parent, _, _ *node) syscall.Errno {
				_, errno := parent.Mkdir(ctx, "new", 0o750)
				return errno
			},
			want: func(t *testing.T, parent, _, _ *node) *authoritypb.SourcePublicationGate {
				return mustNamespaceSourceGate(t, parent.item, "new", false)
			},
		},
		{
			name:   "unlink",
			invoke: func(ctx context.Context, parent, _, _ *node) syscall.Errno { return parent.Unlink(ctx, "old") },
			want: func(t *testing.T, parent, _, _ *node) *authoritypb.SourcePublicationGate {
				return mustNamespaceSourceGate(t, parent.item, "old", false)
			},
		},
		{
			name:   "rmdir",
			invoke: func(ctx context.Context, parent, _, _ *node) syscall.Errno { return parent.Rmdir(ctx, "old") },
			want: func(t *testing.T, parent, _, _ *node) *authoritypb.SourcePublicationGate {
				return mustNamespaceSourceGate(t, parent.item, "old", false)
			},
		},
		{
			name: "rename",
			invoke: func(ctx context.Context, parent, otherParent, _ *node) syscall.Errno {
				_, errno := parent.Rename(ctx, "old", otherParent, "new", 0)
				return errno
			},
			want: func(t *testing.T, parent, otherParent, _ *node) *authoritypb.SourcePublicationGate {
				return mustRenameSourceGate(t, parent.item, "old", otherParent.item, "new")
			},
		},
		{
			name: "link",
			invoke: func(ctx context.Context, parent, _ *node, source *node) syscall.Errno {
				_, errno := parent.Link(ctx, source, "new")
				return errno
			},
			want: func(t *testing.T, parent, _ *node, source *node) *authoritypb.SourcePublicationGate {
				return mustNamespaceSourceGate(t, parent.item, "new", false, source.item)
			},
		},
		{
			name: "symlink",
			invoke: func(ctx context.Context, parent, _, _ *node) syscall.Errno {
				_, errno := parent.Symlink(ctx, "target", "new")
				return errno
			},
			want: func(t *testing.T, parent, _, _ *node) *authoritypb.SourcePublicationGate {
				return mustNamespaceSourceGate(t, parent.item, "new", false)
			},
		},
		{
			name: "remove xattr",
			invoke: func(ctx context.Context, _, _ *node, source *node) syscall.Errno {
				return source.Removexattr(ctx, "user.test")
			},
			want: func(t *testing.T, _, _ *node, source *node) *authoritypb.SourcePublicationGate {
				return mustItemSourceGate(t, source.item, false)
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mount, rpc := testMount(t, 8)
			newNode := func(item *authoritypb.Item) *node {
				return &node{mount: mount, item: item, requestTimeout: time.Second, maxRead: 64 * 1024, maxWrite: 64 * 1024}
			}
			parent := newNode(testItem(1, authoritypb.Attr_DIRECTORY, 1))
			otherParent := newNode(testItem(2, authoritypb.Attr_DIRECTORY, 2))
			source := newNode(testItem(7, authoritypb.Attr_REGULAR, 7))
			var gates []*authoritypb.SourcePublicationGate
			rpc.hook = func(request *authoritypb.Request) {
				if gate := request.GetSourcePublicationGate(); gate != nil {
					gates = append(gates, proto.Clone(gate).(*authoritypb.SourcePublicationGate))
				}
			}
			ctx, finish := testMutationContext(t, mount)
			errno := test.invoke(ctx, parent, otherParent, source)
			finish(errno == 0)
			if len(gates) != 1 {
				t.Fatalf("visible operation emitted %d source gates, want exactly one", len(gates))
			}
			want := test.want(t, parent, otherParent, source)
			if !proto.Equal(gates[0], want) {
				t.Fatalf("source footprint = %v, want %v", gates[0], want)
			}
		})
	}
}

func TestOpenTruncateIsOneAtomicGatedMutation(t *testing.T) {
	f := newStrictFixture(t)
	f.rpc.byName = map[string]*authoritypb.Item{"file": testItem(71, authoritypb.Attr_REGULAR, 71)}
	entry := f.lookup(t, fuse.FUSE_ROOT_ID, "file")
	var opens, setattrs int
	var gotGate *authoritypb.SourcePublicationGate
	f.rpc.hook = func(request *authoritypb.Request) {
		switch {
		case request.GetOpen() != nil:
			opens++
			gotGate = proto.Clone(request.GetSourcePublicationGate()).(*authoritypb.SourcePublicationGate)
		case request.GetSetAttr() != nil:
			setattrs++
		}
	}
	status := f.rawCall(func(unique uint64) fuse.Status {
		return f.raw.Open(nil, &fuse.OpenIn{
			InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId},
			Flags:    syscall.O_WRONLY | syscall.O_TRUNC,
		}, &fuse.OpenOut{})
	})
	if !status.Ok() {
		t.Fatalf("atomic open-truncate = %v", status)
	}
	if opens != 1 || setattrs != 0 {
		t.Fatalf("open(O_TRUNC) authority mutations: OPEN=%d SETATTR=%d, want exactly 1/0", opens, setattrs)
	}
	want := mustItemSourceGate(t, f.rpc.byName["file"], true)
	if !proto.Equal(gotGate, want) {
		t.Fatalf("open-truncate source gate = %v, want exact attrs+data item %v", gotGate, want)
	}
}

func TestOnlySharedOpenTruncateRequiresPostVFSPublication(t *testing.T) {
	f := newStrictFixture(t)
	f.rpc.byName = map[string]*authoritypb.Item{"file": testItem(72, authoritypb.Attr_REGULAR, 72)}
	entry := f.lookup(t, fuse.FUSE_ROOT_ID, "file")

	ordinaryUnique := f.unique.Add(2)
	ordinary := &fuse.OpenOut{}
	if status := f.raw.Open(nil, &fuse.OpenIn{
		InHeader: fuse.InHeader{Unique: ordinaryUnique, NodeId: entry.NodeId},
		Flags:    syscall.O_RDONLY,
	}, ordinary); !status.Ok() {
		t.Fatalf("ordinary OPEN = %v", status)
	}
	// An ordinary OPEN now publishes one thing -- that this kernel may retain
	// the inode's pages -- so its reply is write-ordered against reverse
	// notifications. It still takes no post-VFS receipt: the kernel forbids
	// marking an unmarked OPEN, and there is nothing to mark, because the
	// declaration installs no state a repair could miss. Every folio it permits
	// is separately ordered against the barrier by mapping->invalidate_lock.
	if ordinary.OpenFlags != coherentOpenFlags || !f.raw.ReplyWriteOrdered(ordinaryUnique) ||
		f.raw.ReplyPublishMarked(ordinaryUnique, entry.NodeId, 14) {
		t.Fatal("ordinary OPEN must be write-ordered for its retained-data declaration and must not be post-VFS marked")
	}
	completeTestReply(t, f.raw, ordinaryUnique, fuse.OK)
	if !f.raw.cachedDataHolds(entry.Attr.Ino) {
		t.Fatal("a published retained-data declaration must leave a withdrawal obligation behind")
	}

	directoryUnique := f.unique.Add(2)
	directory := &fuse.OpenOut{}
	if status := f.raw.OpenDir(nil, &fuse.OpenIn{
		InHeader: fuse.InHeader{Unique: directoryUnique, NodeId: fuse.FUSE_ROOT_ID},
	}, directory); !status.Ok() {
		t.Fatalf("OPENDIR = %v", status)
	}
	if directory.OpenFlags != fuse.FOPEN_PFS_SHARED || f.raw.ReplyWriteOrdered(directoryUnique) ||
		f.raw.ReplyPublishMarked(directoryUnique, fuse.FUSE_ROOT_ID, 27) {
		t.Fatal("classification-only OPENDIR entered post-VFS publication")
	}

	truncateUnique := f.unique.Add(2)
	truncated := &fuse.OpenOut{}
	if status := f.raw.Open(nil, &fuse.OpenIn{
		InHeader: fuse.InHeader{Unique: truncateUnique, NodeId: entry.NodeId},
		Flags:    syscall.O_WRONLY | syscall.O_TRUNC,
	}, truncated); !status.Ok() {
		t.Fatalf("OPEN(O_TRUNC) = %v", status)
	}
	if !f.raw.ReplyWriteOrdered(truncateUnique) {
		t.Fatal("shared OPEN(O_TRUNC) did not retain post-VFS publication ownership")
	}
	finishPrivatePublication(t, f, truncateUnique, entry.NodeId, 14)

	f.raw.Release(nil, &fuse.ReleaseIn{InHeader: fuse.InHeader{Unique: f.unique.Add(2), NodeId: entry.NodeId}, Fh: ordinary.Fh})
	f.raw.Release(nil, &fuse.ReleaseIn{InHeader: fuse.InHeader{Unique: f.unique.Add(2), NodeId: entry.NodeId}, Fh: truncated.Fh})
	f.raw.ReleaseDir(&fuse.ReleaseIn{InHeader: fuse.InHeader{Unique: f.unique.Add(2), NodeId: fuse.FUSE_ROOT_ID}, Fh: directory.Fh})
	if f.mount.isRevoked() {
		t.Fatalf("valid OPEN publication matrix revoked mount: %v", f.mount.fatalError())
	}
}

func TestTruncatePublicationOrdersPriorAndLaterExactSizePhases(t *testing.T) {
	tests := []struct {
		name string
		run  func(*strictFixture, uint64, uint64) fuse.Status
	}{
		{
			name: "open O_TRUNC",
			run: func(f *strictFixture, unique, nodeID uint64) fuse.Status {
				return f.raw.Open(nil, &fuse.OpenIn{
					InHeader: fuse.InHeader{Unique: unique, NodeId: nodeID},
					Flags:    syscall.O_WRONLY | syscall.O_TRUNC,
				}, &fuse.OpenOut{})
			},
		},
		{
			name: "SETATTR size",
			run: func(f *strictFixture, unique, nodeID uint64) fuse.Status {
				return f.raw.SetAttr(nil, &fuse.SetAttrIn{SetAttrInCommon: fuse.SetAttrInCommon{
					InHeader: fuse.InHeader{Unique: unique, NodeId: nodeID},
					Valid:    fuse.FATTR_SIZE,
					Size:     0,
				}}, &fuse.AttrOut{})
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newStrictFixture(t)
			f.rpc.byName = map[string]*authoritypb.Item{"file": testItem(73, authoritypb.Attr_REGULAR, 73)}
			entry := f.lookup(t, fuse.FUSE_ROOT_ID, "file")
			targets := []*authoritypb.VisibilityTarget{
				inodeVisibilityTarget(authoritypb.VisibilityScope_VISIBILITY_SCOPE_DATA, 73, 5),
			}

			// A source cannot be granted while an older peer COMPLETE still has
			// an exact-size notification physically outstanding. Item-only
			// mutations wait behind that older inode repair: surfacing a synthetic
			// EINTR would make ordinary concurrent writes/truncates fail even
			// though no application signal interrupted them.
			if err := f.raw.prepareVisibility(context.Background(), targets, false); err != nil {
				t.Fatal(err)
			}
			completion, blocked, err := f.raw.beginVisibilityCompleteAt(targets, false, 41)
			if err != nil || blocked {
				t.Fatalf("begin prior COMPLETE = (blocked=%t, err=%v)", blocked, err)
			}
			sizeReached := make(chan struct{})
			var sizeOnce sync.Once
			f.notify.mu.Lock()
			f.notify.block = make(chan struct{})
			f.notify.onSize = func() { sizeOnce.Do(func() { close(sizeReached) }) }
			notifyBlock := f.notify.block
			f.notify.mu.Unlock()
			completeDone := make(chan error, 1)
			go func() { completeDone <- f.raw.finishVisibilityComplete(context.Background(), completion) }()
			select {
			case <-sizeReached:
			case <-time.After(2 * time.Second):
				t.Fatal("prior exact-size notification never reached its physical write")
			}
			f.rpc.mu.Lock()
			beforeCalls, beforeAssignments := f.rpc.calls, f.rpc.assignments
			f.rpc.mu.Unlock()
			sourceUnique := f.unique.Add(2)
			sourceStarted := make(chan struct{})
			sourceDone := make(chan fuse.Status, 1)
			go func() {
				close(sourceStarted)
				sourceDone <- test.run(f, sourceUnique, entry.NodeId)
			}()
			<-sourceStarted
			select {
			case status := <-sourceDone:
				t.Fatalf("item-only source overtook prior exact-size repair: %v", status)
			case <-time.After(50 * time.Millisecond):
			}
			f.rpc.mu.Lock()
			afterCalls, afterAssignments := f.rpc.calls, f.rpc.assignments
			f.rpc.mu.Unlock()
			if afterCalls != beforeCalls || afterAssignments != beforeAssignments {
				t.Fatalf("waiting item-only source crossed dispatch: calls %d->%d assignments %d->%d", beforeCalls, afterCalls, beforeAssignments, afterAssignments)
			}

			close(notifyBlock)
			if err := awaitPrepareResult(t, completeDone, "prior exact-size COMPLETE"); err != nil {
				t.Fatal(err)
			}
			f.notify.mu.Lock()
			f.notify.block, f.notify.onSize = nil, nil
			f.notify.mu.Unlock()

			// Once the old COMPLETE is acknowledged, the waiting source mutation
			// wins the FIFO cut. A later peer PREPARE must then remain behind it
			// through the original response write and true post-VFS PUBLISH ACK.
			select {
			case status := <-sourceDone:
				if !status.Ok() {
					t.Fatalf("waiting source after prior COMPLETE = %v", status)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("waiting source did not resume after prior COMPLETE")
			}
			if !f.raw.ReplyWriteOrdered(sourceUnique) {
				t.Fatal("successful truncate did not retain source publication ownership")
			}
			laterDone := make(chan error, 1)
			go func() { laterDone <- f.raw.prepareVisibility(context.Background(), targets, false) }()
			waitSourceState(t, f.raw, "later peer PREPARE behind truncate publication", func(raw *rawFileSystem) bool {
				return len(raw.peerHeldPhase) != 0
			})
			assertNoPrepareResult(t, laterDone, "later PREPARE before truncate response write")
			markTestReply(t, f.raw, sourceUnique)
			f.raw.ReplyWritten(sourceUnique, fuse.OK)
			assertNoPrepareResult(t, laterDone, "later PREPARE after truncate response write but before PUBLISH")
			acknowledgeTestPublication(t, f.raw, sourceUnique)
			if err := awaitPrepareResult(t, laterDone, "later PREPARE after truncate PUBLISH"); err != nil {
				t.Fatal(err)
			}
			finishPeerVisibility(t, f.raw, targets)
		})
	}
}

func TestNonVisibleAndLocallyRefusedOperationsDoNotDeclareSourceFootprints(t *testing.T) {
	mount, rpc := testMount(t, 8)
	source := testNode(mount)
	var gates int
	rpc.hook = func(request *authoritypb.Request) {
		if request.GetSourcePublicationGate() != nil {
			gates++
		}
	}
	_, _, _ = source.Open(context.Background(), syscall.O_RDONLY)
	_ = source.Getattr(context.Background(), nil, &fuse.AttrOut{})
	if errno := source.Setxattr(context.Background(), "user.test", []byte("value"), 0); errno != syscall.EOPNOTSUPP {
		t.Fatalf("readonly setxattr = %v, want EOPNOTSUPP", errno)
	}
	if gates != 0 {
		t.Fatalf("non-visible/refused operations emitted %d source gates", gates)
	}
}

func TestMutationGateGrammarFailsBeforeReplayAssignmentOrTransport(t *testing.T) {
	mount, rpc := testMount(t, 8)
	visibleWithoutGate := &authoritypb.Request{Body: &authoritypb.Request_WriteTransaction{WriteTransaction: &authoritypb.WriteTransactionRequest{
		TransactionId: 1, Handle: testToken(1), RequestedSize: 1, FragmentOffset: 1,
		RlimitFsize: 1, FileMaxSize: 1, Phase: authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_COMMIT,
	}}}
	if _, err := mount.callMutation(context.Background(), visibleWithoutGate); err == nil {
		t.Fatal("visible mutation without a source-publication gate was accepted")
	}
	nonVisibleWithGate := &authoritypb.Request{
		SourcePublicationGate: mustItemSourceGate(t, testItem(7, authoritypb.Attr_REGULAR, 7), false),
		Body:                  &authoritypb.Request_GetAttr{GetAttr: &authoritypb.GetAttrRequest{Item: testToken(7)}},
	}
	if _, err := mount.callMutation(context.Background(), nonVisibleWithGate); err == nil {
		t.Fatal("non-visible request carrying a source-publication gate was accepted")
	}
	rpc.snapshot(func(f *fakeRPC) {
		if f.calls != 0 || f.assignments != 0 || f.mutationSeq != 0 {
			t.Fatalf("gate grammar mismatch crossed the pre-dispatch boundary: calls=%d assignments=%d sequence=%d", f.calls, f.assignments, f.mutationSeq)
		}
	})
}

func TestPeerFirstNamespaceGateWaitsWithoutApplicationEINTR(t *testing.T) {
	f := newStrictFixture(t)
	targets := []*authoritypb.VisibilityTarget{namespaceVisibilityTarget(1, "blocked")}
	if err := f.raw.prepareVisibility(context.Background(), targets, false); err != nil {
		t.Fatal(err)
	}
	f.rpc.mu.Lock()
	beforeCalls, beforeAssignments := f.rpc.calls, f.rpc.assignments
	f.rpc.mu.Unlock()

	const unique = uint64(398)
	done := make(chan fuse.Status, 1)
	go func() {
		done <- f.raw.Mkdir(nil, &fuse.MkdirIn{
			InHeader: fuse.InHeader{Unique: unique, NodeId: fuse.FUSE_ROOT_ID},
			Mode:     0o755,
		}, "blocked", &fuse.EntryOut{})
	}()
	select {
	case status := <-done:
		t.Fatalf("peer-first mkdir escaped before the older repair: %v", status)
	case <-time.After(50 * time.Millisecond):
	}
	f.rpc.mu.Lock()
	afterCalls, afterAssignments := f.rpc.calls, f.rpc.assignments
	f.rpc.mu.Unlock()
	if afterCalls != beforeCalls || afterAssignments != beforeAssignments {
		t.Fatalf("waiting namespace gate crossed dispatch: calls %d->%d assignments %d->%d", beforeCalls, afterCalls, beforeAssignments, afterAssignments)
	}
	finishPeerVisibility(t, f.raw, targets)
	select {
	case status := <-done:
		if !status.Ok() {
			t.Fatalf("namespace mutation after repair = %v, want success", status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("namespace mutation did not resume after the peer repair")
	}
	markTestReply(t, f.raw, unique)
	f.raw.ReplyWritten(unique, fuse.OK)
	acknowledgeTestPublication(t, f.raw, unique)
}

func TestNamespaceMutationConsumesSequencedInternalRetry(t *testing.T) {
	f := newStrictFixture(t)
	item := testItem(398, authoritypb.Attr_DIRECTORY, 398)
	firstReturned := make(chan struct{})
	var attempts int
	f.rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
		if request.GetMkdir() == nil {
			return nil, errors.New("unexpected request in namespace visibility-retry test")
		}
		attempts++
		if attempts == 1 {
			close(firstReturned)
			return &authoritypb.Response{
				Errno: int32(syscall.EINTR), Failure: authoritypb.FailureClass_FAILURE_CLASS_VISIBILITY_RETRY,
				VisibilityRetrySequence: 1,
			}, nil
		}
		if request.GetVisibilityRetryAfterSequence() != 1 {
			return nil, errors.New("retried namespace mutation omitted its exact visibility sequence")
		}
		return &authoritypb.Response{Body: &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: item}}}, nil
	}
	const unique = uint64(400)
	done := make(chan fuse.Status, 1)
	go func() {
		done <- f.raw.Mkdir(nil, &fuse.MkdirIn{
			InHeader: fuse.InHeader{Unique: unique, NodeId: fuse.FUSE_ROOT_ID}, Mode: 0o755,
		}, "retry-inside-callback", &fuse.EntryOut{})
	}()
	<-firstReturned
	select {
	case status := <-done:
		t.Fatalf("namespace retry escaped to the kernel before COMPLETE: %v", status)
	case <-time.After(50 * time.Millisecond):
	}
	f.raw.releaseComplete(visibilityCompletion{sequence: 1})
	select {
	case status := <-done:
		if !status.Ok() {
			t.Fatalf("namespace retry returned %v, want success without EINTR", status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("namespace retry did not resume after exact COMPLETE")
	}
	if attempts != 2 || f.mount.isRevoked() {
		t.Fatalf("namespace retry attempts=%d revoked=%t cause=%v", attempts, f.mount.isRevoked(), f.mount.fatalError())
	}
	markTestReply(t, f.raw, unique)
	f.raw.ReplyWritten(unique, fuse.OK)
	acknowledgeTestPublication(t, f.raw, unique)
}

func TestSourceFirstReturnedBindingAndReplyWritePrecedePeerPrepare(t *testing.T) {
	f := newStrictFixture(t)
	child := testItem(44, authoritypb.Attr_DIRECTORY, 44)
	f.rpc.byName = map[string]*authoritypb.Item{"child": child}
	responseReached := make(chan struct{})
	releaseResponse := make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(releaseResponse) }) }
	defer release()
	f.rpc.afterMutation = func() {
		close(responseReached)
		<-releaseResponse
	}

	const unique = 400
	rawDone := make(chan fuse.Status, 1)
	go func() {
		rawDone <- f.raw.Mkdir(nil, &fuse.MkdirIn{
			InHeader: fuse.InHeader{Unique: unique, NodeId: fuse.FUSE_ROOT_ID},
			Mode:     0o755,
		}, "child", &fuse.EntryOut{})
	}()
	select {
	case <-responseReached:
	case <-time.After(2 * time.Second):
		t.Fatal("mkdir never reached its definitive authority response")
	}

	// The authority already knows the returned item, while this frontend still
	// owns an unresolved namespace wildcard. A peer item PREPARE closes first
	// and waits; it must not make attaching that definitive identity illegal.
	targets := []*authoritypb.VisibilityTarget{
		inodeVisibilityTarget(authoritypb.VisibilityScope_VISIBILITY_SCOPE_ATTRIBUTES, 44, 0),
	}
	prepareCtx, cancelPrepare := context.WithCancel(context.Background())
	defer cancelPrepare()
	prepareDone := make(chan error, 1)
	go func() { prepareDone <- f.raw.prepareVisibility(prepareCtx, targets, false) }()
	waitSourceState(t, f.raw, "the peer item cut to close behind the unresolved namespace owner", func(raw *rawFileSystem) bool {
		return len(raw.peerHeldPhase) != 0
	})
	assertNoPrepareResult(t, prepareDone, "peer PREPARE behind unresolved source binding")

	release()
	select {
	case status := <-rawDone:
		if !status.Ok() {
			t.Fatalf("mkdir raw result = %v", status)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("mkdir did not attach its returned identity while the peer waited")
	}
	if f.mount.isRevoked() {
		t.Fatalf("attaching under a waiting peer terminalized the mount: %v", f.mount.fatalError())
	}
	if !f.raw.ReplyWriteOrdered(unique) {
		t.Fatal("source mutation reply did not retain publication ownership after RawFS returned")
	}
	assertNoPrepareResult(t, prepareDone, "peer PREPARE before physical source reply write")

	markTestReply(t, f.raw, unique)
	f.raw.ReplyWritten(unique, fuse.OK)
	assertNoPrepareResult(t, prepareDone, "peer PREPARE after source reply write but before post-VFS publication ACK")
	acknowledgeTestPublication(t, f.raw, unique)
	if err := awaitPrepareResult(t, prepareDone, "peer PREPARE after post-VFS publication ACK"); err != nil {
		t.Fatal(err)
	}
	finishPeerVisibility(t, f.raw, targets)
	if calls := f.notify.snapshot(); len(calls) != 1 || calls[0].kind != "inode" {
		t.Fatalf("peer repair after source publication = %+v, want one inode notification", calls)
	}
}

func TestRenameUsesAuthoritativePostBindingWithoutCachedOldName(t *testing.T) {
	f := newStrictFixture(t)
	f.rpc.renameNewPost = testIdentity(77)
	const unique = 404
	status := f.raw.Rename(nil, &fuse.RenameIn{
		InHeader: fuse.InHeader{Unique: unique, NodeId: fuse.FUSE_ROOT_ID},
		Newdir:   fuse.FUSE_ROOT_ID,
	}, "never-cached-old", "new")
	if !status.Ok() {
		t.Fatalf("rename without a locally cached old binding = %v", status)
	}
	if !f.raw.ReplyWriteOrdered(unique) {
		t.Fatal("rename reply did not retain its authoritative post identity through physical publication")
	}
	f.raw.mu.Lock()
	oldCached := f.raw.cachedStableNames[publicationNamespace{parent: testPublicationIdentity(t, f.rpc.root), name: "never-cached-old"}]
	f.raw.mu.Unlock()
	if oldCached != nil {
		t.Fatal("test precondition failed: old rename name unexpectedly entered the local cache")
	}
	targets := []*authoritypb.VisibilityTarget{
		inodeVisibilityTarget(authoritypb.VisibilityScope_VISIBILITY_SCOPE_ATTRIBUTES, 77, 0),
	}
	prepareDone := make(chan error, 1)
	go func() { prepareDone <- f.raw.prepareVisibility(context.Background(), targets, false) }()
	waitSourceState(t, f.raw, "peer item cut behind authoritative rename result", func(raw *rawFileSystem) bool {
		return len(raw.peerHeldPhase) != 0
	})
	assertNoPrepareResult(t, prepareDone, "peer PREPARE before physical rename reply")
	markTestReply(t, f.raw, unique)
	f.raw.ReplyWritten(unique, fuse.OK)
	assertNoPrepareResult(t, prepareDone, "peer PREPARE after physical rename reply but before post-VFS publication ACK")
	acknowledgeTestPublication(t, f.raw, unique)
	if err := awaitPrepareResult(t, prepareDone, "peer PREPARE after rename publication ACK"); err != nil {
		t.Fatal(err)
	}
	finishPeerVisibility(t, f.raw, targets)
}

func TestNormalSameInodeRenameKeepsBothCachedBindings(t *testing.T) {
	f := newStrictFixture(t)
	before := f.lookup(t, fuse.FUSE_ROOT_ID, "before")
	after := f.lookup(t, fuse.FUSE_ROOT_ID, "after")
	if before.NodeId != after.NodeId {
		t.Fatalf("test hard-link aliases resolved to node IDs %d and %d", before.NodeId, after.NodeId)
	}
	f.rpc.renameNewPost = cloneBytes(f.rpc.item.GetStableIdentity())
	f.rpc.renameOldPost = cloneBytes(f.rpc.item.GetStableIdentity())
	if status := f.rename(fuse.FUSE_ROOT_ID, fuse.FUSE_ROOT_ID, "before", "after", 0); !status.Ok() {
		t.Fatalf("same-inode normal rename = %v", status)
	}
	f.raw.mu.Lock()
	_, beforeStillCached := f.raw.cachedNames[nameKey{parent: 1, name: "before"}]
	_, afterStillCached := f.raw.cachedNames[nameKey{parent: 1, name: "after"}]
	f.raw.mu.Unlock()
	if !beforeStillCached || !afterStillCached {
		t.Fatalf("same-inode rename cached bindings before=%t after=%t, want both retained", beforeStillCached, afterStillCached)
	}
	if f.mount.isRevoked() {
		t.Fatalf("same-inode rename terminalized source publication: %v", f.mount.fatalError())
	}
}

func TestFailedSourceReplyWriteRevokesAndNeverReopensTheGate(t *testing.T) {
	f := newStrictFixture(t)
	f.rpc.byName = map[string]*authoritypb.Item{"child": testItem(45, authoritypb.Attr_DIRECTORY, 45)}
	const unique = 402
	status := f.raw.Mkdir(nil, &fuse.MkdirIn{
		InHeader: fuse.InHeader{Unique: unique, NodeId: fuse.FUSE_ROOT_ID},
		Mode:     0o755,
	}, "child", &fuse.EntryOut{})
	if !status.Ok() || !f.raw.ReplyWriteOrdered(unique) {
		t.Fatalf("mkdir before failed write = (%v, ordered=%t)", status, f.raw.ReplyWriteOrdered(unique))
	}
	targets := []*authoritypb.VisibilityTarget{
		inodeVisibilityTarget(authoritypb.VisibilityScope_VISIBILITY_SCOPE_ATTRIBUTES, 45, 0),
	}
	prepareCtx, cancelPrepare := context.WithCancel(context.Background())
	prepareDone := make(chan error, 1)
	go func() { prepareDone <- f.raw.prepareVisibility(prepareCtx, targets, false) }()
	waitSourceState(t, f.raw, "the peer cut behind the source reply", func(raw *rawFileSystem) bool {
		return len(raw.peerHeldPhase) != 0
	})
	assertNoPrepareResult(t, prepareDone, "peer PREPARE before failed source reply")

	// Keep this unit test's terminal transition synchronous; production teardown
	// is independently covered by mount lifecycle tests.
	f.mount.abort.Do(func() {})
	markTestReply(t, f.raw, unique)
	f.raw.ReplyWritten(unique, fuse.EIO)
	if !f.mount.isRevoked() || f.mount.fatalError() == nil {
		t.Fatal("failed physical source reply did not terminalize the mount")
	}
	assertNoPrepareResult(t, prepareDone, "peer PREPARE after failed source reply")
	cancelPrepare()
	if err := awaitPrepareResult(t, prepareDone, "canceled peer PREPARE"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled PREPARE = %v, want context.Canceled", err)
	}
}

func TestStockWriteOnSharedHandleTerminalizesBeforeAuthorityDispatch(t *testing.T) {
	f := newStrictFixture(t)
	record := f.raw.nodesByID[fuse.FUSE_ROOT_ID]
	handleID, ok := f.raw.addHandle(record, &handleRecord{file: &fileHandle{node: record.node, token: testToken(619)}})
	if !ok {
		t.Fatal("install SHARED handle")
	}
	before := f.rpc.calls
	written, status := f.raw.Write(nil, &fuse.WriteIn{
		InHeader: fuse.InHeader{Unique: 618, NodeId: fuse.FUSE_ROOT_ID},
		Fh:       handleID, Offset: 7,
	}, []byte("x"))
	if written != 0 || status != fuse.Status(syscall.ENOTCONN) {
		t.Fatalf("stock FUSE_WRITE on SHARED = (%d, %v), want (0, ENOTCONN)", written, status)
	}
	if !f.mount.isRevoked() || f.rpc.calls != before {
		t.Fatalf("stock SHARED write revoked=%t authority calls=%d->%d", f.mount.isRevoked(), before, f.rpc.calls)
	}
}

func TestCachedLookupPublicationSettlesOnlyAfterPostVFSAck(t *testing.T) {
	f := newStrictFixture(t)
	f.rpc.byName = map[string]*authoritypb.Item{"cached": testItem(55, authoritypb.Attr_REGULAR, 55)}
	const unique = 500
	out := &fuse.EntryOut{}
	if status := f.raw.Lookup(nil, &fuse.InHeader{Unique: unique, NodeId: fuse.FUSE_ROOT_ID}, "cached", out); !status.Ok() {
		t.Fatalf("lookup = %v", status)
	}
	if !f.raw.ReplyWriteOrdered(unique) {
		t.Fatal("cacheable LOOKUP reply was not joined to the physical writer boundary")
	}
	f.raw.mu.Lock()
	_, committedBeforeWrite := f.raw.cachedNames[nameKey{parent: 1, name: "cached"}]
	pendingBeforeWrite := f.raw.pendingNames
	f.raw.mu.Unlock()
	if committedBeforeWrite || pendingBeforeWrite != 1 {
		t.Fatalf("pre-write registry committed=%t pending=%d, want false/1", committedBeforeWrite, pendingBeforeWrite)
	}

	targets := []*authoritypb.VisibilityTarget{namespaceVisibilityTarget(1, "cached")}
	prepareDone := make(chan error, 1)
	go func() { prepareDone <- f.raw.prepareVisibility(context.Background(), targets, false) }()
	waitSourceState(t, f.raw, "the peer namespace cut behind a cached LOOKUP reply", func(raw *rawFileSystem) bool {
		return len(raw.peerHeldPhase) != 0
	})
	assertNoPrepareResult(t, prepareDone, "peer PREPARE before cached LOOKUP reply write")

	markTestReply(t, f.raw, unique)
	f.raw.ReplyWritten(unique, fuse.OK)
	assertNoPrepareResult(t, prepareDone, "peer PREPARE after LOOKUP reply write but before post-VFS ACK")
	f.raw.mu.Lock()
	_, committedAfterWrite := f.raw.cachedNames[nameKey{parent: 1, name: "cached"}]
	f.raw.mu.Unlock()
	if committedAfterWrite {
		t.Fatal("physical LOOKUP reply committed its repair obligation before kernel postprocessing")
	}
	acknowledgeTestPublication(t, f.raw, unique)
	if err := awaitPrepareResult(t, prepareDone, "peer PREPARE after cached LOOKUP publication ACK"); err != nil {
		t.Fatal(err)
	}
	f.raw.mu.Lock()
	_, committedAfterAck := f.raw.cachedNames[nameKey{parent: 1, name: "cached"}]
	f.raw.mu.Unlock()
	if !committedAfterAck {
		t.Fatal("post-VFS LOOKUP ACK did not commit its exact repair obligation")
	}
	finishPeerVisibility(t, f.raw, targets)
	if calls := f.notify.snapshot(); len(calls) != 1 || calls[0].kind != "delete" || calls[0].name != "cached" {
		t.Fatalf("LOOKUP repair = %+v, want exact delete notification", calls)
	}
}

func TestCachedGetattrPublicationSettlesOnlyAfterPostVFSAck(t *testing.T) {
	f := newStrictFixture(t)
	entry := f.lookup(t, fuse.FUSE_ROOT_ID, "cached")
	const unique = 502
	if status := f.raw.GetAttr(nil, &fuse.GetAttrIn{
		InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId},
	}, &fuse.AttrOut{}); !status.Ok() {
		t.Fatalf("getattr = %v", status)
	}
	if !f.raw.ReplyWriteOrdered(unique) {
		t.Fatal("cacheable GETATTR reply was not joined to the physical writer boundary")
	}
	targets := []*authoritypb.VisibilityTarget{
		inodeVisibilityTarget(authoritypb.VisibilityScope_VISIBILITY_SCOPE_ATTRIBUTES, entry.Attr.Ino, 0),
	}
	prepareDone := make(chan error, 1)
	go func() { prepareDone <- f.raw.prepareVisibility(context.Background(), targets, false) }()
	waitSourceState(t, f.raw, "the peer item cut behind a cached GETATTR reply", func(raw *rawFileSystem) bool {
		return len(raw.peerHeldPhase) != 0
	})
	assertNoPrepareResult(t, prepareDone, "peer PREPARE before cached GETATTR reply write")

	markTestReply(t, f.raw, unique)
	f.raw.ReplyWritten(unique, fuse.OK)
	assertNoPrepareResult(t, prepareDone, "peer PREPARE after GETATTR reply write but before post-VFS ACK")
	acknowledgeTestPublication(t, f.raw, unique)
	if err := awaitPrepareResult(t, prepareDone, "peer PREPARE after cached GETATTR publication ACK"); err != nil {
		t.Fatal(err)
	}
	finishPeerVisibility(t, f.raw, targets)
	if calls := f.notify.snapshot(); len(calls) != 1 || calls[0].kind != "inode" {
		t.Fatalf("GETATTR repair = %+v, want one inode notification", calls)
	}
}

func TestTerminalReadResponseIsRetainedThroughPostVFSAck(t *testing.T) {
	f := newStrictFixture(t)
	entry := f.lookup(t, fuse.FUSE_ROOT_ID, "terminal-getattr")
	consumption := &recordingResponseConsumption{}
	f.rpc.retainedConsumption = consumption
	const unique = 504
	if status := f.raw.GetAttr(nil, &fuse.GetAttrIn{
		InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId},
	}, &fuse.AttrOut{}); !status.Ok() {
		t.Fatalf("getattr = %v", status)
	}
	if got := consumption.calls.Load(); got != 0 {
		t.Fatalf("authority response consumed at callback return: %d", got)
	}
	if !f.raw.ReplyWriteOrdered(unique) || !f.raw.ReplyPublishMarked(unique, testPublicationNodeID, testPublicationOpcode) {
		t.Fatal("terminal GETATTR did not retain its post-VFS publication boundary")
	}
	f.raw.ReplyWritten(unique, fuse.OK)
	if got := consumption.calls.Load(); got != 0 {
		t.Fatalf("authority response consumed at original reply write: %d", got)
	}
	acknowledgeTestPublication(t, f.raw, unique)
	if got := consumption.calls.Load(); got != 1 {
		t.Fatalf("authority response consumption after PFS_PUBLISH = %d, want 1", got)
	}
}

func TestTerminalReadResponseWithoutKernelStateWaitsForPhysicalReply(t *testing.T) {
	f := newStrictFixture(t)
	entry := f.lookup(t, fuse.FUSE_ROOT_ID, "terminal-xattr")
	consumption := &recordingResponseConsumption{}
	f.rpc.retainedConsumption = consumption
	f.rpc.xattrValue = []byte("value")
	const unique = 506
	if _, status := f.raw.GetXAttr(nil, &fuse.InHeader{Unique: unique, NodeId: entry.NodeId}, "user.test", nil); !status.Ok() {
		t.Fatalf("getxattr = %v", status)
	}
	if got := consumption.calls.Load(); got != 0 {
		t.Fatalf("authority response consumed at callback return: %d", got)
	}
	if !f.raw.ReplyWriteOrdered(unique) {
		t.Fatal("terminal GETXATTR did not join the physical reply boundary")
	}
	if f.raw.ReplyPublishMarked(unique, testPublicationNodeID, testPublicationOpcode) {
		t.Fatal("GETXATTR incorrectly requested a post-VFS publication")
	}
	f.raw.ReplyWritten(unique, fuse.OK)
	if got := consumption.calls.Load(); got != 1 {
		t.Fatalf("authority response consumption after physical reply = %d, want 1", got)
	}
}

func TestCachedReadReplyFailureSettlesWithoutNilSourceAndTerminalizes(t *testing.T) {
	for _, operation := range []string{"lookup", "getattr"} {
		t.Run(operation, func(t *testing.T) {
			f := newStrictFixture(t)
			var unique uint64 = 600
			switch operation {
			case "lookup":
				f.rpc.byName = map[string]*authoritypb.Item{"cached": testItem(66, authoritypb.Attr_REGULAR, 66)}
				if status := f.raw.Lookup(nil, &fuse.InHeader{Unique: unique, NodeId: fuse.FUSE_ROOT_ID}, "cached", &fuse.EntryOut{}); !status.Ok() {
					t.Fatalf("lookup = %v", status)
				}
			case "getattr":
				entry := f.lookup(t, fuse.FUSE_ROOT_ID, "cached")
				unique = 602
				if status := f.raw.GetAttr(nil, &fuse.GetAttrIn{InHeader: fuse.InHeader{Unique: unique, NodeId: entry.NodeId}}, &fuse.AttrOut{}); !status.Ok() {
					t.Fatalf("getattr = %v", status)
				}
			}
			if !f.raw.ReplyWriteOrdered(unique) {
				t.Fatalf("cacheable %s reply was not ordered", operation)
			}
			f.mount.abort.Do(func() {})
			markTestReply(t, f.raw, unique)
			f.raw.ReplyWritten(unique, fuse.EIO)
			if !f.mount.isRevoked() || f.mount.fatalError() == nil {
				t.Fatalf("failed %s reply write did not terminalize the mount", operation)
			}
			f.raw.mu.Lock()
			pending := f.raw.pendingNames
			publishingNames := len(f.raw.publishingNames)
			publishingInodes := len(f.raw.publishingInodes)
			registered := len(f.raw.replyPublications)
			cached := len(f.raw.cachedNames)
			f.raw.mu.Unlock()
			if pending != 0 || publishingNames != 0 || publishingInodes != 0 || registered != 0 {
				t.Fatalf("failed %s left publication state pending=%d names=%d inodes=%d registered=%d", operation, pending, publishingNames, publishingInodes, registered)
			}
			if operation == "lookup" && cached != 0 {
				t.Fatalf("failed LOOKUP write committed %d cached bindings", cached)
			}
		})
	}
}

func TestUnknownOrderedReplyIdentityTerminalizesWithoutPanic(t *testing.T) {
	f := newStrictFixture(t)
	f.mount.abort.Do(func() {})
	f.raw.ReplyWritten(9999, fuse.OK)
	if !f.mount.isRevoked() || f.mount.fatalError() == nil {
		t.Fatal("an unknown ordered reply identity did not fail closed")
	}
}

func TestReplyPublicationIdentityIsReservedBeforeAnyCallbackRPC(t *testing.T) {
	for _, test := range []struct {
		name    string
		unique  uint64
		reserve bool
	}{
		{name: "zero", unique: 0},
		{name: "reserved marker range", unique: fuse.PFS_UNIQUE_PUBLISH},
		{name: "above reserved marker range", unique: uint64(1) << 63},
		{name: "duplicate", unique: 800, reserve: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newStrictFixture(t)
			f.mount.abort.Do(func() {})
			var releaseReservation func()
			if test.reserve {
				_, finish, status := f.raw.mutationContext(test.unique)
				if !status.Ok() {
					t.Fatalf("initial reservation = %v", status)
				}
				releaseReservation = finish
				defer releaseReservation()
			}
			before := f.rpc.calls
			status := f.raw.Lookup(nil, &fuse.InHeader{Unique: test.unique, NodeId: fuse.FUSE_ROOT_ID}, "never-dispatched", &fuse.EntryOut{})
			if status != fuse.Status(syscall.ENOTCONN) {
				t.Fatalf("invalid reply identity callback = %v, want ENOTCONN", status)
			}
			if f.rpc.calls != before {
				t.Fatalf("invalid reply identity dispatched %d authority calls, want zero", f.rpc.calls-before)
			}
			if !f.mount.isRevoked() || f.mount.fatalError() == nil {
				t.Fatal("invalid reply-publication identity did not terminalize before dispatch")
			}
		})
	}
}

func TestMalformedAppliedMutationNeverCommitsItsSourcePublication(t *testing.T) {
	tests := []struct {
		name   string
		unique uint64
		run    func(*strictFixture, uint64) fuse.Status
	}{
		{
			name: "setattr missing post attributes", unique: 810,
			run: func(f *strictFixture, unique uint64) fuse.Status {
				f.rpc.replyOverride = func(request *authoritypb.Request) (*authoritypb.Response, error) {
					if request.GetSetAttr() != nil {
						return &authoritypb.Response{}, nil
					}
					return nil, errors.New("unexpected request in malformed setattr test")
				}
				in := &fuse.SetAttrIn{SetAttrInCommon: fuse.SetAttrInCommon{
					InHeader: fuse.InHeader{Unique: unique, NodeId: fuse.FUSE_ROOT_ID},
					Valid:    fuse.FATTR_MODE,
					Mode:     0o640,
				}}
				return f.raw.SetAttr(nil, in, &fuse.AttrOut{})
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f := newStrictFixture(t)
			f.mount.abort.Do(func() {})
			if status := test.run(f, test.unique); status != fuse.EIO {
				t.Fatalf("malformed applied callback = %v, want EIO", status)
			}
			if !f.mount.isRevoked() || f.mount.fatalError() == nil || !f.raw.ReplyWriteOrdered(test.unique) {
				t.Fatalf("malformed applied result revoked=%t fatal=%v ordered=%t", f.mount.isRevoked(), f.mount.fatalError(), f.raw.ReplyWriteOrdered(test.unique))
			}
			if f.raw.ReplyPublishMarked(test.unique, testPublicationNodeID, testPublicationOpcode) {
				t.Fatal("terminal malformed result was marked as a publishable kernel state")
			}
			f.raw.ReplyWritten(test.unique, fuse.OK)
			f.raw.mu.Lock()
			held := len(f.raw.sourceHolds) != 0
			f.raw.mu.Unlock()
			if !held {
				t.Fatal("physical EIO reply reopened a source gate whose authority success could not be represented")
			}
		})
	}
}

func TestAppliedTruncateOpenHandleAdmissionFailureNeverReopensGate(t *testing.T) {
	f := newStrictFixture(t)
	f.mount.abort.Do(func() {})
	f.raw.mu.Lock()
	f.raw.nextHandle = 0
	f.raw.mu.Unlock()
	const unique = 812
	status := f.raw.Open(nil, &fuse.OpenIn{
		InHeader: fuse.InHeader{Unique: unique, NodeId: fuse.FUSE_ROOT_ID},
		Flags:    syscall.O_WRONLY | syscall.O_TRUNC,
	}, &fuse.OpenOut{})
	if status != fuse.EIO {
		t.Fatalf("truncate open with exhausted local handle IDs = %v, want EIO", status)
	}
	if !f.mount.isRevoked() || !f.raw.ReplyWriteOrdered(unique) {
		t.Fatalf("applied truncate bookkeeping failure revoked=%t ordered=%t", f.mount.isRevoked(), f.raw.ReplyWriteOrdered(unique))
	}
	if f.raw.ReplyPublishMarked(unique, testPublicationNodeID, testPublicationOpcode) {
		t.Fatal("terminal post-apply bookkeeping failure was marked as a publishable kernel state")
	}
	f.raw.ReplyWritten(unique, fuse.OK)
	f.raw.mu.Lock()
	held := len(f.raw.sourceHolds) != 0
	f.raw.mu.Unlock()
	if !held {
		t.Fatal("error reply reopened the applied truncate source gate")
	}
}

type assignmentViolationRPC struct {
	*fakeRPC
	mode string
}

func (r *assignmentViolationRPC) CallMutationWithIdentity(_ context.Context, _ *authoritypb.Request, assigned authorityrpc.MutationAssigned) (*authoritypb.Response, error) {
	switch r.mode {
	case "duplicate":
		if err := assigned(authorityrpc.MutationIdentity{Slot: 0, Sequence: 1}); err != nil {
			return nil, err
		}
		if err := assigned(authorityrpc.MutationIdentity{Slot: 0, Sequence: 1}); err != nil {
			return nil, err
		}
		return nil, errors.New("duplicate assignment callback unexpectedly succeeded")
	case "missing":
		return &authoritypb.Response{Errno: int32(syscall.EEXIST)}, nil
	default:
		return nil, errors.New("unknown assignment violation mode")
	}
}

func (r *assignmentViolationRPC) CallMutationWithIdentityRetained(
	ctx context.Context,
	request *authoritypb.Request,
	assigned authorityrpc.MutationAssigned,
	_ func(error),
) (*authoritypb.Response, authorityrpc.ResponseConsumption, error) {
	response, err := r.CallMutationWithIdentity(ctx, request, assigned)
	return response, nil, err
}

func TestAssignmentLifecycleViolationIsTerminalAndNeverReopensGate(t *testing.T) {
	for _, mode := range []string{"duplicate", "missing"} {
		t.Run(mode, func(t *testing.T) {
			base := newFakeRPC()
			base.session = testSelfSession
			rpc := &assignmentViolationRPC{fakeRPC: base, mode: mode}
			mount := newMount(context.Background(), rpc, testStrictConfig(8))
			t.Cleanup(mount.cancel)
			mount.abort.Do(func() {})
			root := &node{mount: mount, item: testItem(1, authoritypb.Attr_DIRECTORY, 1), requestTimeout: time.Second, maxRead: 64 * 1024, maxWrite: 64 * 1024}
			raw := newRawFileSystem(mount, root)
			unique := uint64(820)
			status := raw.Mkdir(nil, &fuse.MkdirIn{InHeader: fuse.InHeader{Unique: unique, NodeId: fuse.FUSE_ROOT_ID}, Mode: 0o755}, "invalid-assignment", &fuse.EntryOut{})
			if status != fuse.EIO {
				t.Fatalf("assignment lifecycle violation = %v, want EIO", status)
			}
			if !mount.isRevoked() || mount.fatalError() == nil || !raw.ReplyWriteOrdered(unique) {
				t.Fatalf("assignment violation revoked=%t fatal=%v ordered=%t", mount.isRevoked(), mount.fatalError(), raw.ReplyWriteOrdered(unique))
			}
			if raw.ReplyPublishMarked(unique, testPublicationNodeID, testPublicationOpcode) {
				t.Fatal("assignment lifecycle failure was marked as a publishable kernel state")
			}
			raw.ReplyWritten(unique, fuse.OK)
			raw.mu.Lock()
			held := len(raw.sourceHolds) != 0 || len(raw.sourceUnresolvedAttributes) != 0
			raw.mu.Unlock()
			if !held {
				t.Fatal("assignment lifecycle violation reopened its source gate")
			}
		})
	}
}

type assignedUncertainRPC struct {
	*fakeRPC
	assigned chan struct{}
}

func (r *assignedUncertainRPC) CallMutationWithIdentity(_ context.Context, _ *authoritypb.Request, assigned authorityrpc.MutationAssigned) (*authoritypb.Response, error) {
	if err := assigned(authorityrpc.MutationIdentity{Slot: 0, Sequence: 1}); err != nil {
		return nil, err
	}
	close(r.assigned)
	return nil, authorityrpc.ErrTransportUncertain
}

func (r *assignedUncertainRPC) CallMutationWithIdentityRetained(
	ctx context.Context,
	request *authoritypb.Request,
	assigned authorityrpc.MutationAssigned,
	_ func(error),
) (*authoritypb.Response, authorityrpc.ResponseConsumption, error) {
	response, err := r.CallMutationWithIdentity(ctx, request, assigned)
	return response, nil, err
}

func TestAssignedUncertainMutationRevokesWithoutReopeningSourceGate(t *testing.T) {
	base := newFakeRPC()
	base.session = testSelfSession
	rpc := &assignedUncertainRPC{fakeRPC: base, assigned: make(chan struct{})}
	mount := newMount(context.Background(), rpc, testStrictConfig(8))
	t.Cleanup(mount.cancel)
	mount.abort.Do(func() {})
	root := &node{mount: mount, item: testItem(1, authoritypb.Attr_DIRECTORY, 1), requestTimeout: time.Second, maxRead: 64 * 1024, maxWrite: 64 * 1024}
	raw := newRawFileSystem(mount, root)

	const unique = 700
	status := raw.Mkdir(nil, &fuse.MkdirIn{
		InHeader: fuse.InHeader{Unique: unique, NodeId: fuse.FUSE_ROOT_ID},
		Mode:     0o755,
	}, "uncertain", &fuse.EntryOut{})
	if status != fuse.EIO {
		t.Fatalf("assigned uncertain mkdir = %v, want EIO", status)
	}
	select {
	case <-rpc.assigned:
	default:
		t.Fatal("mutation did not cross the assignment boundary")
	}
	if !mount.isRevoked() || mount.fatalError() == nil || !raw.ReplyWriteOrdered(unique) {
		t.Fatalf("uncertain mutation state revoked=%t fatal=%v ordered=%t", mount.isRevoked(), mount.fatalError(), raw.ReplyWriteOrdered(unique))
	}
	if raw.ReplyPublishMarked(unique, testPublicationNodeID, testPublicationOpcode) {
		t.Fatal("uncertain mutation was marked as a publishable kernel state")
	}
	raw.ReplyWritten(unique, fuse.OK)
	raw.mu.Lock()
	held := len(raw.sourceHolds) != 0 || len(raw.sourceUnresolvedAttributes) != 0
	raw.mu.Unlock()
	if !held {
		t.Fatal("successful delivery of an error reply reopened an uncertain assigned source gate")
	}
}
