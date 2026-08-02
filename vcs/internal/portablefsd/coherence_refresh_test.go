package portablefsd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/coherence"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

type blockingFrontendLstatFS struct {
	*workfs.FS
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (f *blockingFrontendLstatFS) Lstat(path string) (os.FileInfo, error) {
	f.once.Do(func() { close(f.entered) })
	<-f.release
	return f.FS.Lstat(path)
}

// beginTestLogicalOperation stands in for the dispatcher's whole path to
// publication membership, which is TWO steps (handleAttached): the request
// RESERVES its place in the logical operation suspended — holding nothing,
// waiting for nothing, so its own admission cannot deadlock against it — and
// then ACTIVATES into the publication set. A helper that only reserved would
// hand back a request that is not a member, and every "a handoff must not
// cross this" assertion below would pass vacuously.
func beginTestLogicalOperation(
	t *testing.T,
	conn *frontendConn,
	a *attach,
	operationID uint64,
	body any,
) (context.Context, *frontendOperationParticipant, bool, bool, error) {
	t.Helper()
	initialize, ok := conn.reserveLogicalOperation(operationID, true)
	if !ok {
		return context.Background(), nil, false, false,
			errors.New("reserve logical operation failed")
	}
	ctx, participant, participates, publishes, err := conn.beginLogicalOperation(
		context.Background(), a, operationID, initialize, body,
	)
	if err != nil || participant == nil {
		return ctx, participant, participates, publishes, err
	}
	if err := activateTestParticipant(ctx, a, participant); err != nil {
		return ctx, participant, participates, publishes, err
	}
	return ctx, participant, participates, publishes, nil
}

// activateTestParticipant is enterFrontendMirrors without the mirrors: the
// attempt/wait/retry loop the dispatcher runs, so a test request reaches
// membership by the same route production does.
func activateTestParticipant(
	ctx context.Context,
	a *attach,
	participant *frontendOperationParticipant,
) error {
	for {
		activated, err := a.tryActivateFrontendParticipant(participant)
		if err != nil {
			return err
		}
		if activated {
			return nil
		}
		if err := a.awaitFrontendActivation(ctx, participant); err != nil {
			return err
		}
	}
}

func exposeTestLogicalOperation(
	t *testing.T,
	conn *frontendConn,
	operationID uint64,
) {
	t.Helper()
	if !conn.markPublicationReplyExposed(operationID) {
		t.Fatalf("expose logical operation %d failed", operationID)
	}
}

func TestFSKitItemIDBoundary(t *testing.T) {
	if got, ok := fskitItemID(1); !ok || got != 2 {
		t.Fatalf("root mapping = (%d, %v), want (2, true)", got, ok)
	}
	if got, ok := fskitItemID(2); !ok || got != 3 {
		t.Fatalf("child mapping = (%d, %v), want (3, true)", got, ok)
	}
	if got, ok := fskitItemID(0); ok || got != 0 {
		t.Fatalf("invalid mapping = (%d, %v), want (0, false)", got, ok)
	}
	if got, ok := fskitItemID(^uint64(0)); ok || got != 0 {
		t.Fatalf("overflow mapping = (%d, %v), want (0, false)", got, ok)
	}
}

// TestConsumeExpectedTruncate pins the marked-truncate note protocol that
// keeps the daemon's kernel-size refreshes invisible to the authority: only
// a pure size-set matching the noted size consumes the note; mode/ownership
// changes never match; a size mismatch retires the note (the kernel is doing
// a REAL truncate that must reach the authority); expired notes never match;
// and every note is single-use.
func TestConsumeExpectedTruncate(t *testing.T) {
	size := func(v uint64) *uint64 { return &v }
	mode := uint32(0o600)

	a := &attach{}
	note := func(p string, itemID uint64, sz int64, ttl time.Duration) {
		a.mu.Lock()
		if a.expectedTruncates == nil {
			a.expectedTruncates = map[string]expectedTruncate{}
		}
		a.expectedTruncates[p] = expectedTruncate{
			itemID: itemID, size: sz, deadline: time.Now().Add(ttl),
		}
		a.mu.Unlock()
	}
	request := func(itemID uint64, sz uint64) *pfslocal.SetAttrRequest {
		return &pfslocal.SetAttrRequest{
			Item: pfslocal.Item{ItemID: itemID},
			Size: size(sz),
		}
	}

	// No note: never consumed.
	if consumedInternal(a, "f", request(7, 22)) {
		t.Fatal("consumed without a note")
	}
	// Matching size-only request consumes exactly once.
	note("f", 7, 22, time.Minute)
	if !consumedInternal(a, "f", request(7, 22)) {
		t.Fatal("matching refresh truncate not consumed")
	}
	if consumedInternal(a, "f", request(7, 22)) {
		t.Fatal("note consumed twice")
	}
	// A mode-bearing setattr is a real application request even if size matches.
	note("f", 7, 22, time.Minute)
	withMode := request(7, 22)
	withMode.Mode = &mode
	if consumedInternal(a, "f", withMode) {
		t.Fatal("application setattr with mode was suppressed")
	}
	// Size mismatch: a REAL truncate races the note; it must pass through AND
	// retire the note so it cannot suppress anything later.
	if consumedInternal(a, "f", request(7, 7)) {
		t.Fatal("mismatched truncate was suppressed")
	}
	if consumedInternal(a, "f", request(7, 22)) {
		t.Fatal("note survived a mismatched truncate")
	}
	// Expired notes never match.
	note("f", 7, 22, -time.Second)
	if consumedInternal(a, "f", request(7, 22)) {
		t.Fatal("expired note consumed")
	}
	// A rename between secure open and ftruncate changes the current path but
	// not the descriptor's FSItem identity. The moved marker must still be
	// consumed so the refresh cannot mutate the item's new authority path.
	note("old-name", 7, 22, time.Minute)
	if !consumedInternal(a, "new-name", request(7, 22)) {
		t.Fatal("renamed FSItem refresh note not consumed")
	}
}

func TestAppliedRefreshCannotLeaveConsumableTruncateMarker(t *testing.T) {
	a := &attach{
		items: map[uint64]*itemRecord{},
	}
	rec := &itemRecord{
		item: pfslocal.Item{ItemID: 4, ItemGeneration: 1},
		path: "same-size",
		attr: fsproto.Attr{Kind: "file", Size: 8},
	}
	a.items[rec.item.ItemID] = rec
	a.testRefreshKernelFile = func(string, string, uint64, int64, func() (func(), error)) (kernelRefreshOutcome, error) {
		// Models a vnode whose size already matches: no setattr callback
		// consumes the marker, but page invalidation succeeds.
		return kernelRefreshApplied, nil
	}
	if outcome, err := a.applyKernelRefresh("", rec.path, rec, 8, refreshApplyFence{observedSize: rec.attr.Size}); outcome != kernelRefreshApplied || err != nil {
		t.Fatalf("apply = (%v, %v)", outcome, err)
	}
	if consumedInternal(a, rec.path, &pfslocal.SetAttrRequest{
		Item: rec.item,
		Size: func() *uint64 { value := uint64(8); return &value }(),
	}) {
		t.Fatal("later application truncate consumed a retired refresh marker")
	}
}

func TestUnrepresentableRefreshCannotMutateTruncateOrAttributeState(t *testing.T) {
	rec := &itemRecord{
		item: pfslocal.Item{ItemID: ^uint64(0), ItemGeneration: 1},
		path: "invalid",
		attr: fsproto.Attr{Kind: "file", Size: 4},
	}
	originalNote := expectedTruncate{
		itemID:   7,
		size:     3,
		deadline: time.Now().Add(time.Minute),
	}
	a := &attach{
		items:             map[uint64]*itemRecord{rec.item.ItemID: rec},
		expectedTruncates: map[string]expectedTruncate{"sentinel": originalNote},
		testRefreshKernelFile: func(string, string, uint64, int64, func() (func(), error)) (kernelRefreshOutcome, error) {
			t.Fatal("kernel refresh ran for an unrepresentable item")
			return kernelRefreshApplied, nil
		},
	}
	if outcome, err := a.applyKernelRefresh("", rec.path, rec, 8, refreshApplyFence{observedSize: rec.attr.Size}); outcome != kernelRefreshRetry || err == nil {
		t.Fatalf("apply = (%v, %v), want retry with error", outcome, err)
	}
	if rec.attr.Size != 4 {
		t.Fatalf("cached size mutated to %d", rec.attr.Size)
	}
	if len(a.expectedTruncates) != 1 || a.expectedTruncates["sentinel"] != originalNote {
		t.Fatalf("truncate markers mutated: %+v", a.expectedTruncates)
	}
}

func TestExactRefreshSerializesOneItemTransaction(t *testing.T) {
	a := &attach{}
	firstEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	var calls atomic.Int32
	a.testExactKernelRefresh = func(context.Context, uint64) error {
		if calls.Add(1) == 1 {
			close(firstEntered)
			<-releaseFirst
		}
		return nil
	}
	firstDone := make(chan error, 1)
	secondDone := make(chan error, 1)
	go func() { firstDone <- a.exactKernelRefresh(context.Background(), 42) }()
	<-firstEntered
	go func() { secondDone <- a.exactKernelRefresh(context.Background(), 42) }()
	select {
	case err := <-secondDone:
		t.Fatalf("second item refresh overlapped the first: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(releaseFirst)
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
	if err := <-secondDone; err != nil {
		t.Fatal(err)
	}
}

func TestQueuedRemoteRefreshSamplesNewDelegatedViewAtExecution(t *testing.T) {
	authority, server := serveAuthorityServer(t)
	ctx := context.Background()
	vol, err := clientcore.Dial(ctx, clientcore.Options{
		Addr:     authority,
		Pool:     4,
		Owner:    "queued-refresh-holder",
		WALDir:   privateTestDir(t),
		VolumeID: "queued-refresh-volume",
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = vol.Close() })
	if _, st := vol.Mkdir(ctx, "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir d: %d", st)
	}

	blockFlush := make(chan struct{})
	var unblock sync.Once
	t.Cleanup(func() { unblock.Do(func() { close(blockFlush) }) })
	entered := make(chan struct{}, 1)
	server.SetBeforeFlushBatch(func() {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-blockFlush
	})
	attr, st := vol.Create(ctx, "d/f", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create d/f: %d", st)
	}
	node := clientcore.NewNodeState(attr.Ino, attr.Ino != 0)
	payload := []byte("new-delegated-size")
	if _, st := vol.Write(ctx, "d/f", node, 0, payload); st != fsproto.OK {
		t.Fatalf("write d/f: %d", st)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("flush did not enter authority gate")
	}

	var appliedSize int64 = -1
	a := &attach{
		vol: vol,
		paths: map[string]*itemRecord{
			"d/f": {
				item:  pfslocal.Item{ItemID: 7, ItemGeneration: 1},
				path:  "d/f",
				state: node,
				attr:  fsproto.Attr{Kind: "file"},
			},
		},
	}
	a.items = map[uint64]*itemRecord{7: a.paths["d/f"]}
	a.testRefreshKernelFile = func(_ string, path string, itemID uint64, size int64, _ func() (func(), error)) (kernelRefreshOutcome, error) {
		expectedItemID, ok := fskitItemID(7)
		if !ok {
			t.Fatal("map expected FSKit item ID")
		}
		if path != "d/f" || itemID != expectedItemID {
			t.Fatalf("refresh target = %q item=%d", path, itemID)
		}
		appliedSize = size
		return kernelRefreshApplied, nil
	}
	// Model a remote invalidation that was queued before the grant/write but
	// reaches its worker afterward. The pass must choose the composed view at
	// execution, not the stale raw authority lane implied by its origin.
	if settled := a.refreshKernelItemStateComposed("/unused-test-mount", 7); !settled {
		t.Fatal("composed refresh did not settle")
	}
	if appliedSize != int64(len(payload)) {
		t.Fatalf("queued remote refresh applied size %d, want %d", appliedSize, len(payload))
	}
	unblock.Do(func() { close(blockFlush) })
}

func TestRefreshSamplesFenceAuthorityGenerationChanges(t *testing.T) {
	if refreshSamplesSettled(9, 101, 1, 202) {
		t.Fatal("versions from different generation nonces were ordered")
	}
	if refreshSamplesSettled(9, 101, 0, 0) {
		t.Fatal("authority-to-overlay ownership boundary was marked settled")
	}
	if refreshSamplesSettled(0, 0, 9, 101) {
		t.Fatal("overlay-to-authority ownership boundary was marked settled")
	}
	if !refreshSamplesSettled(0, 0, 0, 0) {
		t.Fatal("stable delegated overlay samples did not settle")
	}
	if !refreshSamplesSettled(9, 101, 8, 101) {
		t.Fatal("same-generation non-advancing sample did not settle")
	}
	if refreshSamplesSettled(8, 101, 9, 101) {
		t.Fatal("same-generation advancing sample was marked settled")
	}
}

func TestFrontendHandoffBracketsReadReplyPublication(t *testing.T) {
	a := &attach{}
	_, read := a.beginFrontendPaths(context.Background(), []string{"d/f"})
	started := make(chan struct{})
	go func() {
		if err := a.startFrontendHandoff(context.Background(), "d"); err != nil {
			t.Errorf("start handoff: %v", err)
		}
		close(started)
	}()
	select {
	case <-started:
		t.Fatal("handoff crossed an in-flight read reply")
	case <-time.After(20 * time.Millisecond):
	}
	a.finishFrontendOperation(read)
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("handoff did not start after read reply completed")
	}

	nextRead := make(chan *frontendOperation, 1)
	go func() {
		_, op := a.beginFrontendPaths(context.Background(), []string{"d/next"})
		nextRead <- op
	}()
	select {
	case <-nextRead:
		t.Fatal("new read reply entered during handoff")
	case <-time.After(20 * time.Millisecond):
	}
	a.endFrontendHandoff("d")
	select {
	case op := <-nextRead:
		a.finishFrontendOperation(op)
	case <-time.After(time.Second):
		t.Fatal("new read reply did not resume after handoff")
	}
}

func TestFrontendHandoffDoesNotBlockDisjointScope(t *testing.T) {
	a := &attach{}
	if err := a.startFrontendHandoff(context.Background(), "left"); err != nil {
		t.Fatal(err)
	}
	entered := make(chan *frontendOperation, 1)
	go func() {
		_, op := a.beginFrontendPaths(context.Background(), []string{"right/file"})
		entered <- op
	}()
	select {
	case op := <-entered:
		a.finishFrontendOperation(op)
	case <-time.After(time.Second):
		t.Fatal("disjoint frontend operation was blocked by handoff")
	}
	a.endFrontendHandoff("left")
}

func TestFrontendReleaseWaitSuspendsEveryJoinedCaller(t *testing.T) {
	a := &attach{}
	ctxA, opA := a.beginFrontendPaths(context.Background(), []string{"d/a"})
	ctxB, opB := a.beginFrontendPaths(context.Background(), []string{"d/b"})
	resumeA := a.suspendFrontendOperation(ctxA)
	resumeB := a.suspendFrontendOperation(ctxB)

	if err := a.startFrontendHandoff(context.Background(), "d"); err != nil {
		t.Fatal(err)
	}
	resumed := make(chan struct{}, 2)
	go func() {
		resumeA()
		resumed <- struct{}{}
	}()
	go func() {
		resumeB()
		resumed <- struct{}{}
	}()
	select {
	case <-resumed:
		t.Fatal("release waiter re-entered before handoff ended")
	case <-time.After(20 * time.Millisecond):
	}
	a.endFrontendHandoff("d")
	for range 2 {
		select {
		case <-resumed:
		case <-time.After(time.Second):
			t.Fatal("release waiter did not re-enter after handoff")
		}
	}
	a.finishFrontendOperation(opA)
	a.finishFrontendOperation(opB)
}

func TestFrontendPathEpochMakesRenameRaceConservative(t *testing.T) {
	a := &attach{}
	_, op := a.beginFrontendPaths(context.Background(), []string{"right/file"})
	// Model a namespace rekey after the operation resolved its scope.
	a.frontendPathEpoch.Add(1)
	started := make(chan error, 1)
	go func() {
		started <- a.startFrontendHandoff(context.Background(), "left")
	}()
	select {
	case err := <-started:
		t.Fatalf("handoff crossed stale path snapshot: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	a.finishFrontendOperation(op)
	select {
	case err := <-started:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("handoff did not resume after stale-snapshot operation completed")
	}
	a.endFrontendHandoff("left")
}

func TestFrontendItemOperationCoversEveryHardlinkAlias(t *testing.T) {
	state := clientcore.NewNodeState(7, true)
	item := pfslocal.Item{ItemID: 7, ItemGeneration: 1}
	a := &attach{
		items:       map[uint64]*itemRecord{},
		paths:       map[string]*itemRecord{},
		itemAliases: map[uint64]map[string]struct{}{},
	}
	first := &itemRecord{item: item, path: "left/a", state: state}
	second := &itemRecord{item: item, path: "right/b", state: state}
	a.items[item.ItemID] = first
	a.paths[first.path] = first
	a.paths[second.path] = second
	a.addItemAliasLocked(first)
	a.addItemAliasLocked(second)

	paths, _, publishes := a.frontendOperationPaths(&pfslocal.GetAttrRequest{Item: item})
	if !publishes {
		t.Fatal("getattr was not publication-tracked")
	}
	got := map[string]bool{}
	for _, path := range paths {
		got[path] = true
	}
	if !got[first.path] || !got[second.path] || len(got) != 2 {
		t.Fatalf("hardlink publication paths = %v", paths)
	}
}

func TestDetachedHandlePublicationScopeNeverUsesStalePath(t *testing.T) {
	state := clientcore.NewNodeState(7, true)
	item := pfslocal.Item{ItemID: 7, ItemGeneration: 1}
	a := &attach{
		items:       map[uint64]*itemRecord{},
		paths:       map[string]*itemRecord{},
		itemAliases: map[uint64]map[string]struct{}{},
		handles:     map[uint64]*handleRecord{},
		subscribers: map[*eventSubscriber]struct{}{},
	}
	detached := &itemRecord{item: item, path: "target", state: state}
	replacement := &itemRecord{
		item:  pfslocal.Item{ItemID: 9, ItemGeneration: 1},
		path:  "target",
		state: clientcore.NewNodeState(9, true),
	}
	a.items[item.ItemID] = detached
	a.items[replacement.item.ItemID] = replacement
	a.paths["target"] = replacement
	a.addItemAliasLocked(replacement)
	a.handles[3] = &handleRecord{
		id: 3, itemID: item.ItemID, path: "target", openPath: "target", state: state, write: true,
	}

	requests := []struct {
		name string
		body any
	}{
		{"getattr", &pfslocal.GetAttrRequest{Item: item, Handle: 3}},
		{"setattr", &pfslocal.SetAttrRequest{Item: item, Handle: 3}},
		{"read", &pfslocal.ReadRequest{Handle: 3}},
		{"write", &pfslocal.WriteRequest{Handle: 3}},
		{"getxattr", &pfslocal.XattrGetRequest{Item: item, Handle: 3}},
		{"setxattr", &pfslocal.XattrSetRequest{Item: item, Handle: 3}},
		{"listxattr", &pfslocal.XattrListRequest{Item: item, Handle: 3}},
		{"removexattr", &pfslocal.XattrRemoveRequest{Item: item, Handle: 3}},
	}
	for _, test := range requests {
		t.Run(test.name, func(t *testing.T) {
			paths, _, publishes := a.frontendOperationPaths(test.body)
			if !publishes {
				t.Fatalf("detached %s was not publication-tracked", test.name)
			}
			if len(paths) != 1 || paths[0] != "" {
				t.Fatalf(
					"detached %s publication paths=%v want mount-wide unknown scope",
					test.name, paths,
				)
			}
		})
	}

	sub := &eventSubscriber{origin: 41, ch: make(chan pfslocal.Event, 3)}
	a.subscribers[sub] = struct{}{}
	mutations := []any{
		&pfslocal.SetAttrRequest{Item: item, Handle: 3},
		&pfslocal.XattrSetRequest{Item: item, Handle: 3},
		&pfslocal.XattrRemoveRequest{Item: item, Handle: 3},
	}
	for _, mutation := range mutations {
		a.synthesizeFrontendMutation(mutation, 17)
		ev := <-sub.ch
		invalidation, ok := ev.Kind.(*pfslocal.Invalidation)
		if !ok || invalidation.Item != item || !invalidation.ContentChanged ||
			!invalidation.AttrsChanged {
			t.Fatalf("detached mutation invalidation=%+v want exact old Item", ev)
		}
	}
}

func TestFrontendHandoffCancellationReopensAdmission(t *testing.T) {
	a := &attach{}
	_, op := a.beginFrontendPaths(context.Background(), []string{"d/f"})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := a.startFrontendHandoff(ctx, "d"); err == nil {
		t.Fatal("canceled handoff unexpectedly succeeded")
	}
	a.finishFrontendOperation(op)

	entered := make(chan *frontendOperation, 1)
	go func() {
		_, next := a.beginFrontendPaths(context.Background(), []string{"d/next"})
		entered <- next
	}()
	select {
	case next := <-entered:
		a.finishFrontendOperation(next)
	case <-time.After(time.Second):
		t.Fatal("canceled handoff left admission closed")
	}
}

func TestClosedFrontendConnectionReleasesUnexposedOperation(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	a := &attach{}
	_, inFlight := a.beginFrontendPaths(context.Background(), []string{"d/in-flight"})
	ready := make(chan struct{})
	close(ready)
	conn := &frontendConn{
		conn: serverSide,
		operations: map[uint64]*frontendOperationEntry{
			1: {ready: ready, op: inFlight},
		},
		lastOperationID: 1,
	}
	conn.close()
	if _, ok := conn.reserveLogicalOperation(2, true); ok {
		t.Fatal("closed connection admitted a late logical operation")
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := a.startFrontendHandoff(ctx, "d"); err != nil {
		t.Fatalf("late publication survived closed connection: %v", err)
	}
	a.endFrontendHandoff("d")
}

func TestFrontendDisconnectCompletesReservedOperationWhoseInitializerHasNotStarted(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	a := &attach{}
	ready := make(chan struct{})
	conn := &frontendConn{
		conn: serverSide,
		operations: map[uint64]*frontendOperationEntry{
			1: {ready: ready, activeRequests: 1},
		},
		lastOperationID: 1,
	}
	startHandler := make(chan struct{})
	handlerResult := make(chan error, 1)
	conn.handlerWG.Add(1)
	go func() {
		defer conn.handlerWG.Done()
		<-startHandler
		_, _, _, _, err := conn.beginLogicalOperation(
			context.Background(),
			a,
			1,
			true,
			&pfslocal.GetAttrRequest{},
		)
		handlerResult <- err
	}()
	closeDone := make(chan struct{})
	go func() {
		conn.close()
		close(closeDone)
	}()
	deadline := time.Now().Add(time.Second)
	for {
		conn.publicationMu.Lock()
		closed := conn.publicationClosed
		conn.publicationMu.Unlock()
		if closed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("disconnect did not close publication admission")
		}
		time.Sleep(time.Millisecond)
	}
	close(startHandler)
	select {
	case err := <-handlerResult:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("initializer error = %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("reserved initializer did not observe disconnect")
	}
	select {
	case <-closeDone:
	case <-time.After(time.Second):
		t.Fatal("disconnect waited forever on the reserved operation")
	}
	select {
	case <-ready:
	default:
		t.Fatal("reserved operation outcome was not published")
	}
}

// A disconnect that loses an acknowledgement RETIRES the operation and lets the
// mount go on serving. It does not install a terminal verdict.
//
// The old contract was the opposite: one exposed-unacknowledged publication at
// disconnect published a terminal gate error, froze the attach, and aborted the
// waiting handoff. That is the live blocker — a latency outlier closed the
// connection and the mount answered EIO forever after. The acknowledgement is
// genuinely unreachable once the connection is gone, but "unreachable" is a
// statement about the ACK, not about the kernel: the mount outlives the
// connection and the daemon can rewrite the affected kernel state through it.
//
// So what this test pins is the liveness the verdict used to provide by force:
//   - the waiting handoff PROCEEDS (its blocker was retired, not failed),
//   - the attach is still admitting,
//   - a later handoff still succeeds,
//   - and close() does not deadlock against a handler parked behind that very
//     handoff, which is the cycle the terminal verdict was introduced to break:
//     close -> handlerWG -> handler -> handoff -> exposed operation -> close.
func TestClosedFrontendConnectionRepairsExposedUnacknowledgedOperation(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	a := &attach{}
	_, inFlight := a.beginFrontendPaths(context.Background(), []string{"d/in-flight"})
	ready := make(chan struct{})
	close(ready)
	conn := &frontendConn{
		conn: serverSide,
		operations: map[uint64]*frontendOperationEntry{
			1: {ready: ready, op: inFlight},
		},
		lastOperationID: 1,
	}
	exposeTestLogicalOperation(t, conn, 1)
	handoffDone := make(chan error, 1)
	handoffFinished := make(chan struct{})
	go func() {
		// A real attached handler holds the frontend proxy for reading while a
		// delegation handoff runs.
		a.frontendSerial.RLock()
		err := a.startFrontendHandoff(context.Background(), "d")
		a.frontendSerial.RUnlock()
		handoffDone <- err
		close(handoffFinished)
	}()
	deadline := time.Now().Add(time.Second)
	for {
		a.frontendGateMu.Lock()
		waiting := a.frontendHandoffs["d"] != 0
		a.frontendGateMu.Unlock()
		if waiting {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("handoff did not enter the publication wait")
		}
		time.Sleep(time.Millisecond)
	}
	// Model a connection handler whose only exit is the completion of that
	// handoff. If close() joined handlers before retiring the exposed
	// operation, this would be the closed cycle above and the test would hang.
	handlerStarted := make(chan struct{})
	handlerDone := make(chan struct{})
	conn.handlerWG.Add(1)
	go func() {
		defer conn.handlerWG.Done()
		close(handlerStarted)
		<-handoffFinished
		close(handlerDone)
	}()
	<-handlerStarted
	closeDone := make(chan struct{})
	go func() {
		conn.close()
		close(closeDone)
	}()
	select {
	case <-handlerDone:
	case <-time.After(2 * time.Second):
		t.Fatal("disconnect did not retire the exposed operation before joining handlers")
	}
	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("exposed disconnect deadlocked behind the waiting handoff")
	}
	// The handoff CROSSED rather than aborting: its blocker was retired, not
	// failed. It owns the scope until its release ends, exactly as a successful
	// handoff always has.
	if err := <-handoffDone; err != nil {
		t.Fatalf("handoff was refused by a lost acknowledgement: %v", err)
	}
	a.endFrontendHandoff("d")
	// THE POSTURE. A lost acknowledgement leaves the mount serving.
	if err := a.frontendAdmissionError(); err != nil {
		t.Fatalf("attach was terminally degraded by a lost acknowledgement: %v", err)
	}
	a.frontendGateMu.Lock()
	stillActive := len(a.frontendActive)
	a.frontendGateMu.Unlock()
	if stillActive != 0 {
		t.Fatalf("disconnect left %d operation(s) in the publication set", stillActive)
	}
	a.frontendGateMu.Lock()
	waiting := len(a.frontendHandoffs)
	a.frontendGateMu.Unlock()
	if waiting != 0 {
		t.Fatalf("completed handoff left %d scope(s) installed", waiting)
	}

	if err := a.startFrontendHandoff(context.Background(), "d"); err != nil {
		t.Fatalf("later handoff was refused after a lost acknowledgement: %v", err)
	}
	a.endFrontendHandoff("d")
}

func TestClosedFrontendConnectionReleasesAcknowledgedOperation(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer clientSide.Close()
	a := &attach{}
	_, inFlight := a.beginFrontendPaths(context.Background(), []string{"d/in-flight"})
	ready := make(chan struct{})
	close(ready)
	conn := &frontendConn{
		conn: serverSide,
		operations: map[uint64]*frontendOperationEntry{
			1: {ready: ready, op: inFlight},
		},
		lastOperationID: 1,
	}
	exposeTestLogicalOperation(t, conn, 1)
	if !conn.acknowledgePublication(1) {
		t.Fatal("acknowledgement rejected")
	}
	conn.close()

	if err := a.frontendAdmissionError(); err != nil {
		t.Fatalf("acknowledged disconnect failed attach: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := a.startFrontendHandoff(ctx, "d"); err != nil {
		t.Fatalf("acknowledged operation survived closed connection: %v", err)
	}
	a.endFrontendHandoff("d")
}

func TestLogicalOperationCanIssueNextRPCWhileHandoffWaitsForItsPublication(t *testing.T) {
	a := &attach{}
	conn := &frontendConn{}
	const operationID uint64 = 1

	ctx1, participant1, participates, publishes, err := beginTestLogicalOperation(
		t, conn, a,
		operationID,
		&pfslocal.GetAttrRequest{},
	)
	if err != nil || !participates || !publishes || participant1 == nil {
		t.Fatalf("first request admission: participates=%v publishes=%v participant=%v err=%v", participates, publishes, participant1, err)
	}
	_ = ctx1
	a.finishFrontendParticipant(participant1)
	conn.finishLogicalRequest(operationID)
	exposeTestLogicalOperation(t, conn, operationID)

	handoffDone := make(chan error, 1)
	go func() {
		handoffDone <- a.startFrontendHandoff(context.Background(), "")
	}()
	select {
	case err := <-handoffDone:
		t.Fatalf("handoff crossed unacknowledged first reply: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	_, participant2, participates, publishes, err := beginTestLogicalOperation(
		t, conn, a,
		operationID,
		&pfslocal.EnumerateRequest{},
	)
	if err != nil || !participates || !publishes || participant2 == nil {
		t.Fatalf("second request admission: participates=%v publishes=%v participant=%v err=%v", participates, publishes, participant2, err)
	}
	select {
	case err := <-handoffDone:
		t.Fatalf("handoff crossed the logical operation's second request: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	a.finishFrontendParticipant(participant2)
	conn.finishLogicalRequest(operationID)
	if !conn.acknowledgePublication(operationID) {
		t.Fatal("logical operation acknowledgement was rejected")
	}
	select {
	case err := <-handoffDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("handoff did not complete after the logical operation acknowledgement")
	}
	a.endFrontendHandoff("")
}

func TestLogicalOperationIDsAreAdmittedInWireOrderNotHandlerOrder(t *testing.T) {
	a := &attach{}
	conn := &frontendConn{}
	initializeOne, ok := conn.reserveLogicalOperation(1, true)
	if !ok || !initializeOne {
		t.Fatal("reserve operation 1")
	}
	initializeTwo, ok := conn.reserveLogicalOperation(2, true)
	if !ok || !initializeTwo {
		t.Fatal("reserve operation 2")
	}

	// Deliberately run the second handler first. Frame ingress already proved
	// 1 then 2, so parallel goroutine scheduling must not reinterpret this as
	// a malformed decreasing operation stream.
	ctxTwo, second, participates, publishes, err := conn.beginLogicalOperation(
		context.Background(), a, 2, initializeTwo, &pfslocal.GetAttrRequest{},
	)
	if err != nil || !participates || !publishes || second == nil {
		t.Fatalf("operation 2 admission: participant=%v err=%v", second, err)
	}
	if err := activateTestParticipant(ctxTwo, a, second); err != nil {
		t.Fatalf("operation 2 activation: %v", err)
	}
	ctxOne, first, participates, publishes, err := conn.beginLogicalOperation(
		context.Background(), a, 1, initializeOne, &pfslocal.GetAttrRequest{},
	)
	if err != nil || !participates || !publishes || first == nil {
		t.Fatalf("operation 1 admission: participant=%v err=%v", first, err)
	}
	if err := activateTestParticipant(ctxOne, a, first); err != nil {
		t.Fatalf("operation 1 activation: %v", err)
	}

	a.finishFrontendParticipant(first)
	conn.finishLogicalRequest(1)
	a.finishFrontendParticipant(second)
	conn.finishLogicalRequest(2)
	exposeTestLogicalOperation(t, conn, 1)
	exposeTestLogicalOperation(t, conn, 2)
	if !conn.acknowledgePublication(1) ||
		!conn.acknowledgePublication(2) {
		t.Fatal("wire-ordered operations did not retire")
	}
}

// An acknowledgement is accepted whether or not a reply has been exposed yet,
// and either way the operation is retired only once EVERY pipelined request of
// it has finished.
//
// The first half is the changed contract. The daemon used to refuse an
// acknowledgement for an operation with no exposed reply and kill the
// connection over it, which was right while the frontend created its obligation
// on RECEIVING an ack-required reply. The obligation now begins where the daemon's
// own does — when the operation ID is stamped on a request — so a frontend that
// gave up on a reply this daemon is still computing can say it has finished, and
// that is the statement that used to strand: the operation stayed pinned in the
// publication set on a healthy connection, blocking every handoff over its scope
// and refusing clean unmount, with no event left that could ever retire it.
func TestLogicalOperationAckBeforeExposureRetiresAfterEveryPipelinedRequest(t *testing.T) {
	a := &attach{}
	conn := &frontendConn{}
	const operationID uint64 = 1

	_, first, _, _, err := beginTestLogicalOperation(
		t, conn, a, operationID, &pfslocal.GetAttrRequest{},
	)
	if err != nil {
		t.Fatal(err)
	}
	_, second, _, _, err := beginTestLogicalOperation(
		t, conn, a, operationID, &pfslocal.EnumerateRequest{},
	)
	if err != nil {
		t.Fatal(err)
	}
	if !conn.acknowledgePublication(operationID) {
		t.Fatal("acknowledgement before a reply was exposed was refused")
	}
	// A reply written after the acknowledgement still goes out — the request is
	// owed one either way — and simply pins nothing, because the obligation has
	// already been discharged and there is exactly one acknowledgement per
	// operation.
	exposeTestLogicalOperation(t, conn, operationID)
	if conn.acknowledgePublication(operationID) {
		t.Fatal("operation was acknowledged twice")
	}

	handoffDone := make(chan error, 1)
	go func() { handoffDone <- a.startFrontendHandoff(context.Background(), "") }()
	a.finishFrontendParticipant(first)
	conn.finishLogicalRequest(operationID)
	select {
	case err := <-handoffDone:
		t.Fatalf("handoff crossed the still-executing second request: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	a.finishFrontendParticipant(second)
	conn.finishLogicalRequest(operationID)
	select {
	case err := <-handoffDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("handoff did not complete after every pipelined request finished")
	}
	a.endFrontendHandoff("")

	if _, ok := conn.reserveLogicalOperation(operationID, true); ok {
		t.Fatal("acknowledged operation id was reusable")
	}
}

func TestAuthorityAckWaitsForExactKernelRefresh(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	item := pfslocal.Item{ItemID: 17, ItemGeneration: 1}
	rec := &itemRecord{
		item: item,
		path: "visible",
		// Restored bindings intentionally begin with only authority identity;
		// an empty cached Kind must not let a live vnode escape the barrier.
		attr: fsproto.Attr{Ino: 91},
	}
	a := &attach{
		paths: map[string]*itemRecord{"visible": rec},
		items: map[uint64]*itemRecord{item.ItemID: rec},
	}
	refreshStarted := make(chan struct{})
	allowRefresh := make(chan struct{})
	a.testExactKernelRefresh = func(context.Context, uint64) error {
		close(refreshStarted)
		<-allowRefresh
		return nil
	}
	stream := make(chan coherence.Batch, 1)
	acked := make(chan uint64, 1)
	done := make(chan struct{})
	go func() {
		a.forwardEvents(ctx, nil, stream, func(pos uint64) { acked <- pos })
		close(done)
	}()
	stream <- coherence.Batch{
		Pos: 7,
		Invs: []coherence.Invalidation{{
			Path: "visible", Version: 2, InPlace: true,
		}},
	}
	select {
	case <-refreshStarted:
	case <-time.After(time.Second):
		t.Fatal("exact kernel refresh did not start")
	}
	select {
	case pos := <-acked:
		t.Fatalf("authority position %d acknowledged before kernel refresh", pos)
	case <-time.After(20 * time.Millisecond):
	}
	close(allowRefresh)
	select {
	case pos := <-acked:
		if pos != 7 {
			t.Fatalf("ack position = %d, want 7", pos)
		}
	case <-time.After(time.Second):
		t.Fatal("authority position was not acknowledged after exact refresh")
	}
	cancel()
	close(stream)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("event forwarder did not stop")
	}
}

func TestRelatedAuthorityInodeRefreshesKnownAliasBeforeAck(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	item := pfslocal.Item{ItemID: 31, ItemGeneration: 1}
	state := clientcore.NewNodeState(77, true)
	rec := &itemRecord{
		item: item, path: "known-alias", state: state,
		attr: fsproto.Attr{Kind: "file", Ino: 77},
	}
	a := &attach{
		paths:          map[string]*itemRecord{"known-alias": rec},
		items:          map[uint64]*itemRecord{item.ItemID: rec},
		itemAliases:    map[uint64]map[string]struct{}{item.ItemID: {"known-alias": {}}},
		authorityItems: map[uint64]frontendItemIdentity{77: {item: item, state: state}},
	}
	refreshed := make(chan uint64, 1)
	a.testExactKernelRefresh = func(_ context.Context, itemID uint64) error {
		refreshed <- itemID
		return nil
	}
	stream := make(chan coherence.Batch, 1)
	acked := make(chan uint64, 1)
	done := make(chan struct{})
	go func() {
		a.forwardEvents(ctx, nil, stream, func(pos uint64) { acked <- pos })
		close(done)
	}()
	// The peer mutated a retained inode with no trustworthy path. The related
	// authority inode is the only bridge to the live local alias; an empty
	// Path is inode-scoped here, not a mount-wide flush.
	stream <- coherence.Batch{
		Pos: 11,
		Invs: []coherence.Invalidation{{
			Version: 4, RelatedInos: []uint64{77},
		}},
	}
	select {
	case itemID := <-refreshed:
		if itemID != item.ItemID {
			t.Fatalf("refreshed item = %d, want %d", itemID, item.ItemID)
		}
	case <-time.After(time.Second):
		t.Fatal("related known alias was not refreshed")
	}
	select {
	case pos := <-acked:
		if pos != 11 {
			t.Fatalf("ack position = %d, want 11", pos)
		}
	case <-time.After(time.Second):
		t.Fatal("related-alias batch was not acknowledged after refresh")
	}
	cancel()
	close(stream)
	<-done
}

func TestObsoleteDirectRefreshRetriesMovedCanonicalAlias(t *testing.T) {
	item := pfslocal.Item{ItemID: 63, ItemGeneration: 1}
	state := clientcore.NewNodeState(700, true)
	moved := &itemRecord{
		item: item, path: "b", state: state,
		attr: fsproto.Attr{Ino: 700, Kind: "file"},
	}
	a := &attach{items: map[uint64]*itemRecord{item.ItemID: moved}}
	if a.obsoleteRefreshSettled(item, "a", false) {
		t.Fatal("obsolete sample at old a settled after exact Item moved to b")
	}
	if !a.obsoleteRefreshSettled(item, "b", false) {
		t.Fatal("ordinary obsolete sample at unchanged canonical name did not settle")
	}
	if a.obsoleteRefreshSettled(item, "b", true) {
		t.Fatal("identity-required obsolete sample settled")
	}
}

func TestExactKernelRefreshGateHonorsCanceledWaiter(t *testing.T) {
	a := &attach{}
	entered := make(chan struct{})
	release := make(chan struct{})
	a.testExactKernelRefresh = func(_ context.Context, itemID uint64) error {
		if itemID != 1 {
			t.Fatalf("unexpected refresh entered gate for item %d", itemID)
		}
		close(entered)
		<-release
		return nil
	}
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- a.exactKernelRefreshMode(context.Background(), 1, true)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("first colliding refresh did not enter")
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	err := a.exactKernelRefreshMode(ctx, 65, true) // same 64-way stripe as item 1
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled colliding refresh error=%v", err)
	}
	if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
		t.Fatalf("canceled gate waiter returned after %v", elapsed)
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first refresh: %v", err)
	}
}

func TestRestartRestoredRegularAndSymlinkFlushAll(t *testing.T) {
	authority := serveAuthority(t)
	vol, err := clientcore.Dial(context.Background(), clientcore.Options{Addr: authority, Pool: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer vol.Close()
	cli := vol.Client()
	fileAttr, st, err := cli.Create("regular", 0o644)
	if err != nil || st != fsproto.OK {
		t.Fatalf("create regular st=%d err=%v", st, err)
	}
	if _, st, err := cli.Write("regular", 0, []byte("data"), 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("write regular st=%d err=%v", st, err)
	}
	fileAttr, st, err = cli.Getattr("regular")
	if err != nil || st != fsproto.OK {
		t.Fatalf("getattr regular st=%d err=%v", st, err)
	}
	linkAttr, st, err := cli.Symlink("regular", "link")
	if err != nil || st != fsproto.OK {
		t.Fatalf("symlink st=%d err=%v", st, err)
	}

	a := newAttach("att_restart_types", "key", ensureAttachRequest{
		VolumeID: "vol-restart-types", Branch: "main",
		MountPath: "/Volumes/RestartTypes",
	}, privateTestDir(t))
	a.vol = vol
	a.restoreItemsLocked([]persistedItemRecord{
		{
			Path: "regular", ItemID: fileAttr.Ino, ItemGeneration: 1,
			AuthorityIno: true, Kind: "file",
		},
		{
			Path: "link", ItemID: linkAttr.Ino, ItemGeneration: 1,
			AuthorityIno: true, Kind: "symlink",
		},
	})
	var regularApplies atomic.Int32
	a.testRefreshKernelFile = func(_ string, p string, itemID uint64, size int64, _ func() (func(), error)) (kernelRefreshOutcome, error) {
		expectedItemID, ok := fskitItemID(fileAttr.Ino)
		if !ok {
			t.Fatal("map expected FSKit item ID")
		}
		if p != "regular" || itemID != expectedItemID || size != 4 {
			t.Fatalf("kernel apply path=%q item=%d size=%d", p, itemID, size)
		}
		regularApplies.Add(1)
		return kernelRefreshApplied, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream := make(chan coherence.Batch, 2)
	acked := make(chan uint64, 2)
	done := make(chan struct{})
	go func() {
		a.forwardEvents(ctx, nil, stream, func(pos uint64) { acked <- pos })
		close(done)
	}()
	stream <- coherence.Batch{Pos: 31, Invs: []coherence.Invalidation{{FlushAll: true}}}
	select {
	case pos := <-acked:
		if pos != 31 {
			t.Fatalf("FlushAll ack=%d want 31", pos)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("restored regular+symlink FlushAll did not settle")
	}
	if got := regularApplies.Load(); got != 1 {
		t.Fatalf("regular kernel applies=%d want 1 (symlink must not apply)", got)
	}

	stream <- coherence.Batch{Pos: 32, Invs: []coherence.Invalidation{{
		Path: "link", RelatedInos: []uint64{linkAttr.Ino},
	}}}
	select {
	case pos := <-acked:
		if pos != 32 {
			t.Fatalf("symlink RelatedInos ack=%d want 32", pos)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("exact symlink RelatedInos did not settle as nonregular")
	}
	if got := regularApplies.Load(); got != 1 {
		t.Fatalf("symlink RelatedInos touched regular-file apply path: %d", got)
	}
	cancel()
	close(stream)
	<-done
}

func TestRelatedRetainedInodeCannotAckThroughReplacementPath(t *testing.T) {
	authority := serveAuthority(t)
	vol, err := clientcore.Dial(context.Background(), clientcore.Options{Addr: authority, Pool: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer vol.Close()
	cli := vol.Client()
	oldAttr, st, err := cli.Create("a", 0o644)
	if err != nil || st != fsproto.OK {
		t.Fatalf("create old a st=%d err=%v", st, err)
	}
	if _, st, err := cli.Write("a", 0, []byte("old"), 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("write old a st=%d err=%v", st, err)
	}
	if linked, st, err := cli.Link("a", "b"); err != nil || st != fsproto.OK ||
		linked.Ino != oldAttr.Ino {
		t.Fatalf("link unseen b attr=%+v st=%d err=%v", linked, st, err)
	}
	if _, st, err := cli.Create("replacement", 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("create replacement st=%d err=%v", st, err)
	}
	if _, st, err := cli.Write("replacement", 0, []byte("replacement-is-larger"), 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("write replacement st=%d err=%v", st, err)
	}
	if st, _, err := cli.RenameWithOrphanTarget("replacement", "a", false); err != nil || st != fsproto.OK {
		t.Fatalf("replace a st=%d err=%v", st, err)
	}
	newAttr, st, err := cli.Getattr("a")
	if err != nil || st != fsproto.OK || newAttr.Ino == oldAttr.Ino {
		t.Fatalf("replacement getattr attr=%+v st=%d err=%v", newAttr, st, err)
	}

	oldItem := pfslocal.Item{ItemID: 81, ItemGeneration: 1}
	oldState := clientcore.NewNodeState(oldAttr.Ino, true)
	oldDetached := &itemRecord{
		item: oldItem, path: "a", state: oldState,
		attr: fsproto.Attr{Ino: oldAttr.Ino, Kind: "file", Size: 3},
	}
	newItem := pfslocal.Item{ItemID: 82, ItemGeneration: 1}
	newRec := &itemRecord{
		item: newItem, path: "a", state: clientcore.NewNodeState(newAttr.Ino, true),
		attr: *newAttr,
	}
	blocked := &attach{
		vol:               vol,
		mountPath:         "/unused",
		items:             map[uint64]*itemRecord{oldItem.ItemID: oldDetached, newItem.ItemID: newRec},
		paths:             map[string]*itemRecord{"a": newRec},
		itemAliases:       map[uint64]map[string]struct{}{newItem.ItemID: {"a": {}}},
		authorityItems:    map[uint64]frontendItemIdentity{oldAttr.Ino: {item: oldItem, state: oldState}},
		expectedTruncates: map[string]expectedTruncate{},
	}
	blocked.testRefreshKernelFile = func(string, string, uint64, int64, func() (func(), error)) (kernelRefreshOutcome, error) {
		t.Fatal("replacement pathname was applied to retained old vnode")
		return kernelRefreshRetry, errors.New("unreachable")
	}
	stream := make(chan coherence.Batch, 1)
	acked := make(chan uint64, 1)
	done := make(chan struct{})
	go func() {
		blocked.forwardEvents(context.Background(), nil, stream, func(pos uint64) { acked <- pos })
		close(done)
	}()
	stream <- coherence.Batch{Pos: 21, Invs: []coherence.Invalidation{{
		Path: "b", InPlace: true, Version: 9, RelatedInos: []uint64{oldAttr.Ino},
	}}}
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("unresolved retained-inode refresh did not fail closed")
	}
	select {
	case pos := <-acked:
		t.Fatalf("unresolved retained inode falsely acknowledged position %d", pos)
	default:
	}
	if err := blocked.frontendAdmissionError(); err == nil {
		t.Fatal("unresolved retained inode did not fail-freeze admission")
	}

	flushBlocked := &attach{
		vol:               vol,
		mountPath:         "/unused",
		items:             map[uint64]*itemRecord{oldItem.ItemID: oldDetached, newItem.ItemID: newRec},
		paths:             map[string]*itemRecord{"a": newRec},
		itemAliases:       map[uint64]map[string]struct{}{newItem.ItemID: {"a": {}}},
		authorityItems:    map[uint64]frontendItemIdentity{oldAttr.Ino: {item: oldItem, state: oldState}},
		expectedTruncates: map[string]expectedTruncate{},
	}
	var oldFlushApplied atomic.Bool
	flushBlocked.testRefreshKernelFile = func(_ string, p string, itemID uint64, size int64, _ func() (func(), error)) (kernelRefreshOutcome, error) {
		oldFSKitItemID, ok := fskitItemID(oldItem.ItemID)
		if !ok {
			t.Fatal("map old FSKit item ID")
		}
		newFSKitItemID, ok := fskitItemID(newItem.ItemID)
		if !ok {
			t.Fatal("map new FSKit item ID")
		}
		if itemID == oldFSKitItemID {
			oldFlushApplied.Store(true)
		}
		if itemID != newFSKitItemID || p != "a" || size != newAttr.Size {
			return kernelRefreshRetry, errors.New("unexpected FlushAll apply target")
		}
		// FlushAll legitimately refreshes the live replacement too. The
		// retained old Item must still fail closed independently, regardless
		// of nondeterministic map iteration order.
		return kernelRefreshApplied, nil
	}
	flushStream := make(chan coherence.Batch, 1)
	flushAcked := make(chan uint64, 1)
	flushDone := make(chan struct{})
	go func() {
		flushBlocked.forwardEvents(context.Background(), nil, flushStream, func(pos uint64) { flushAcked <- pos })
		close(flushDone)
	}()
	flushStream <- coherence.Batch{Pos: 23, Invs: []coherence.Invalidation{{FlushAll: true}}}
	select {
	case <-flushDone:
	case <-time.After(4 * time.Second):
		t.Fatal("FlushAll with unresolved retained inode did not fail closed")
	}
	select {
	case pos := <-flushAcked:
		t.Fatalf("unresolved FlushAll falsely acknowledged position %d", pos)
	default:
	}
	if err := flushBlocked.frontendAdmissionError(); err == nil {
		t.Fatal("unresolved FlushAll did not fail-freeze admission")
	}
	if oldFlushApplied.Load() {
		t.Fatal("FlushAll applied replacement pathname to retained old vnode")
	}

	// Once lookup has made b the canonical alias, the exact same authority
	// claim samples the matching inode, applies that vnode, and may ACK.
	oldAlias := &itemRecord{
		item: oldItem, path: "b", state: oldState,
		attr: fsproto.Attr{Ino: oldAttr.Ino, Kind: "file", Size: 3},
	}
	resolved := &attach{
		vol:            vol,
		mountPath:      "/unused",
		items:          map[uint64]*itemRecord{oldItem.ItemID: oldAlias},
		paths:          map[string]*itemRecord{"b": oldAlias},
		itemAliases:    map[uint64]map[string]struct{}{oldItem.ItemID: {"b": {}}},
		authorityItems: map[uint64]frontendItemIdentity{oldAttr.Ino: {item: oldItem, state: oldState}},
	}
	applied := make(chan struct{}, 1)
	resolved.testRefreshKernelFile = func(_ string, path string, itemID uint64, size int64, _ func() (func(), error)) (kernelRefreshOutcome, error) {
		expectedItemID, ok := fskitItemID(oldItem.ItemID)
		if !ok {
			t.Fatal("map expected FSKit item ID")
		}
		if path != "b" || itemID != expectedItemID || size != 3 {
			t.Fatalf("resolved exact refresh path=%q item=%d size=%d", path, itemID, size)
		}
		applied <- struct{}{}
		return kernelRefreshApplied, nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	resolvedStream := make(chan coherence.Batch, 1)
	resolvedAck := make(chan uint64, 1)
	resolvedDone := make(chan struct{})
	go func() {
		resolved.forwardEvents(ctx, nil, resolvedStream, func(pos uint64) { resolvedAck <- pos })
		close(resolvedDone)
	}()
	resolvedStream <- coherence.Batch{Pos: 22, Invs: []coherence.Invalidation{{
		Path: "b", InPlace: true, Version: 10, RelatedInos: []uint64{oldAttr.Ino},
	}}}
	select {
	case <-applied:
	case <-time.After(time.Second):
		t.Fatal("known surviving alias was not exactly refreshed")
	}
	select {
	case pos := <-resolvedAck:
		if pos != 22 {
			t.Fatalf("resolved ack=%d want 22", pos)
		}
	case <-time.After(time.Second):
		t.Fatal("resolved surviving alias was not acknowledged")
	}
	resolvedStream <- coherence.Batch{Pos: 24, Invs: []coherence.Invalidation{{FlushAll: true}}}
	select {
	case <-applied:
	case <-time.After(time.Second):
		t.Fatal("resolved surviving alias was not refreshed for FlushAll")
	}
	select {
	case pos := <-resolvedAck:
		if pos != 24 {
			t.Fatalf("resolved FlushAll ack=%d want 24", pos)
		}
	case <-time.After(time.Second):
		t.Fatal("resolved surviving alias FlushAll was not acknowledged")
	}
	cancel()
	close(resolvedStream)
	<-resolvedDone
}

func TestAuthorityRefreshFailureFailFreezesWithoutAcknowledging(t *testing.T) {
	item := pfslocal.Item{ItemID: 23, ItemGeneration: 1}
	rec := &itemRecord{item: item, path: "stale", attr: fsproto.Attr{Ino: 101}}
	a := &attach{
		paths: map[string]*itemRecord{"stale": rec},
		items: map[uint64]*itemRecord{item.ItemID: rec},
	}
	refreshErr := errors.New("kernel rejected exact invalidation")
	a.testExactKernelRefresh = func(context.Context, uint64) error {
		return refreshErr
	}
	stream := make(chan coherence.Batch, 1)
	acked := make(chan uint64, 1)
	done := make(chan struct{})
	go func() {
		a.forwardEvents(context.Background(), nil, stream, func(pos uint64) { acked <- pos })
		close(done)
	}()
	stream <- coherence.Batch{
		Pos: 9,
		Invs: []coherence.Invalidation{{
			Path: "stale", Version: 3, InPlace: true,
		}},
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("event forwarder did not stop on exact refresh failure")
	}
	select {
	case pos := <-acked:
		t.Fatalf("failed kernel refresh acknowledged authority position %d", pos)
	default:
	}
	if err := a.frontendAdmissionError(); err == nil {
		t.Fatal("frontend remained admitted after unproven kernel coherence")
	}
	if err := a.controlAdmissionError(); err == nil {
		t.Fatal("control API remained admitted after unproven kernel coherence")
	}
	if got := a.statusState(); got != pfslocal.AttachStateDegraded {
		t.Fatalf("attach state = %v, want degraded", got)
	}
	// Health success must never self-heal a correctness fail-freeze.
	a.setErr(nil)
	if err := a.frontendAdmissionError(); err == nil {
		t.Fatal("health tick cleared terminal coherence fail-freeze")
	}
}

func TestFirstPublishingReplyAfterFailFreezeCanRetireItsGate(t *testing.T) {
	serverSide, clientSide := net.Pipe()
	defer serverSide.Close()
	defer clientSide.Close()
	a := &attach{}
	a.failCoherence(errors.New("unproven vnode state"))
	conn := &frontendConn{conn: serverSide}
	initialize, ok := conn.reserveLogicalOperation(1, true)
	if !ok || !initialize {
		t.Fatal("reserve first logical operation")
	}
	done := make(chan struct{})
	go func() {
		conn.handleAttached(
			context.Background(),
			a,
			1,
			1,
			initialize,
			&pfslocal.GetAttrRequest{},
		)
		close(done)
	}()
	reply, err := pfslocal.ReadFrame(clientSide)
	if err != nil {
		t.Fatal(err)
	}
	if !reply.PublicationAckRequired {
		t.Fatal("fail-frozen publishing error did not request publication acknowledgement")
	}
	if _, ok := reply.Body.(*pfslocal.ErrorReply); !ok {
		t.Fatalf("reply = %T, want ErrorReply", reply.Body)
	}
	<-done
	if !conn.acknowledgePublication(1) {
		t.Fatal("fail-frozen publication acknowledgement was rejected")
	}
	a.frontendGateMu.Lock()
	active := len(a.frontendActive)
	a.frontendGateMu.Unlock()
	if active != 0 {
		t.Fatalf("fail-frozen operation remained active after acknowledgement: %d", active)
	}
	if err := a.startFrontendHandoff(context.Background(), ""); err == nil {
		t.Fatal("terminal coherence failure did not abort a later handoff")
	}
}

func TestLogicalOperationContinuationSuspendsBeforeProxyWait(t *testing.T) {
	a := &attach{}
	conn := &frontendConn{}
	const operationID uint64 = 1
	_, first, _, _, err := beginTestLogicalOperation(
		t, conn, a, operationID, &pfslocal.GetAttrRequest{},
	)
	if err != nil {
		t.Fatal(err)
	}
	a.finishFrontendParticipant(first)
	conn.finishLogicalRequest(operationID)
	exposeTestLogicalOperation(t, conn, operationID)

	// Model a control/lifecycle writer that has acquired the proxy and is
	// waiting for this logical callback to publish before taking nsMu.
	a.frontendSerial.Lock()
	handoffDone := make(chan error, 1)
	go func() { handoffDone <- a.startFrontendHandoff(context.Background(), "") }()
	select {
	case err := <-handoffDone:
		t.Fatalf("handoff crossed the unacknowledged callback: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	continuationReady := make(chan *frontendOperationParticipant, 1)
	continuationDone := make(chan struct{})
	go func() {
		ctx, participant, participates, publishes, beginErr := beginTestLogicalOperation(
			t, conn, a, operationID, &pfslocal.OpenRequest{},
		)
		if beginErr != nil || !participates || publishes {
			continuationReady <- nil
			close(continuationDone)
			return
		}
		resume := a.suspendFrontendOperation(ctx)
		continuationReady <- participant
		unlock := a.lockFrontendRequest(&pfslocal.OpenRequest{})
		if resume != nil {
			resume()
		}
		unlock()
		a.finishFrontendParticipant(participant)
		conn.finishLogicalRequest(operationID)
		close(continuationDone)
	}()
	participant := <-continuationReady
	if participant == nil {
		t.Fatal("logical continuation admission failed")
	}
	select {
	case err := <-handoffDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("suspended continuation did not release the handoff cycle")
	}
	a.endFrontendHandoff("")
	a.frontendSerial.Unlock()
	select {
	case <-continuationDone:
	case <-time.After(time.Second):
		t.Fatal("logical continuation did not resume after proxy release")
	}
	if !conn.acknowledgePublication(operationID) {
		t.Fatal("logical callback acknowledgement failed")
	}
}

func TestLastRunningSiblingFinishingDeactivatesFullySuspendedOperation(t *testing.T) {
	a := &attach{}
	conn := &frontendConn{}
	const operationID uint64 = 1
	ctxA, participantA, _, _, err := beginTestLogicalOperation(
		t, conn, a, operationID, &pfslocal.GetAttrRequest{},
	)
	if err != nil {
		t.Fatal(err)
	}
	_, participantB, _, _, err := beginTestLogicalOperation(
		t, conn, a, operationID, &pfslocal.GetAttrRequest{},
	)
	if err != nil {
		t.Fatal(err)
	}
	resumeA := a.suspendFrontendOperation(ctxA)
	if resumeA == nil {
		t.Fatal("request A did not suspend")
	}
	handoffDone := make(chan error, 1)
	go func() { handoffDone <- a.startFrontendHandoff(context.Background(), "") }()
	select {
	case err := <-handoffDone:
		t.Fatalf("handoff crossed running request B: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	a.finishFrontendParticipant(participantB)
	conn.finishLogicalRequest(operationID)
	select {
	case err := <-handoffDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("handoff remained blocked after only live participant was suspended")
	}
	a.endFrontendHandoff("")
	resumeA()
	a.finishFrontendParticipant(participantA)
	conn.finishLogicalRequest(operationID)
	exposeTestLogicalOperation(t, conn, operationID)
	if !conn.acknowledgePublication(operationID) {
		t.Fatal("operation acknowledgement failed")
	}
}

func TestFrontendOperationNestedSuspensionReentersOnlyAtFinalResume(t *testing.T) {
	for _, tc := range []struct {
		name        string
		resumeOuter bool
	}{
		{name: "outer first", resumeOuter: true},
		{name: "inner first", resumeOuter: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := &attach{}
			ctx, op := a.beginFrontendPaths(context.Background(), []string{""})
			participant := ctx.Value(frontendOperationContextKey{}).(*frontendOperationParticipant)
			outer := a.suspendFrontendOperation(ctx)
			inner := a.suspendFrontendOperation(ctx)
			first, final := inner, outer
			if tc.resumeOuter {
				first, final = outer, inner
			}
			assertState := func(wantDepth, wantSuspended, wantActive int) {
				t.Helper()
				a.frontendGateMu.Lock()
				defer a.frontendGateMu.Unlock()
				active := 0
				if op.gateActive {
					active = 1
				}
				if participant.suspendDepth != wantDepth ||
					op.suspended != wantSuspended ||
					active != wantActive {
					t.Fatalf(
						"state depth=%d suspended=%d active=%d, want %d/%d/%d",
						participant.suspendDepth, op.suspended, active,
						wantDepth, wantSuspended, wantActive,
					)
				}
			}
			assertState(2, 1, 0)
			first()
			assertState(1, 1, 0)
			first() // every resume closure is idempotent
			assertState(1, 1, 0)
			final()
			assertState(0, 0, 1)
			a.finishFrontendOperation(op)
		})
	}

	a := &attach{}
	ctx, cancel := context.WithCancel(context.Background())
	ctx, op := a.beginFrontendPaths(ctx, []string{""})
	outer := a.suspendFrontendOperation(ctx)
	inner := a.suspendFrontendOperation(ctx)
	inner()
	cancel()
	outer()
	a.frontendGateMu.Lock()
	active := op.gateActive
	suspended := op.suspended
	a.frontendGateMu.Unlock()
	if active || suspended != 0 {
		t.Fatalf("canceled final resume reactivated operation: active=%v suspended=%d", active, suspended)
	}
	a.finishFrontendOperation(op)
}

func TestCanceledAuthorityReadInterruptsTransportWithoutFrontendLeak(t *testing.T) {
	base := newManagedTestFS(t, daemonTestBlobs{}, filepath.Join(t.TempDir(), "wal.log"))
	blocked := &blockingFrontendLstatFS{
		FS:      base,
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverCtx, stopServer := context.WithCancel(context.Background())
	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		_ = fsproto.NewServer(blocked, base).Serve(serverCtx, listener)
	}()
	t.Cleanup(func() {
		close(blocked.release)
		stopServer()
		_ = listener.Close()
		select {
		case <-serverDone:
		case <-time.After(5 * time.Second):
			t.Error("blocked authority did not stop")
		}
	})

	a := &attach{}
	volume, err := clientcore.Dial(context.Background(), clientcore.Options{
		Addr:     listener.Addr().String(),
		Pool:     2,
		Owner:    "cancel-client",
		VolumeID: "cancel-authority-read",
		Branch:   "main",
		WALDir:   t.TempDir(),
		OnHandoffStart: func(ctx context.Context, scope string) error {
			return a.startFrontendHandoff(ctx, scope)
		},
		OnHandoffEnd: a.endFrontendHandoff,
		OnOperationWait: func(ctx context.Context) func() {
			return a.suspendFrontendOperation(ctx)
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = volume.Close() })
	a.vol = volume

	requestCtx, cancelRequest := context.WithCancel(context.Background())
	requestCtx, op := a.beginFrontendPaths(requestCtx, []string{""})
	result := make(chan clientcore.Status, 1)
	go func() {
		_, st := volume.Getattr(requestCtx, "blocked", nil)
		result <- st
	}()
	select {
	case <-blocked.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("authority getattr did not reach blocked transport")
	}
	handoffCtx, cancelHandoff := context.WithTimeout(context.Background(), time.Second)
	defer cancelHandoff()
	if err := a.startFrontendHandoff(handoffCtx, ""); err != nil {
		t.Fatalf("suspended authority read blocked handoff: %v", err)
	}
	cancelRequest()
	select {
	case st := <-result:
		if st != fsproto.EIO {
			t.Fatalf("canceled getattr status = %d, want EIO", st)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled authority read did not interrupt and join its transport")
	}
	a.frontendGateMu.Lock()
	active := op.gateActive
	suspended := op.suspended
	a.frontendGateMu.Unlock()
	if active || suspended != 0 {
		t.Fatalf("canceled authority read leaked publication state: active=%v suspended=%d", active, suspended)
	}
	a.endFrontendHandoff("")
	a.finishFrontendOperation(op)
}

func TestSymmetricCrossClientReadsReleaseBothFrontendHandoffs(t *testing.T) {
	fsproto.SetAdaptivePolicyContentionWindowForTest(time.Nanosecond)
	t.Cleanup(func() { fsproto.SetAdaptivePolicyContentionWindowForTest(30 * time.Second) })
	writeback.SetDenialBackoffForTest(time.Nanosecond)
	t.Cleanup(func() { writeback.SetDenialBackoffForTest(5 * time.Second) })

	authority := serveAuthority(t)
	setup, err := fsproto.Dial(authority, 2)
	if err != nil {
		t.Fatal(err)
	}
	setup.SetOwner("setup")
	if live, err := setup.EnsureExactSession(); err != nil || !live {
		t.Fatalf("setup exact session: live=%v err=%v", live, err)
	}
	if _, st, err := setup.Mkdir("left", 0o755); err != nil || st != fsproto.OK {
		t.Fatalf("mkdir left: status=%d err=%v", st, err)
	}
	if _, st, err := setup.Mkdir("right", 0o755); err != nil || st != fsproto.OK {
		t.Fatalf("mkdir right: status=%d err=%v", st, err)
	}
	leftLockTarget := "left/lock-target"
	rightLockTarget := "right/lock-target"
	if _, st, err := setup.Create(leftLockTarget, 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("create left lock target: status=%d err=%v", st, err)
	}
	if _, st, err := setup.Create(rightLockTarget, 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("create right lock target: status=%d err=%v", st, err)
	}
	if err := setup.Close(); err != nil {
		t.Fatal(err)
	}

	type frontend struct {
		attach *attach
		volume *clientcore.Volume
		waits  atomic.Int64
	}
	dial := func(owner string) *frontend {
		f := &frontend{attach: &attach{}}
		volume, err := clientcore.Dial(context.Background(), clientcore.Options{
			Addr:     authority,
			Pool:     4,
			Owner:    owner,
			VolumeID: "cross-client-liveness",
			Branch:   "main",
			WALDir:   t.TempDir(),
			OnHandoffStart: func(ctx context.Context, scope string) error {
				return f.attach.startFrontendHandoff(ctx, scope)
			},
			OnHandoffEnd: f.attach.endFrontendHandoff,
			OnOperationWait: func(ctx context.Context) func() {
				f.waits.Add(1)
				return f.attach.suspendFrontendOperation(ctx)
			},
		})
		if err != nil {
			t.Fatal(err)
		}
		f.volume = volume
		f.attach.vol = volume
		t.Cleanup(func() { _ = volume.Close() })
		invalidationCtx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		go volume.StartInvalidations(invalidationCtx, false)
		return f
	}
	left := dial("left-client")
	right := dial("right-client")
	time.Sleep(100 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	acquire := func(side, phase string, f *frontend) string {
		t.Helper()
		for i := 0; i < 32; i++ {
			path := fmt.Sprintf("%s/%s-held-%02d", side, phase, i)
			if _, st := f.volume.Getattr(ctx, path, nil); st != fsproto.ENOENT {
				t.Fatalf("%s negative proof %d: %d", side, i, st)
			}
			if _, st := f.volume.Create(ctx, path, 0o644); st != fsproto.OK {
				t.Fatalf("%s delegation seed %d: %d", side, i, st)
			}
			if records, _ := f.volume.WriteBackPending(); records > 0 {
				return path
			}
		}
		t.Fatalf("%s client did not acquire a delegation", side)
		return ""
	}
	_ = acquire("left", "lock", left)
	_ = acquire("right", "lock", right)
	left.waits.Store(0)
	right.waits.Store(0)

	type lockResult struct {
		side string
		st   int32
		err  error
	}
	lockResults := make(chan lockResult, 2)
	lockStart := make(chan struct{})
	leftLock := &clientcore.LockHandle{}
	rightLock := &clientcore.LockHandle{}
	runLock := func(side, path string, owner uint64, f *frontend, handle *clientcore.LockHandle) {
		opCtx, op := f.attach.beginFrontendPaths(ctx, []string{""})
		go func() {
			defer f.attach.finishFrontendOperation(op)
			<-lockStart
			got, err := f.volume.Setlk(opCtx, handle, path, owner, 0, 1, true, false)
			lockResults <- lockResult{side: side, st: got.Status, err: err}
		}()
	}
	runLock("left", rightLockTarget, 11, left, leftLock)
	runLock("right", leftLockTarget, 22, right, rightLock)
	close(lockStart)
	for range 2 {
		select {
		case got := <-lockResults:
			if got.err != nil || got.st != fsproto.OK {
				t.Fatalf("%s cross-client setlk: status=%d err=%v", got.side, got.st, got.err)
			}
		case <-ctx.Done():
			t.Fatal("symmetric cross-client locks deadlocked with reciprocal delegation handoffs")
		}
	}
	if left.waits.Load() == 0 || right.waits.Load() == 0 {
		t.Fatalf("lock authority waits: left=%d right=%d, want both frontends suspended", left.waits.Load(), right.waits.Load())
	}
	if got, err := left.volume.Setlk(ctx, leftLock, rightLockTarget, 11, 0, 1, false, true); err != nil || got.Status != fsproto.OK {
		t.Fatalf("left unlock: status=%d err=%v", got.Status, err)
	}
	if got, err := right.volume.Setlk(ctx, rightLock, leftLockTarget, 22, 0, 1, false, true); err != nil || got.Status != fsproto.OK {
		t.Fatalf("right unlock: status=%d err=%v", got.Status, err)
	}

	leftPath := acquire("left", "read", left)
	rightPath := acquire("right", "read", right)
	left.waits.Store(0)
	right.waits.Store(0)

	type result struct {
		side string
		st   clientcore.Status
	}
	results := make(chan result, 2)
	start := make(chan struct{})
	run := func(side, path string, f *frontend) {
		opCtx, op := f.attach.beginFrontendPaths(ctx, []string{""})
		go func() {
			defer f.attach.finishFrontendOperation(op)
			<-start
			_, st := f.volume.Getattr(opCtx, path, nil)
			results <- result{side: side, st: st}
		}()
	}
	run("left", rightPath, left)
	run("right", leftPath, right)
	close(start)
	for range 2 {
		select {
		case got := <-results:
			if got.st != fsproto.OK {
				t.Fatalf("%s cross-client getattr: %d", got.side, got.st)
			}
		case <-ctx.Done():
			t.Fatal("symmetric cross-client authority reads deadlocked with reciprocal handoffs")
		}
	}
	if left.waits.Load() == 0 || right.waits.Load() == 0 {
		t.Fatalf("authority waits: left=%d right=%d, want both frontends suspended", left.waits.Load(), right.waits.Load())
	}
}

func TestExternalNamespaceWriterTakesProxyBeforeConcreteLock(t *testing.T) {
	a := &attach{}
	a.frontendSerial.RLock()
	acquired := make(chan func(), 1)
	go func() { acquired <- a.lockExternalNamespaceWrite() }()
	select {
	case <-acquired:
		t.Fatal("external writer crossed an active frontend proxy")
	case <-time.After(20 * time.Millisecond):
	}
	if !a.nsMu.TryLock() {
		t.Fatal("external writer took nsMu before its frontend proxy")
	}
	a.nsMu.Unlock()
	a.frontendSerial.RUnlock()
	var unlock func()
	select {
	case unlock = <-acquired:
	case <-time.After(time.Second):
		t.Fatal("external writer did not acquire after proxy release")
	}
	unlock()
}

func TestFrontendReclaimTakesExclusiveNamespaceProxy(t *testing.T) {
	a := &attach{}
	a.frontendSerial.RLock()
	readerHeld := true
	defer func() {
		if readerHeld {
			a.frontendSerial.RUnlock()
		}
	}()

	acquired := make(chan func(), 1)
	go func() { acquired <- a.lockFrontendRequest(&pfslocal.ReclaimRequest{}) }()
	select {
	case unlock := <-acquired:
		unlock()
		t.Fatal("reclaim acquired a shared frontend proxy")
	case <-time.After(20 * time.Millisecond):
	}

	a.frontendSerial.RUnlock()
	readerHeld = false
	var unlock func()
	select {
	case unlock = <-acquired:
	case <-time.After(time.Second):
		t.Fatal("reclaim did not acquire after readers exited")
	}
	unlock()
}

func TestCloseCrossesUnrelatedSharedNamespaceLocks(t *testing.T) {
	a := &attach{
		handles:            map[uint64]*handleRecord{},
		retiredCloseErrnos: map[uint64]int32{},
	}
	a.frontendSerial.RLock()
	a.nsMu.RLock()
	locksHeld := true
	defer func() {
		if locksHeld {
			a.nsMu.RUnlock()
			a.frontendSerial.RUnlock()
		}
	}()

	done := make(chan int32, 1)
	go func() {
		unlock := a.lockFrontendRequest(&pfslocal.CloseRequest{Handle: 42})
		_, eno := a.close(&pfslocal.CloseRequest{Handle: 42})
		unlock()
		done <- eno
	}()
	select {
	case eno := <-done:
		if eno != darwinEINVAL {
			t.Fatalf("close errno=%d want EINVAL", eno)
		}
	case <-time.After(time.Second):
		t.Fatal("close blocked behind unrelated shared namespace locks")
	}

	a.nsMu.RUnlock()
	a.frontendSerial.RUnlock()
	locksHeld = false
}

func TestHandleOperationsSerializeOnlyMatchingDescriptor(t *testing.T) {
	a := &attach{
		handles: map[uint64]*handleRecord{
			1: {id: 1},
			2: {id: 2},
		},
	}

	firstFrontend := a.lockFrontendRequest(&pfslocal.ReadRequest{Handle: 1})
	secondFrontend := a.lockFrontendRequest(&pfslocal.ReadRequest{Handle: 1})
	secondFrontend()
	sameFrontend := make(chan func(), 1)
	otherFrontend := make(chan func(), 1)
	go func() {
		sameFrontend <- a.lockFrontendRequest(&pfslocal.CloseRequest{Handle: 1})
	}()
	go func() {
		otherFrontend <- a.lockFrontendRequest(&pfslocal.CloseRequest{Handle: 2})
	}()
	select {
	case unlock := <-sameFrontend:
		unlock()
		t.Fatal("same-handle frontend request crossed descriptor gate")
	case <-time.After(20 * time.Millisecond):
	}
	select {
	case unlock := <-otherFrontend:
		unlock()
	case <-time.After(time.Second):
		t.Fatal("unrelated frontend handle was globally serialized")
	}
	firstFrontend()
	select {
	case unlock := <-sameFrontend:
		unlock()
	case <-time.After(time.Second):
		t.Fatal("same-handle frontend request did not resume")
	}

	firstConcrete := a.lockHandleOperation(1, false)
	secondConcrete := a.lockHandleOperation(1, false)
	secondConcrete()
	sameConcrete := make(chan func(), 1)
	otherConcrete := make(chan func(), 1)
	go func() { sameConcrete <- a.lockHandleOperation(1, true) }()
	go func() { otherConcrete <- a.lockHandleOperation(2, true) }()
	select {
	case unlock := <-sameConcrete:
		unlock()
		t.Fatal("same-handle concrete operation crossed descriptor gate")
	case <-time.After(20 * time.Millisecond):
	}
	select {
	case unlock := <-otherConcrete:
		unlock()
	case <-time.After(time.Second):
		t.Fatal("unrelated concrete handle was globally serialized")
	}
	firstConcrete()
	select {
	case unlock := <-sameConcrete:
		unlock()
	case <-time.After(time.Second):
		t.Fatal("same-handle concrete operation did not resume")
	}
}

// newScopeTestAttach builds a bare registry with the bindings the publication
// scope derivation reads. It deliberately avoids newAttach: these tests
// exercise frontendOperationPaths and the frontend gate only.
func newScopeTestAttach() *attach {
	return &attach{
		items:       map[uint64]*itemRecord{},
		paths:       map[string]*itemRecord{},
		itemAliases: map[uint64]map[string]struct{}{},
		handles:     map[uint64]*handleRecord{},
	}
}

func (a *attach) bindScopeTestItem(id uint64, p string) pfslocal.Item {
	item := pfslocal.Item{ItemID: id, ItemGeneration: 1}
	rec := &itemRecord{item: item, path: p, state: clientcore.NewNodeState(id, true)}
	if a.items[id] == nil {
		a.items[id] = rec
	}
	a.paths[p] = rec
	a.addItemAliasLocked(rec)
	return item
}

func scopeSet(paths []string) map[string]bool {
	got := map[string]bool{}
	for _, p := range paths {
		got[p] = true
	}
	return got
}

// Rename and remove publish two names each (and every alias of whatever they
// displace); the concrete lookup/enumerate scopes must not have regressed
// those multi-name derivations.
func TestRenameAndRemovePublicationScopesCoverEveryName(t *testing.T) {
	a := newScopeTestAttach()
	from := a.bindScopeTestItem(2, "from")
	to := a.bindScopeTestItem(3, "to")
	a.bindScopeTestItem(7, "from/a")
	alias := &itemRecord{item: a.items[7].item, path: "other/b", state: a.items[7].state}
	a.paths[alias.path] = alias
	a.addItemAliasLocked(alias)

	paths, _, _ := a.frontendOperationPaths(&pfslocal.RenameRequest{
		FromDir: from, FromName: []byte("a"), ToDir: to, ToName: []byte("b"),
	})
	got := scopeSet(paths)
	for _, want := range []string{"from", "from/a", "to", "to/b", "other/b"} {
		if !got[want] {
			t.Fatalf("rename publication paths = %v, missing %q", paths, want)
		}
	}

	paths, _, _ = a.frontendOperationPaths(&pfslocal.RemoveRequest{
		Dir: from, Name: []byte("a"),
	})
	got = scopeSet(paths)
	for _, want := range []string{"from", "from/a", "other/b"} {
		if !got[want] {
			t.Fatalf("remove publication paths = %v, missing %q", paths, want)
		}
	}
}

// The gate consequence of the concrete scopes: a handoff for one subtree no
// longer waits behind a lookup or enumerate in a disjoint subtree, and still
// waits behind one that overlaps.

// Lookup and Enumerate publish per-inode attributes through per-path
// delegations, and a hard link can alias an inode under a scope whose
// handoff has already passed the gate — a passed handoff cannot be
// re-blocked, so these two read publishers stay mount-wide until an
// inode-identity gate exists (liveness follow-up item 2).
func TestLookupAndEnumeratePublicationScopesStayMountWide(t *testing.T) {
	a := newScopeTestAttach()
	root := a.bindScopeTestItem(1, "")
	dir := a.bindScopeTestItem(2, "d")
	a.bindScopeTestItem(3, "d/f")
	_ = root
	for _, body := range []any{
		&pfslocal.LookupRequest{Dir: dir, Name: []byte("f")},
		&pfslocal.EnumerateRequest{Dir: dir},
	} {
		paths, _, known := a.frontendOperationPaths(body)
		if !known || len(paths) != 1 || paths[0] != "" {
			t.Fatalf("%T publication paths = %v (known=%v), want mount-wide", body, paths, known)
		}
	}
}
