//go:build linux

package fusev3

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

type gateMutationResult struct {
	response *authoritypb.Response
	err      error
}

// startGateMutation exercises the same source-publication acquisition and
// physical-reply release edges as a raw callback, while leaving operation-
// specific response validation out of scheduling tests.
func startGateMutation(t *testing.T, fixture *strictFixture, request *authoritypb.Request, gate *sourcePublicationGate) <-chan gateMutationResult {
	t.Helper()
	unique := fixture.unique.Add(2)
	ctx, finish, status := fixture.raw.mutationContext(unique)
	if !status.Ok() {
		t.Fatalf("reserve mutation publication: %v", status)
	}
	result := make(chan gateMutationResult, 1)
	go func() {
		response, err := fixture.mount.callMutation(ctx, request, gate)
		if err == nil {
			lease := sourceLeaseFromContext(ctx)
			lease.resolveAllNoBinding()
			err = completeSourcePublication(ctx)
		}
		finish()
		if fixture.raw.ReplyWriteTracked(unique) {
			fixture.raw.ReplyWritten(unique, fuse.OK)
		}
		result <- gateMutationResult{response: response, err: err}
	}()
	return result
}

func awaitGateMutation(t *testing.T, result <-chan gateMutationResult) *authoritypb.Response {
	t.Helper()
	select {
	case completed := <-result:
		if completed.err != nil {
			t.Fatalf("gated mutation: %v", completed.err)
		}
		return completed.response
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for gated mutation")
		return nil
	}
}

func createGateRequest(parent *authoritypb.Item, name string) (*authoritypb.Request, *sourcePublicationGate, error) {
	gate, err := namespaceSourceGate(parent, name, false)
	if err != nil {
		return nil, nil, err
	}
	return &authoritypb.Request{Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{
		Parent: cloneBytes(parent.GetToken()), Name: []byte(name), Mode: 0o600,
		Flags: &authoritypb.OpenFlags{Write: true}, Exclusive: true,
	}}}, gate, nil
}

func writeGateRequest(item *authoritypb.Item, marker byte) (*authoritypb.Request, *sourcePublicationGate, error) {
	gate, err := itemSourceGate(item, true)
	if err != nil {
		return nil, nil, err
	}
	return &authoritypb.Request{Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{
		Handle: []byte{marker}, Size: 1, Data: []byte{marker},
	}}}, gate, nil
}

func installAuthorityHook(fixture *strictFixture, hook func(*authoritypb.Request)) {
	fixture.rpc.mu.Lock()
	fixture.rpc.hook = hook
	fixture.rpc.mu.Unlock()
}

func finishDirectSourceLease(t *testing.T, lease *sourcePublicationLease, resolveNames bool) {
	t.Helper()
	if err := lease.markAssigned(); err != nil {
		t.Fatal(err)
	}
	if resolveNames {
		lease.resolveAllNoBinding()
	}
	if err := lease.markCallbackPublicationReady(); err != nil {
		t.Fatal(err)
	}
	lease.release()
}

func TestDistinctDirectoryCreatesReachAuthorityConcurrently(t *testing.T) {
	fixture := newStrictFixture(t)
	firstParent := testItem(101, authoritypb.Attr_DIRECTORY, 101)
	secondParent := testItem(102, authoritypb.Attr_DIRECTORY, 102)
	firstRequest, firstGate, err := createGateRequest(firstParent, "first")
	if err != nil {
		t.Fatal(err)
	}
	secondRequest, secondGate, err := createGateRequest(secondParent, "second")
	if err != nil {
		t.Fatal(err)
	}

	firstEntered := make(chan struct{})
	secondEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	installAuthorityHook(fixture, func(request *authoritypb.Request) {
		create := request.GetCreate()
		if create == nil {
			return
		}
		switch string(create.GetName()) {
		case "first":
			close(firstEntered)
			<-releaseFirst
		case "second":
			close(secondEntered)
		}
	})

	firstResult := startGateMutation(t, fixture, firstRequest, firstGate)
	select {
	case <-firstEntered:
	case <-time.After(time.Second):
		t.Fatal("first create did not reach the authority")
	}
	secondResult := startGateMutation(t, fixture, secondRequest, secondGate)
	select {
	case <-secondEntered:
		// The first authority call is still waiting for releaseFirst.
	case <-time.After(time.Second):
		close(releaseFirst)
		t.Fatal("create in a distinct directory did not reach the authority concurrently")
	}
	close(releaseFirst)
	awaitGateMutation(t, firstResult)
	awaitGateMutation(t, secondResult)
}

func TestUnrelatedWriteReachesAuthorityWhileCreatePending(t *testing.T) {
	fixture := newStrictFixture(t)
	parent := testItem(103, authoritypb.Attr_DIRECTORY, 103)
	unrelated := testItem(104, authoritypb.Attr_REGULAR, 104)
	createRequest, createGate, err := createGateRequest(parent, "created")
	if err != nil {
		t.Fatal(err)
	}
	writeRequest, writeGate, err := writeGateRequest(unrelated, 1)
	if err != nil {
		t.Fatal(err)
	}

	createEntered := make(chan struct{})
	writeEntered := make(chan struct{})
	releaseCreate := make(chan struct{})
	installAuthorityHook(fixture, func(request *authoritypb.Request) {
		switch {
		case request.GetCreate() != nil:
			close(createEntered)
			<-releaseCreate
		case request.GetWrite() != nil:
			close(writeEntered)
		}
	})

	createResult := startGateMutation(t, fixture, createRequest, createGate)
	select {
	case <-createEntered:
	case <-time.After(time.Second):
		t.Fatal("create did not reach the authority")
	}
	writeResult := startGateMutation(t, fixture, writeRequest, writeGate)
	select {
	case <-writeEntered:
		// The create reply remains held by releaseCreate.
	case <-time.After(time.Second):
		close(releaseCreate)
		t.Fatal("write to an unrelated identity did not reach the authority concurrently")
	}
	close(releaseCreate)
	awaitGateMutation(t, createResult)
	awaitGateMutation(t, writeResult)
}

func TestSameIdentityWritesSerializeAtSourcePublicationGate(t *testing.T) {
	fixture := newStrictFixture(t)
	item := testItem(105, authoritypb.Attr_REGULAR, 105)
	firstRequest, firstGate, err := writeGateRequest(item, 1)
	if err != nil {
		t.Fatal(err)
	}
	secondRequest, secondGate, err := writeGateRequest(item, 2)
	if err != nil {
		t.Fatal(err)
	}

	firstEntered := make(chan struct{})
	secondEntered := make(chan struct{})
	releaseFirst := make(chan struct{})
	installAuthorityHook(fixture, func(request *authoritypb.Request) {
		write := request.GetWrite()
		if write == nil {
			return
		}
		switch write.GetData()[0] {
		case 1:
			close(firstEntered)
			<-releaseFirst
		case 2:
			close(secondEntered)
		}
	})

	firstResult := startGateMutation(t, fixture, firstRequest, firstGate)
	select {
	case <-firstEntered:
	case <-time.After(time.Second):
		t.Fatal("first write did not reach the authority")
	}
	secondResult := startGateMutation(t, fixture, secondRequest, secondGate)
	select {
	case <-secondEntered:
		close(releaseFirst)
		t.Fatal("second write reached the authority across the first identity gate")
	case <-time.After(25 * time.Millisecond):
	}
	close(releaseFirst)
	awaitGateMutation(t, firstResult)
	select {
	case <-secondEntered:
	case <-time.After(time.Second):
		t.Fatal("second write did not reach the authority after the first reply was published")
	}
	awaitGateMutation(t, secondResult)
}

func TestCreateAndWriteOnKnownIdentitySerialize(t *testing.T) {
	fixture := newStrictFixture(t)
	parent := testItem(106, authoritypb.Attr_DIRECTORY, 106)
	child := testItem(107, authoritypb.Attr_REGULAR, 107)
	record, errno := fixture.raw.intern(context.Background(), child)
	if errno != 0 {
		t.Fatal(errno)
	}
	parentIdentity, ok := publicationIdentityFromItem(parent)
	if !ok {
		t.Fatal("parent identity")
	}
	fixture.raw.mu.Lock()
	fixture.raw.cachedStableNames[publicationNamespace{parent: parentIdentity, name: "known"}] = record
	fixture.raw.mu.Unlock()

	createRequest, createGate, err := createGateRequest(parent, "known")
	if err != nil {
		t.Fatal(err)
	}
	writeRequest, writeGate, err := writeGateRequest(child, 3)
	if err != nil {
		t.Fatal(err)
	}
	createEntered := make(chan struct{})
	writeEntered := make(chan struct{})
	releaseCreate := make(chan struct{})
	installAuthorityHook(fixture, func(request *authoritypb.Request) {
		switch {
		case request.GetCreate() != nil:
			close(createEntered)
			<-releaseCreate
		case request.GetWrite() != nil:
			close(writeEntered)
		}
	})

	createResult := startGateMutation(t, fixture, createRequest, createGate)
	select {
	case <-createEntered:
	case <-time.After(time.Second):
		t.Fatal("create did not reach the authority")
	}
	writeResult := startGateMutation(t, fixture, writeRequest, writeGate)
	select {
	case <-writeEntered:
		close(releaseCreate)
		t.Fatal("write reached the authority across the create's known child identity gate")
	case <-time.After(25 * time.Millisecond):
	}
	close(releaseCreate)
	awaitGateMutation(t, createResult)
	select {
	case <-writeEntered:
	case <-time.After(time.Second):
		t.Fatal("write did not reach the authority after the create reply was published")
	}
	awaitGateMutation(t, writeResult)
}

func TestCreateReplyBindingDrainsOnlyExactIdentityPublications(t *testing.T) {
	for _, test := range []struct {
		name       string
		publishing publicationIdentity
		blocks     bool
	}{
		{name: "exact child", publishing: publicationIdentity(testIdentity(109)), blocks: true},
		{name: "unrelated child", publishing: publicationIdentity(testIdentity(110)), blocks: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newStrictFixture(t)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			parent := testItem(108, authoritypb.Attr_DIRECTORY, 108)
			gate, err := namespaceSourceGate(parent, "created", false)
			if err != nil {
				t.Fatal(err)
			}
			coordinate := publicationCoordinate{kind: publicationItemAttributes, item: test.publishing}
			fixture.raw.mu.Lock()
			fixture.raw.admitSourcePublicationLocked(coordinate)
			fixture.raw.mu.Unlock()
			publishing := true
			defer func() {
				if !publishing {
					return
				}
				fixture.raw.mu.Lock()
				fixture.raw.settleSourcePublicationLocked(coordinate)
				fixture.raw.mu.Unlock()
			}()

			lease, err := fixture.raw.acquireSourcePublication(ctx, gate)
			if err != nil {
				t.Fatal(err)
			}
			if err := lease.markAssigned(); err != nil {
				t.Fatal(err)
			}
			parentIdentity, _ := publicationIdentityFromItem(parent)
			namespace := publicationNamespace{parent: parentIdentity, name: "created"}
			child := publicationIdentity(testIdentity(109))
			attached := make(chan error, 1)
			go func() {
				attached <- lease.attachBinding(ctx, namespace, child)
			}()

			if test.blocks {
				waitFor(t, "reply binding to own the exact child coordinate", func() bool {
					fixture.raw.mu.Lock()
					defer fixture.raw.mu.Unlock()
					return fixture.raw.sourceHolds[publicationCoordinate{kind: publicationItemAttributes, item: child}] == lease &&
						lease.unresolvedAttributes == 0
				})
				select {
				case err := <-attached:
					t.Fatalf("exact child binding crossed its in-flight cache publication: %v", err)
				default:
				}
			} else {
				select {
				case err := <-attached:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("unrelated cache publication blocked definitive create binding")
				}
			}

			fixture.raw.mu.Lock()
			fixture.raw.settleSourcePublicationLocked(coordinate)
			fixture.raw.mu.Unlock()
			publishing = false
			if test.blocks {
				select {
				case err := <-attached:
					if err != nil {
						t.Fatal(err)
					}
				case <-time.After(time.Second):
					t.Fatal("create binding did not resume after exact cache publication drained")
				}
			}
			if err := lease.markCallbackPublicationReady(); err != nil {
				t.Fatal(err)
			}
			lease.release()
		})
	}
}

func TestUnresolvedCreateIgnoresUnrelatedRecallAndAllowsUnrelatedPublication(t *testing.T) {
	fixture := newStrictFixture(t)
	parent := testItem(111, authoritypb.Attr_DIRECTORY, 111)
	gate, err := namespaceSourceGate(parent, "created", false)
	if err != nil {
		t.Fatal(err)
	}
	unrelated := publicationCoordinate{kind: publicationItemAttributes, item: publicationIdentity(testIdentity(112))}
	if err := fixture.raw.closeCacheCoordinate(context.Background(), unrelated); err != nil {
		t.Fatal(err)
	}
	defer fixture.raw.openCacheCoordinate(unrelated)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	lease, err := fixture.raw.acquireSourcePublication(ctx, gate)
	if err != nil {
		t.Fatalf("unresolved create waited for unrelated recall: %v", err)
	}
	parentIdentity, _ := publicationIdentityFromItem(parent)
	parentCoordinate := publicationCoordinate{kind: publicationItemAttributes, item: parentIdentity}
	fixture.raw.mu.Lock()
	unrelatedAllowed := fixture.raw.sourcePublicationAllowedLocked(unrelated, nil)
	parentAllowed := fixture.raw.sourcePublicationAllowedLocked(parentCoordinate, nil)
	ownerAllowed := fixture.raw.sourcePublicationAllowedLocked(parentCoordinate, lease)
	fixture.raw.mu.Unlock()
	if !unrelatedAllowed {
		t.Fatal("unresolved create suppressed publication on an unrelated identity")
	}
	if parentAllowed || !ownerAllowed {
		t.Fatalf("exact parent publication admission = foreign %t owner %t, want false/true", parentAllowed, ownerAllowed)
	}
	finishDirectSourceLease(t, lease, true)
}

func TestReplyDiscoveredCoordinateCoOwnershipSurvivesEitherReleaseOrder(t *testing.T) {
	for _, releaseReplyFirst := range []bool{false, true} {
		t.Run(fmt.Sprintf("release_reply_first=%t", releaseReplyFirst), func(t *testing.T) {
			fixture := newStrictFixture(t)
			parent := testItem(113, authoritypb.Attr_DIRECTORY, 113)
			child := testItem(114, authoritypb.Attr_REGULAR, 114)
			childIdentity, _ := publicationIdentityFromItem(child)
			coordinate := publicationCoordinate{kind: publicationItemAttributes, item: childIdentity}
			childGate, err := itemSourceGate(child, false)
			if err != nil {
				t.Fatal(err)
			}
			childLease, err := fixture.raw.acquireSourcePublication(context.Background(), childGate)
			if err != nil {
				t.Fatal(err)
			}
			if err := childLease.markAssigned(); err != nil {
				t.Fatal(err)
			}
			createGate, err := namespaceSourceGate(parent, "created", false)
			if err != nil {
				t.Fatal(err)
			}
			replyLease, err := fixture.raw.acquireSourcePublication(context.Background(), createGate)
			if err != nil {
				t.Fatal(err)
			}
			if err := replyLease.markAssigned(); err != nil {
				t.Fatal(err)
			}
			if err := replyLease.attachCoordinates(map[publicationCoordinate]struct{}{coordinate: {}}); err != nil {
				t.Fatalf("co-own reply-discovered coordinate: %v", err)
			}
			fixture.raw.mu.Lock()
			allowedForeign := fixture.raw.sourcePublicationAllowedLocked(coordinate, nil)
			allowedChildOwner := fixture.raw.sourcePublicationAllowedLocked(coordinate, childLease)
			allowedReplyOwner := fixture.raw.sourcePublicationAllowedLocked(coordinate, replyLease)
			fixture.raw.mu.Unlock()
			if allowedForeign || allowedChildOwner || allowedReplyOwner {
				t.Fatalf("co-owned publication admission = foreign %t child %t reply %t, want all false", allowedForeign, allowedChildOwner, allowedReplyOwner)
			}

			releaseChild := func() {
				if err := childLease.markCallbackPublicationReady(); err != nil {
					t.Fatal(err)
				}
				childLease.release()
			}
			releaseReply := func() {
				replyLease.resolveAllNoBinding()
				if err := replyLease.markCallbackPublicationReady(); err != nil {
					t.Fatal(err)
				}
				replyLease.release()
			}
			if releaseReplyFirst {
				releaseReply()
			} else {
				releaseChild()
			}
			fixture.raw.mu.Lock()
			allowedAfterOneRelease := fixture.raw.sourcePublicationAllowedLocked(coordinate, nil)
			fixture.raw.mu.Unlock()
			if allowedAfterOneRelease {
				t.Fatal("first co-owner release reopened the coordinate")
			}
			if releaseReplyFirst {
				releaseChild()
			} else {
				releaseReply()
			}
			fixture.raw.mu.Lock()
			allowedAfterBothRelease := fixture.raw.sourcePublicationAllowedLocked(coordinate, nil)
			fixture.raw.mu.Unlock()
			if !allowedAfterBothRelease {
				t.Fatal("final co-owner release left the coordinate closed")
			}
		})
	}
}

func TestSourceDischargeBindsUnknownChildBeforePurging(t *testing.T) {
	fixture := newStrictFixture(t)
	parent := testItem(115, authoritypb.Attr_DIRECTORY, 115)
	child := testItem(116, authoritypb.Attr_REGULAR, 116)
	childIdentity, _ := publicationIdentityFromItem(child)
	coordinate := publicationCoordinate{kind: publicationItemAttributes, item: childIdentity}
	done := make(chan struct{})
	fixture.raw.mu.Lock()
	fixture.raw.replyPublications[41] = &replyPublication{attrs: []replyAttrPublication{{coordinate: coordinate}}, originalFinalized: true, originalDone: done}
	fixture.raw.sourcePublishing[coordinate] = 1
	fixture.raw.mu.Unlock()
	gate, err := namespaceSourceGate(parent, "created", false)
	if err != nil {
		t.Fatal(err)
	}
	lease, err := fixture.raw.acquireSourcePublication(context.Background(), gate)
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.markAssigned(); err != nil {
		t.Fatal(err)
	}
	attached := make(chan error, 1)
	go func() {
		attached <- lease.attachBinding(context.Background(), publicationNamespace{parent: publicationIdentity(testIdentity(115)), name: "created"}, childIdentity)
	}()
	select {
	case err := <-attached:
		t.Fatalf("reply-discovered identity crossed its staged cache reply: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(done)
	fixture.raw.mu.Lock()
	delete(fixture.raw.sourcePublishing, coordinate)
	fixture.raw.signalSourceChangedLocked()
	fixture.raw.mu.Unlock()
	select {
	case err := <-attached:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("reply-discovered identity did not resume after exact reply drain")
	}
	if err := lease.markCallbackPublicationReady(); err != nil {
		t.Fatal(err)
	}
	lease.release()
}

func TestSourceDischargeDoesNotWaitForExistingExactSourceGate(t *testing.T) {
	fixture := newStrictFixture(t)
	child := testItem(118, authoritypb.Attr_REGULAR, 118)
	childIdentity, _ := publicationIdentityFromItem(child)
	coordinate := publicationCoordinate{kind: publicationItemAttributes, item: childIdentity}
	childGate, err := itemSourceGate(child, false)
	if err != nil {
		t.Fatal(err)
	}
	childLease, err := fixture.raw.acquireSourcePublication(context.Background(), childGate)
	if err != nil {
		t.Fatal(err)
	}
	if err := childLease.markAssigned(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := fixture.raw.closeCacheCoordinate(ctx, coordinate); err != nil {
		t.Fatalf("subscription withdrawal waited for an existing source gate: %v", err)
	}
	fixture.raw.openCacheCoordinate(coordinate)
	fixture.raw.mu.Lock()
	openedEarly := fixture.raw.sourcePublicationAllowedLocked(coordinate, nil)
	fixture.raw.mu.Unlock()
	if openedEarly {
		t.Fatal("cache withdrawal reopened a coordinate held by the exact source request")
	}
	if err := childLease.markCallbackPublicationReady(); err != nil {
		t.Fatal(err)
	}
	childLease.release()
	fixture.raw.mu.Lock()
	opened := fixture.raw.sourcePublicationAllowedLocked(coordinate, nil)
	fixture.raw.mu.Unlock()
	if !opened {
		t.Fatal("final exact source release left the coordinate closed")
	}
}

func BenchmarkSourcePublicationAdmissionWithUnrelatedCoordinates(b *testing.B) {
	for _, unrelated := range []int{0, 4096} {
		b.Run(fmt.Sprintf("unrelated=%d", unrelated), func(b *testing.B) {
			rpc := newFakeRPC()
			mount := newMount(context.Background(), rpc, testConfig(8))
			b.Cleanup(mount.cancel)
			parent := testItem(200, authoritypb.Attr_DIRECTORY, 200)
			root := &node{mount: mount, item: parent, requestTimeout: time.Second, maxRead: 64 * 1024, maxWrite: 64 * 1024}
			raw := newRawFileSystem(mount, root)
			gate, err := namespaceSourceGate(parent, "bench", false)
			if err != nil {
				b.Fatal(err)
			}
			raw.mu.Lock()
			for index := 0; index < unrelated; index++ {
				identity := publicationIdentity(testIdentity(uint64(1000 + index)))
				raw.sourcePublishing[publicationCoordinate{kind: publicationItemAttributes, item: identity}] = 1
				raw.sourceHolds[publicationCoordinate{kind: publicationItemData, item: identity}] = &sourcePublicationLease{}
			}
			raw.mu.Unlock()

			b.ReportAllocs()
			b.ResetTimer()
			for iteration := 0; iteration < b.N; iteration++ {
				lease, err := raw.acquireSourcePublication(context.Background(), gate)
				if err != nil {
					b.Fatal(err)
				}
				if err := lease.markAssigned(); err != nil {
					b.Fatal(err)
				}
				lease.resolveAllNoBinding()
				if err := lease.markCallbackPublicationReady(); err != nil {
					b.Fatal(err)
				}
				lease.release()
			}
		})
	}
}

func TestSourceCompletionWithdrawsSettledAttributesAndKeepsDataObligation(t *testing.T) {
	for _, kind := range []publicationCoordinateKind{publicationItemAttributes, publicationItemData} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			f := newStrictFixture(t)
			entry := f.lookup(t, 1, "file")
			record := f.raw.acquire(entry.NodeId)
			defer f.raw.release(record)
			coordinate := publicationCoordinate{kind: kind, item: record.identity}
			lease := &sourcePublicationLease{r: f.raw, assigned: true, coordinates: map[publicationCoordinate]struct{}{coordinate: {}}}
			f.raw.mu.Lock()
			f.raw.cachedAttrs[record.identity] = record
			f.raw.cachedAttrPayloads[record.identity] = cachedAttrPayload{attr: &authoritypb.Attr{Nlink: 2}}
			f.raw.cachedData[record.key.inode] = record
			f.raw.mu.Unlock()
			if err := lease.markCallbackPublicationReady(); err != nil {
				t.Fatal(err)
			}
			f.raw.mu.Lock()
			defer f.raw.mu.Unlock()
			if f.raw.cachedAttrs[record.identity] != nil || f.raw.cachedAttrPayloads[record.identity].attr != nil {
				t.Fatal("source completion retained stale link-count payload")
			}
			if f.raw.cachedData[record.key.inode] != record {
				t.Fatal("source completion discarded kernel data obligation")
			}
		})
	}
}

func TestSourceChangedChannelIsDemandAllocated(t *testing.T) {
	f := newStrictFixture(t)
	r := f.raw
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sourceChanged != nil {
		t.Fatal("uncontended setup allocated a wake channel")
	}
	for range 100 {
		r.signalSourceChangedLocked()
	}
	if r.sourceChanged != nil {
		t.Fatal("signals without waiters allocated a wake channel")
	}
	first := r.sourceChangedWaitLocked()
	if second := r.sourceChangedWaitLocked(); second != first {
		t.Fatal("waiters did not share a wake channel")
	}
	r.signalSourceChangedLocked()
	select {
	case <-first:
	default:
		t.Fatal("signal did not wake waiters")
	}
	if r.sourceChanged != nil {
		t.Fatal("signal retained a closed channel")
	}
	if next := r.sourceChangedWaitLocked(); next == first {
		t.Fatal("next waiter received the previous closed channel")
	}
}

func TestNamespaceSourceGateCoversEveryEmittedChangeKind(t *testing.T) {
	seen := make(map[volumeserver.ChangeKind]bool)
	for _, truncate := range []bool{false, true} {
		t.Run(fmt.Sprintf("truncate=%t", truncate), func(t *testing.T) {
			f := newStrictFixture(t)
			entry := f.lookup(t, 1, "file")
			child := f.raw.acquire(entry.NodeId)
			parent := f.raw.acquire(1)
			defer f.raw.release(child)
			defer f.raw.release(parent)
			name := publicationNamespace{parent: parent.identity, name: "new-link"}
			if truncate {
				name.name = "file"
			}
			gate, err := namespaceSourceGate(parent.node.item, name.name, truncate, child.node.item)
			if err != nil {
				t.Fatal(err)
			}
			lease, err := f.raw.acquireSourcePublication(t.Context(), gate)
			if err != nil {
				t.Fatal(err)
			}
			defer lease.release()
			if err := lease.markAssigned(); err != nil {
				t.Fatal(err)
			}
			if err := lease.attachBinding(t.Context(), name, child.identity); err != nil {
				t.Fatal(err)
			}
			coordinates := map[volumeserver.ChangeKind][]publicationCoordinate{
				volumeserver.NamespaceChanged:  {{kind: publicationNamespaceName, parent: parent.identity, name: name.name}},
				volumeserver.DirectoryChanged:  {{kind: publicationItemEnumeration, item: parent.identity}},
				volumeserver.AttributesChanged: {{kind: publicationItemAttributes, item: parent.identity}, {kind: publicationItemAttributes, item: child.identity}},
			}
			if truncate {
				coordinates[volumeserver.DataChanged] = []publicationCoordinate{{kind: publicationItemData, item: child.identity}}
			}
			dir := &dirHandle{node: parent.node, page: []*authoritypb.Dirent{{Name: []byte("old")}}, eof: true}
			f.raw.mu.Lock()
			f.raw.handles[999] = &handleRecord{inode: parent, dir: dir}
			for _, record := range []*inodeRecord{parent, child} {
				f.raw.cachedAttrs[record.identity] = record
				f.raw.cachedAttrPayloads[record.identity] = cachedAttrPayload{attr: &authoritypb.Attr{Nlink: 1}}
			}
			f.raw.cachedData[child.key.inode] = child
			for kind, targets := range coordinates {
				seen[kind] = true
				for _, target := range targets {
					if _, ok := lease.coordinates[target]; !ok || f.raw.sourceHolds[target] != lease || f.raw.sourcePublicationAllowedLocked(target, nil) {
						t.Errorf("kind %v coordinate %+v is not closed by source gate", kind, target)
					}
				}
			}
			f.raw.mu.Unlock()
			if err := lease.markCallbackPublicationReady(); err != nil {
				t.Fatal(err)
			}
			dir.mu.Lock()
			if len(dir.page) != 0 || dir.eof || dir.cursorGeneration != 1 {
				t.Errorf("source enumeration retained page/EOF: page=%v eof=%v generation=%d", dir.page, dir.eof, dir.cursorGeneration)
			}
			dir.mu.Unlock()
			f.raw.mu.Lock()
			for _, record := range []*inodeRecord{parent, child} {
				if f.raw.cachedAttrs[record.identity] != nil || f.raw.cachedAttrPayloads[record.identity].attr != nil {
					t.Error("source retained stale attributes/link count")
				}
			}
			if f.raw.cachedData[child.key.inode] != child {
				t.Error("source forgot kernel data obligation")
			}
			f.raw.mu.Unlock()
			lease.release()
			f.raw.mu.Lock()
			for _, targets := range coordinates {
				for _, target := range targets {
					if !f.raw.sourcePublicationAllowedLocked(target, nil) {
						t.Errorf("coordinate %+v did not reopen", target)
					}
				}
			}
			delete(f.raw.handles, 999)
			f.raw.mu.Unlock()
		})
	}
	if len(seen) != 4 {
		t.Fatalf("namespace change inventory = %v", seen)
	}
}
