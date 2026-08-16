//go:build linux

package authorityrpc

import (
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/errnos"
	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

// emptyRoutesRevision is the revision of a volume with no declaration. "No
// routing configured" is a value every mount has to agree with, not a case that
// skips the check, so it has a digest like any other rule set.
func emptyRoutesRevision() []byte {
	empty, err := localroutes.Parse(nil)
	if err != nil {
		panic(err)
	}
	revision := empty.Revision()
	return append([]byte(nil), revision[:]...)
}

// testRoutesController builds a controller over a real volume, for the
// privileged end-to-end test.
func testRoutesController(t *testing.T, store *xfsstore.Volume) *RoutesController {
	return testRoutesControllerWithFencer(t, store, noopFencer{})
}

func testRoutesControllerWithFencer(t *testing.T, store *xfsstore.Volume, fencer volumeserver.SessionFencer) *RoutesController {
	t.Helper()
	visibility, err := volumeserver.NewVisibilityCoordinator(volumeserver.VisibilityConfig{
		Prior: volumeserver.PriorEpochStrictMountsFenced, Membership: noopMembership{}, Fencer: fencer,
		MaxCachedNameCapacity: 1 << 16, MaxRepairBudget: time.Minute, MaxClockSkew: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	locks := volumeserver.NewLockTable(1024, 1024, time.Now)
	if authority, ok := fencer.(*volumeserver.Authority); ok {
		locks = authority.Locks()
	}
	routes, err := NewRoutesController(store, visibility, locks)
	if err != nil {
		t.Fatal(err)
	}
	if err := routes.Load(); err != nil {
		t.Fatal(err)
	}
	return routes
}

type noopMembership struct{}

func (noopMembership) Activate(volumeserver.SessionID) error   { return nil }
func (noopMembership) Deactivate(volumeserver.SessionID) error { return nil }

type noopFencer struct{}

func (noopFencer) FenceSession(volumeserver.SessionID) {}

func TestRouteLockWaitAdmissionCannotSlipPastTransition(t *testing.T) {
	id := volumeserver.SessionID{1}
	locks := volumeserver.NewLockTable(16, 16, time.Now)
	locks.RegisterSession(id, time.Now().Add(time.Hour))
	routes := &RoutesController{Locks: locks}
	routes.lockWaitAdmission.Lock()

	active := true
	started := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		close(started)
		_, err := routes.beginLockWait(func() error {
			if !active {
				return volumeserver.ErrSessionExpired
			}
			return nil
		}, volumeserver.Lock{
			Object: volumeserver.ObjectKey{1},
			Owner:  volumeserver.LockOwner{Session: id},
			Type:   volumeserver.LockWrite,
			Range:  volumeserver.ToEOF(0),
		})
		done <- err
	}()
	<-started
	select {
	case err := <-done:
		t.Fatalf("wait admission crossed a held topology writer: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	// Apply changes the authoritative revision while it owns the writer. The
	// queued admission can run only afterwards and must see the new verdict.
	active = false
	locks.InterruptWaiters(volumeserver.ErrSessionExpired)
	routes.lockWaitAdmission.Unlock()
	select {
	case err := <-done:
		if !errors.Is(err, volumeserver.ErrSessionExpired) {
			t.Fatalf("post-transition lock admission = %v, want ErrSessionExpired", err)
		}
	case <-time.After(time.Second):
		t.Fatal("post-transition lock admission remained blocked")
	}
}

// loadedRoutes is a controller whose active revision is set directly. Every
// check below runs before any storage access - a routing disagreement is
// decided from two digests - so the tests that exercise those checks give the
// handler a store it provably never reaches rather than a provisioned XFS
// volume they do not need.
func loadedRoutes(rules string) *RoutesController {
	parsed, err := localroutes.Parse([]byte(rules))
	if err != nil {
		panic(err)
	}
	visibility, err := volumeserver.NewVisibilityCoordinator(volumeserver.VisibilityConfig{
		Prior: volumeserver.PriorEpochStrictMountsFenced, Membership: noopMembership{}, Fencer: noopFencer{},
		MaxCachedNameCapacity: 1 << 16, MaxRepairBudget: time.Minute, MaxClockSkew: time.Second,
	})
	if err != nil {
		panic(err)
	}
	return &RoutesController{Visibility: visibility, loaded: true, revision: parsed.Revision(), canonical: parsed.Canonical()}
}

func routesRevisionOf(rules string) [32]byte {
	parsed, err := localroutes.Parse([]byte(rules))
	if err != nil {
		panic(err)
	}
	return parsed.Revision()
}

// A refusal reaches a mount as an errno, and an errno cannot say which two
// configurations disagreed. The operator is holding two files and needs to know
// which one to edit, so both revisions travel with the refusal.
func TestAttachWithAMismatchedRoutingRevisionNamesBothRevisions(t *testing.T) {
	active := routesRevisionOf("node_modules\n")
	mount := routesRevisionOf("target\n")
	h := testVolumeHandler()
	h.Store = &resourceAdmissionFaultStore{}
	h.Authorizer = allowAuthorizer{volumeserver.AccessRead | volumeserver.AccessWrite}
	h.Routes = loadedRoutes("node_modules\n")
	h.Visibility = h.Routes.Visibility
	runtime, err := volumeserver.New("routes-volume", volumeserver.Config{
		SessionLease: time.Minute, MaxReplaySlots: 4, MaxSessions: 4, MaxLockRecords: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.Runtime = runtime
	ctx := context.WithValue(context.Background(), peerIdentityKey{}, [32]byte{1})

	for _, test := range []struct {
		name      string
		revision  []byte
		presented bool
	}{
		{"a different topology", append([]byte(nil), mount[:]...), true},
		{"no topology at all", nil, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := h.Handle(ctx, &authoritypb.Request{RequestId: 1, Body: &authoritypb.Request_Attach{
				Attach: &authoritypb.AttachRequest{
					VolumeId: "routes-volume", AccessToken: []byte("test-only"), ReplaySlots: 2,
					RoutesRevision: test.revision, AttachAttemptId: testAttachAttempt(1),
					CoherenceProfile:   authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT,
					CachedNameCapacity: 1024, RepairBudgetMillis: 1000,
					NamespaceRepair: authoritypb.NamespaceRepair_NAMESPACE_REPAIR_PARENT_EXCLUSIVE,
				}}})
			if response.GetAttach() != nil {
				t.Fatal("a mount running another topology was admitted")
			}
			if response.GetErrno() != errnos.EPERM {
				t.Fatalf("errno = %d, want EPERM", response.GetErrno())
			}
			if response.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_ROUTES {
				t.Fatalf("failure class = %v, want ROUTES", response.GetFailure())
			}
			mismatch := response.GetRoutesMismatch()
			if mismatch == nil {
				t.Fatal("the refusal carried no routing mismatch")
			}
			if hex.EncodeToString(mismatch.GetActiveRevision()) != hex.EncodeToString(active[:]) {
				t.Fatalf("active revision = %x, want %x", mismatch.GetActiveRevision(), active)
			}
			if !strings.Contains(mismatch.GetDetail(), hex.EncodeToString(active[:])) {
				t.Fatalf("detail %q does not name the volume's revision", mismatch.GetDetail())
			}
			if test.presented && !strings.Contains(mismatch.GetDetail(), hex.EncodeToString(mount[:])) {
				t.Fatalf("detail %q does not name the mount's revision", mismatch.GetDetail())
			}
			if !strings.Contains(mismatch.GetDetail(), localroutes.ConfigPath) {
				t.Fatalf("detail %q does not name the file to reconcile", mismatch.GetDetail())
			}
			// An attach refusal is not terminal for anyone's session; there is
			// no session yet.
			if mismatch.GetSessionRefused() {
				t.Fatal("an attach refusal claimed to end a session")
			}
			// A mount cannot read the declaration without a session and cannot
			// get a session without the revision, so the refusal has to hand it
			// the declaration or the first attach of a fresh machine has
			// nowhere to start.
			installed, err := localroutes.Parse(mismatch.GetCanonicalRules())
			if err != nil {
				t.Fatalf("the refusal carried a declaration that does not parse: %v", err)
			}
			if installed.Revision() != active {
				t.Fatalf("the declaration in the refusal is revision %x, want %x", installed.Revision(), active)
			}
		})
	}
}

// Every mount joins route barriers. The recorded revision remains an independent
// admission invariant: if a session presents a stale topology, every request is
// refused actionably even before filesystem execution.
func TestStaleRoutingRevisionRefusesEveryLaterRequestActionably(t *testing.T) {
	first := routesRevisionOf("node_modules\n")
	second := routesRevisionOf("node_modules\ntarget\n")
	h := testVolumeHandler()
	h.Store = &resourceAdmissionFaultStore{}
	h.Authorizer = allowAuthorizer{volumeserver.AccessRead | volumeserver.AccessWrite}
	h.Routes = loadedRoutes("node_modules\n")
	runtime, err := volumeserver.New("routes-volume", volumeserver.Config{
		SessionLease: time.Minute, MaxReplaySlots: 4, MaxSessions: 4, MaxLockRecords: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.Runtime = runtime
	cred, err := runtime.AttachActiveForTest(2, volumeserver.PeerIdentity{1},
		volumeserver.Authorization{Access: volumeserver.AccessRead | volumeserver.AccessWrite, Deadline: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	root := xfsstore.Capability{0xAA}
	if err := h.startSessionResources(cred.ID, root, 2, first); err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), peerIdentityKey{}, [32]byte{1})
	keepAlive := func(id uint64) *authoritypb.Response {
		return h.Handle(ctx, &authoritypb.Request{
			RequestId: id, Epoch: cred.Epoch[:],
			Session: &authoritypb.SessionProof{Id: cred.ID[:], Generation: cred.Generation, ResumeSecret: cred.Secret[:]},
			Body:    &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}},
		})
	}
	if response := keepAlive(1); response.GetErrno() != 0 {
		t.Fatalf("a session on the active revision was refused: errno %d", response.GetErrno())
	}

	// The topology changes under the mount.
	h.Routes.mu.Lock()
	h.Routes.revision = second
	h.Routes.mu.Unlock()

	response := keepAlive(2)
	if response.GetErrno() != errnos.EPERM {
		t.Fatalf("errno = %d, want EPERM", response.GetErrno())
	}
	if response.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_ROUTES {
		t.Fatalf("failure class = %v, want ROUTES", response.GetFailure())
	}
	mismatch := response.GetRoutesMismatch()
	if mismatch == nil {
		t.Fatal("the refusal carried no routing mismatch")
	}
	if !mismatch.GetSessionRefused() {
		t.Fatal("a stale session was refused without being told it is terminal")
	}
	// The rule set belongs on the attach path, not on every request a stale
	// mount makes.
	if len(mismatch.GetCanonicalRules()) != 0 {
		t.Fatal("a per-request refusal carried the whole rule set")
	}
	for _, want := range []string{hex.EncodeToString(first[:]), hex.EncodeToString(second[:]), localroutes.ConfigPath} {
		if !strings.Contains(mismatch.GetDetail(), want) {
			t.Fatalf("detail %q does not name %q", mismatch.GetDetail(), want)
		}
	}
}

// The visibility stream is barrier control, not filesystem work. The barrier
// that installs a new routing revision still needs its participants'
// acknowledgments and blocked reports after the commit point — refusing them
// through the session-routes gate would convert every routing change into one
// full repair-budget stall per strict participant. So after the revision
// moves, an ordinary request is refused as stale (the control assertion), but
// a visibility request must reach its own handler.
func TestVisibilityControlIsNotRoutesGated(t *testing.T) {
	first := routesRevisionOf("node_modules\n")
	second := routesRevisionOf("node_modules\ntarget\n")
	h := testVolumeHandler()
	h.Store = &xfsstore.Volume{}
	h.Authorizer = allowAuthorizer{volumeserver.AccessRead | volumeserver.AccessWrite}
	h.Routes = loadedRoutes("node_modules\n")
	runtime, err := volumeserver.New("routes-volume", volumeserver.Config{
		SessionLease: time.Minute, MaxReplaySlots: 4, MaxSessions: 4, MaxLockRecords: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.Runtime = runtime
	cred, err := runtime.AttachActiveForTest(2, volumeserver.PeerIdentity{1},
		volumeserver.Authorization{Access: volumeserver.AccessRead | volumeserver.AccessWrite, Deadline: time.Now().Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if err := h.startSessionResources(cred.ID, xfsstore.Capability{0xAA}, 2, first); err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(context.Background(), peerIdentityKey{}, [32]byte{1})
	request := func(id uint64, body any) *authoritypb.Response {
		req := &authoritypb.Request{
			RequestId: id, Epoch: cred.Epoch[:],
			Session: &authoritypb.SessionProof{Id: cred.ID[:], Generation: cred.Generation, ResumeSecret: cred.Secret[:]},
		}
		switch body := body.(type) {
		case *authoritypb.KeepAliveRequest:
			req.Body = &authoritypb.Request_KeepAlive{KeepAlive: body}
		case *authoritypb.AckVisibilityRequest:
			req.Body = &authoritypb.Request_AckVisibility{AckVisibility: body}
		case *authoritypb.NextVisibilityRequest:
			req.Body = &authoritypb.Request_NextVisibility{NextVisibility: body}
		default:
			t.Fatalf("unhandled body %T", body)
		}
		return h.Handle(ctx, req)
	}

	// The topology changes under the mount.
	h.Routes.mu.Lock()
	h.Routes.revision = second
	h.Routes.mu.Unlock()

	if response := request(1, &authoritypb.KeepAliveRequest{}); response.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_ROUTES {
		t.Fatalf("keepalive after the revision moved = %+v, want the ROUTES refusal proving the session is stale", response)
	}
	ack := request(2, &authoritypb.AckVisibilityRequest{Cursor: &authoritypb.VisibilityCursor{Sequence: 1, Phase: authoritypb.VisibilityPhase_VISIBILITY_PHASE_PREPARE}, Blocked: true})
	if ack.GetFailure() == authoritypb.FailureClass_FAILURE_CLASS_ROUTES {
		t.Fatalf("a blocked report was refused by the routes gate: %+v", ack)
	}
	if ack.GetErrno() != int32(syscall.EOPNOTSUPP) {
		// This fixture registers no visibility coordinator, so the request
		// must reach the visibility handler and be answered by it.
		t.Fatalf("blocked report = %+v, want the visibility handler's own EOPNOTSUPP", ack)
	}
	next := request(3, &authoritypb.NextVisibilityRequest{})
	if next.GetFailure() == authoritypb.FailureClass_FAILURE_CLASS_ROUTES {
		t.Fatalf("a visibility poll was refused by the routes gate: %+v", next)
	}
}

// .portablefs/ decides what every machine can see, so no mount may change it
// through the ordinary filesystem path - only ApplyRoutes, which runs the change
// through the barrier. Reading stays open, because a mount cannot present the
// revision it must agree with unless it can read the declaration.
func TestProtectedNamespaceRefusesEveryMountMutation(t *testing.T) {
	h := testVolumeHandler()
	session := volumeserver.SessionID{1}
	root := xfsstore.Capability{0xAA}
	if err := h.startSessionResources(session, root, 2, [32]byte{}); err != nil {
		t.Fatal(err)
	}
	// The mount resolved .portablefs, and then a file inside it, exactly as a
	// client reading the declaration does. Nothing else marks a capability, and
	// nothing else has to: creating, linking and renaming into the subtree are
	// all refused, so no other path can mint one.
	protectedDir := xfsstore.Capability{0xB1}
	if !h.protectedChild(session, root, []byte(localroutes.ProtectedPortableFS)) {
		t.Fatal("resolving .portablefs under the volume root is not protected")
	}
	if err := h.trackItem(session, protectedDir, true); err != nil {
		t.Fatal(err)
	}
	declaration := xfsstore.Capability{0xB2}
	if !h.protectedChild(session, protectedDir, []byte("local-dirs")) {
		t.Fatal("a name under .portablefs/ is not protected")
	}
	if err := h.trackItem(session, declaration, true); err != nil {
		t.Fatal(err)
	}
	// Depth is not special-cased: a directory two levels down inherits the mark
	// from its parent alone.
	deeper := xfsstore.Capability{0xB3}
	if !h.protectedChild(session, declaration, []byte("anything")) {
		t.Fatal("protection did not survive a second level")
	}
	if err := h.trackItem(session, deeper, true); err != nil {
		t.Fatal(err)
	}
	ordinary := xfsstore.Capability{0xC1}
	if err := h.trackItem(session, ordinary, false); err != nil {
		t.Fatal(err)
	}
	handle := xfsstore.Capability{0xD1}
	if err := h.trackOpen(session, handle, true); err != nil {
		t.Fatal(err)
	}

	refused := map[string]*authoritypb.Request{
		"create in the protected directory": {Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{
			Parent: protectedDir[:], Name: []byte("local-dirs")}}},
		"create the protected directory itself": {Body: &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{
			Parent: root[:], Name: []byte(localroutes.ProtectedPortableFS)}}},
		"symlink into it": {Body: &authoritypb.Request_Symlink{Symlink: &authoritypb.SymlinkRequest{
			Parent: protectedDir[:], Name: []byte("shortcut"), Target: []byte("/etc/passwd")}}},
		"unlink the declaration": {Body: &authoritypb.Request_Unlink{Unlink: &authoritypb.UnlinkRequest{
			Parent: protectedDir[:], Name: []byte("local-dirs")}}},
		"delete a deeper entry": {Body: &authoritypb.Request_Unlink{Unlink: &authoritypb.UnlinkRequest{
			Parent: deeper[:], Name: []byte("anything")}}},
		"rename out of it": {Body: &authoritypb.Request_Rename{Rename: &authoritypb.RenameRequest{
			OldParent: protectedDir[:], OldName: []byte("local-dirs"), NewParent: root[:], NewName: []byte("stolen")}}},
		"rename into it": {Body: &authoritypb.Request_Rename{Rename: &authoritypb.RenameRequest{
			OldParent: root[:], OldName: []byte("mine"), NewParent: protectedDir[:], NewName: []byte("local-dirs")}}},
		"rename the protected directory away": {Body: &authoritypb.Request_Rename{Rename: &authoritypb.RenameRequest{
			OldParent: root[:], OldName: []byte(localroutes.ProtectedPortableFS), NewParent: root[:], NewName: []byte("elsewhere")}}},
		"hard link the declaration out": {Body: &authoritypb.Request_Link{Link: &authoritypb.LinkRequest{
			ExistingItem: declaration[:], NewParent: root[:], NewName: []byte("writable-alias")}}},
		"chmod the declaration": {Body: &authoritypb.Request_SetAttr{SetAttr: &authoritypb.SetAttrRequest{
			Item: declaration[:], Mode: proto32(0o777)}}},
		"set an xattr on it": {Body: &authoritypb.Request_SetXattr{SetXattr: &authoritypb.SetXattrRequest{
			Item: declaration[:], Name: []byte("user.x")}}},
		"remove an xattr from it": {Body: &authoritypb.Request_RemoveXattr{RemoveXattr: &authoritypb.RemoveXattrRequest{
			Item: declaration[:], Name: []byte("user.x")}}},
		"fallocate through a handle on it": {Body: &authoritypb.Request_Fallocate{Fallocate: &authoritypb.FallocateRequest{
			Handle: handle[:], Offset: 0, Length: 1, FileMaxSize: 1 << 20}}},
		"open it for writing": {Body: &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{
			Item: declaration[:], Flags: &authoritypb.OpenFlags{Write: true}}}},
		"open it for truncation": {Body: &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{
			Item: declaration[:], Flags: &authoritypb.OpenFlags{Read: true, Truncate: true}}}},
	}
	for name, request := range refused {
		if err := h.refuseProtectedNamespace(session, request); err == nil {
			t.Fatalf("%s was allowed", name)
		}
	}

	allowed := map[string]*authoritypb.Request{
		"read the declaration": {Body: &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{
			Item: declaration[:], Flags: &authoritypb.OpenFlags{Read: true}}}},
		"write an ordinary file": {Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{
			Parent: root[:], Name: []byte("main.go")}}},
		"create under an ordinary directory": {Body: &authoritypb.Request_Mkdir{Mkdir: &authoritypb.MkdirRequest{
			Parent: ordinary[:], Name: []byte("build")}}},
		// .git is protected from ROUTING, which is a different question from
		// whether a mount may write it. Version control has to keep working.
		"write inside .git": {Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{
			Parent: root[:], Name: []byte(localroutes.ProtectedGit)}}},
	}
	for name, request := range allowed {
		if err := h.refuseProtectedNamespace(session, request); err != nil {
			t.Fatalf("%s was refused: %v", name, err)
		}
	}
}

func proto32(v uint32) *uint32 { return &v }

// The declaration is volume-wide configuration, not file contents, so writing
// files is not enough authority to change it.
func TestApplyRoutesNeedsAdminScope(t *testing.T) {
	request := &authoritypb.Request{Body: &authoritypb.Request_ApplyRoutes{
		ApplyRoutes: &authoritypb.ApplyRoutesRequest{Rules: []byte("node_modules\n")}}}
	if !requestRequiresAdmin(request) {
		t.Fatal("ApplyRoutes is not gated on admin scope")
	}
	if requestRequiresWrite(request) {
		t.Fatal("ApplyRoutes is classified as an ordinary write, which a mount capability grants")
	}
	for _, ordinary := range []*authoritypb.Request{
		{Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{}}},
		{Body: &authoritypb.Request_Unlink{Unlink: &authoritypb.UnlinkRequest{}}},
		{Body: &authoritypb.Request_Lookup{Lookup: &authoritypb.LookupRequest{}}},
	} {
		if requestRequiresAdmin(ordinary) {
			t.Fatalf("%T was classified as volume-wide configuration", ordinary.GetBody())
		}
	}
}

// The empty declaration has a revision like any other, and it is the digest of
// the canonical empty rule set - not the zero value, which is what a mount that
// declared nothing would send.
func TestEmptyRoutingDeclarationStillHasARevision(t *testing.T) {
	empty := routesRevisionOf("")
	if empty == ([32]byte{}) {
		t.Fatal("the empty rule set has a zero revision, so silence and agreement are indistinguishable")
	}
	if empty != sha256.Sum256(nil) {
		t.Fatalf("empty revision = %x, want the digest of no canonical rules", empty)
	}
}

func TestAuthorityGitIndexGuardFailsClosed(t *testing.T) {
	tracked := testGitIndex("src/main.go", "vendor/dep/index.js")
	for _, test := range []struct {
		name         string
		rules        string
		index        []byte
		wantTracked  bool
		wantUnproven bool
	}{
		{name: "tracked route", rules: "/vendor/\n", index: tracked, wantTracked: true},
		{name: "untracked route", rules: "/node_modules/\n", index: tracked},
		{name: "malformed index", rules: "/node_modules/\n", index: []byte("not an index"), wantUnproven: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			rules, err := localroutes.Parse([]byte(test.rules))
			if err != nil {
				t.Fatal(err)
			}
			err = checkGitIndexTracked(rules, test.index)
			if !test.wantTracked && !test.wantUnproven {
				if err != nil {
					t.Fatalf("guard refused a proven-safe route: %v", err)
				}
				return
			}
			if test.wantUnproven {
				if err == nil || !strings.Contains(err.Error(), "cannot prove") {
					t.Fatalf("malformed index = %v, want fail-closed proof error", err)
				}
				return
			}
			if !errors.Is(err, errRoutesTrackedByGit) {
				t.Fatalf("guard error = %v, want %v", err, errRoutesTrackedByGit)
			}
		})
	}
}

func testGitIndex(paths ...string) []byte {
	out := make([]byte, 12)
	copy(out, "DIRC")
	binary.BigEndian.PutUint32(out[4:8], 2)
	binary.BigEndian.PutUint32(out[8:12], uint32(len(paths)))
	for _, path := range paths {
		start := len(out)
		entry := make([]byte, 62)
		binary.BigEndian.PutUint32(entry[24:28], 0o100644)
		binary.BigEndian.PutUint16(entry[60:62], uint16(len(path)))
		out = append(out, entry...)
		out = append(out, path...)
		for (len(out)-start)%8 != 0 || len(out) == start+len(entry)+len(path) {
			out = append(out, 0)
		}
	}
	sum := sha1.Sum(out)
	return append(out, sum[:]...)
}

// The declaration round trip through the volume itself: absent means the empty
// rule set, an applied change is durable and re-reads to the same revision, and
// a compare-and-swap against a revision that is no longer active is refused
// naming both. It runs under the same privileged gate as the other XFS test,
// because the crash-atomic write is a real create/fsync/rename/fsync sequence
// against a real project directory and there is nothing to learn from faking it.
func TestRoutesControllerRoundTripsThroughTheVolumeOnXFS(t *testing.T) {
	store, _ := xfsTestVolume(t)
	visibility, err := volumeserver.NewVisibilityCoordinator(volumeserver.VisibilityConfig{
		Prior: volumeserver.PriorEpochStrictMountsFenced, Membership: noopMembership{}, Fencer: noopFencer{},
		MaxCachedNameCapacity: 1 << 16, MaxRepairBudget: time.Minute, MaxClockSkew: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	locks := volumeserver.NewLockTable(1024, 1024, time.Now)
	routes, err := NewRoutesController(store, visibility, locks)
	if err != nil {
		t.Fatal(err)
	}
	if err := routes.Load(); err != nil {
		t.Fatal(err)
	}
	empty, err := routes.Revision()
	if err != nil {
		t.Fatal(err)
	}
	if empty != routesRevisionOf("") {
		t.Fatalf("a volume with no declaration is at %x, want the empty rule set", empty)
	}

	rules := []byte("# machine-local\nnode_modules\n")
	reply, err := routes.Apply(context.Background(), rules, empty)
	if err != nil {
		t.Fatalf("apply: %v", err)
	}
	installed := routesRevisionOf(string(rules))
	if hex.EncodeToString(reply.GetRevision()) != hex.EncodeToString(installed[:]) {
		t.Fatalf("apply returned %x, want %x", reply.GetRevision(), installed)
	}

	// A second controller over the same volume is a restarted authority epoch.
	// It has to arrive at exactly the same revision, or a mount admitted before
	// the restart and one admitted after would disagree.
	restarted, err := NewRoutesController(store, visibility, locks)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Load(); err != nil {
		t.Fatalf("reload after apply: %v", err)
	}
	reloaded, err := restarted.Revision()
	if err != nil {
		t.Fatal(err)
	}
	if reloaded != installed {
		t.Fatalf("a restarted epoch reads %x, want %x", reloaded, installed)
	}

	// Losing the compare-and-swap must not last-writer-win.
	if _, err := routes.Apply(context.Background(), []byte("target\n"), empty); err == nil {
		t.Fatal("a change staked on a revision that is no longer active was applied")
	} else {
		var mismatch *RoutesMismatchError
		if !errors.As(err, &mismatch) {
			t.Fatalf("lost compare-and-swap = %v, want a routing mismatch", err)
		}
		if mismatch.Active != installed || mismatch.Presented != empty {
			t.Fatalf("mismatch named %x/%x, want active %x presented %x",
				mismatch.Active, mismatch.Presented, installed, empty)
		}
	}

	// Re-applying what is already in force is a no-op, not a barrier round.
	same, err := routes.Apply(context.Background(), rules, installed)
	if err != nil {
		t.Fatalf("re-apply of the active declaration: %v", err)
	}
	if hex.EncodeToString(same.GetRevision()) != hex.EncodeToString(installed[:]) {
		t.Fatalf("re-apply returned %x, want %x", same.GetRevision(), installed)
	}

	// A declaration that does not parse never reaches the volume.
	if _, err := routes.Apply(context.Background(), []byte("!negation/is/not/supported/\n"), installed); err == nil {
		t.Fatal("an unparseable declaration was installed")
	}
	if after, err := routes.Revision(); err != nil || after != installed {
		t.Fatalf("a refused declaration moved the active revision to %x", after)
	}
}

func TestRoutesControllerRefusesGitTrackedContentOnXFS(t *testing.T) {
	store, root := xfsTestVolume(t)
	routes := testRoutesController(t, store)
	empty, err := routes.Revision()
	if err != nil {
		t.Fatal(err)
	}
	gitDir := filepath.Join(root, localroutes.ProtectedGit)
	indexPath := filepath.Join(gitDir, "index")
	if err := os.Mkdir(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(indexPath, testGitIndex("vendor/dep/index.js"), 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := routes.Apply(context.Background(), []byte("/vendor/\n"), empty); !errors.Is(err, errRoutesTrackedByGit) {
		t.Fatalf("ApplyRoutes over tracked content = %v, want %v", err, errRoutesTrackedByGit)
	}
	if active, err := routes.Revision(); err != nil || active != empty {
		t.Fatalf("refused route moved active revision to %x, %v", active, err)
	}
	if _, err := os.Lstat(filepath.Join(root, localroutes.ConfigPath)); !os.IsNotExist(err) {
		t.Fatalf("refused route reached the declaration: %v", err)
	}

	if _, err := routes.Apply(context.Background(), []byte("/node_modules/\n"), empty); err != nil {
		t.Fatalf("ApplyRoutes over untracked content: %v", err)
	}
}

func TestRoutesControllerTreatsRenameAsPublishedWhenDirectorySyncFails(t *testing.T) {
	store, _ := xfsTestVolume(t)
	routes := testRoutesController(t, store)
	empty, err := routes.Revision()
	if err != nil {
		t.Fatal(err)
	}
	firstRules := []byte("node_modules\n")
	if _, err := routes.Apply(context.Background(), firstRules, empty); err != nil {
		t.Fatalf("initial apply: %v", err)
	}
	first := routesRevisionOf(string(firstRules))
	routes.syncDirectory = func(xfsstore.Capability) error { return syscall.ENOSPC }
	secondRules := []byte("node_modules\ntarget\n")
	second := routesRevisionOf(string(secondRules))
	_, err = routes.Apply(context.Background(), secondRules, first)
	if !errors.Is(err, xfsstore.ErrOutcomeUncertain) {
		t.Fatalf("post-rename sync failure = %v, want ErrOutcomeUncertain", err)
	}
	var barrier *volumeserver.VisibilityBarrierError
	if !errors.As(err, &barrier) || !barrier.Applied {
		t.Fatalf("post-rename sync failure = %v, want applied visibility-barrier error", err)
	}
	if active, err := routes.Revision(); err != nil || active != second {
		t.Fatalf("in-memory active revision = %x, %v; want %x", active, err, second)
	}

	// Rename publication is immediately visible even though its durability is
	// uncertain. A fresh controller must not reconstruct the old revision.
	restarted, err := NewRoutesController(store, routes.Visibility, routes.Locks)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Load(); err != nil {
		t.Fatalf("load after published rename: %v", err)
	}
	if active, err := restarted.Revision(); err != nil || active != second {
		t.Fatalf("reloaded active revision = %x, %v; want %x", active, err, second)
	}
}

func TestRoutesControllerRefusesAProtectedDeclarationWithAnOutsideHardLink(t *testing.T) {
	store, root := xfsTestVolume(t)
	routes := testRoutesController(t, store)
	empty, err := routes.Revision()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := routes.Apply(context.Background(), []byte("node_modules\n"), empty); err != nil {
		t.Fatalf("create declaration: %v", err)
	}
	alias := filepath.Join(root, ".portablefs-local-dirs-outside-alias")
	if err := os.Link(filepath.Join(root, localroutes.ConfigPath), alias); err != nil {
		t.Fatalf("create outside hard-link alias: %v", err)
	}

	restarted, err := NewRoutesController(store, routes.Visibility, routes.Locks)
	if err != nil {
		t.Fatal(err)
	}
	if err := restarted.Load(); err == nil || !strings.Contains(err.Error(), "exactly one link") {
		t.Fatalf("load with outside hard link = %v, want link-count refusal", err)
	}
}

func TestRoutesControllerSerializesConcurrentApplyCompareAndSwapOnXFS(t *testing.T) {
	store, _ := xfsTestVolume(t)
	routes := testRoutesController(t, store)
	expected, err := routes.Revision()
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, rules := range [][]byte{[]byte("node_modules\n"), []byte("target\n")} {
		rules := append([]byte(nil), rules...)
		go func() {
			<-start
			_, err := routes.Apply(context.Background(), rules, expected)
			results <- err
		}()
	}
	close(start)
	var succeeded, lost int
	for range 2 {
		err := <-results
		if err == nil {
			succeeded++
			continue
		}
		var mismatch *RoutesMismatchError
		if errors.As(err, &mismatch) && mismatch.Presented == expected {
			lost++
			continue
		}
		t.Fatalf("concurrent Apply returned %v", err)
	}
	if succeeded != 1 || lost != 1 {
		t.Fatalf("concurrent Apply results = %d success, %d CAS loss; want one each", succeeded, lost)
	}
}

// xfsTestVolume opens a unique child of the provisioned project directory,
// under the same fail-loud gate the handler end-to-end test uses. XFS inherits
// the project ID and PROJINHERIT flag onto this root, so every route-controller
// test gets the production gate without sharing .git, route declarations, or
// crash residue with another test.
func xfsTestVolume(t *testing.T) (*xfsstore.Volume, string) {
	t.Helper()
	provisioned := os.Getenv("PORTABLEFS_XFS_TEST_ROOT")
	projectRaw := os.Getenv("PORTABLEFS_XFS_TEST_PROJECT")
	required := os.Getenv("PORTABLEFS_XFS_TEST_REQUIRED") == "1"
	if provisioned == "" || projectRaw == "" {
		if required {
			t.Fatalf("PORTABLEFS_XFS_TEST_REQUIRED=1 but PORTABLEFS_XFS_TEST_ROOT=%q PORTABLEFS_XFS_TEST_PROJECT=%q", provisioned, projectRaw)
		}
		t.Skip("privileged XFS gate is not configured")
	}
	if required && os.Geteuid() == 0 {
		t.Fatal("PORTABLEFS_XFS_TEST_REQUIRED=1 requires the unprivileged volume identity, not root")
	}
	project, err := strconv.ParseUint(projectRaw, 10, 32)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.MkdirTemp(provisioned, "authorityrpc-routes-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(root); err != nil {
			t.Errorf("remove isolated XFS route-controller root %s: %v", root, err)
		}
	})
	store, err := xfsstore.Open(root, xfsstore.Config{
		ExpectedProjectID: uint32(project),
		ExpectedOwnerUID:  uint32(os.Geteuid()), ExpectedOwnerGID: uint32(os.Getegid()),
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store, root
}

// resetXFSRouteDeclaration is retained for the separate volume-handler XFS
// fixture, which intentionally opens the provisioned root itself. Route
// controller tests use xfsTestVolume's isolated roots and never need this
// shared-state cleanup.
func resetXFSRouteDeclaration(t *testing.T, root string) {
	t.Helper()
	remove := func() {
		for _, path := range []string{
			filepath.Join(root, localroutes.ConfigPath),
			filepath.Join(root, localroutes.ConfigPath+".pending"),
		} {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				t.Errorf("remove shared XFS routing fixture %s: %v", path, err)
			}
		}
	}
	remove()
	t.Cleanup(remove)
}

// singleUseAuthorizer is what a volume capability actually is: volumecap.Verify
// spends the nonce as the last step of an otherwise successful verification, so
// presenting the same token twice fails the second time.
type singleUseAuthorizer struct {
	access volumeserver.Access
	spent  map[string]bool
	calls  int
}

type blockingAuthorizer struct {
	entered chan struct{}
	release chan struct{}
}

func (a blockingAuthorizer) Authorize(context.Context, string, []byte) (volumeserver.Authorization, error) {
	close(a.entered)
	<-a.release
	return volumeserver.Authorization{Access: volumeserver.AccessRead | volumeserver.AccessWrite, Deadline: time.Now().Add(time.Hour)}, nil
}

func (a *singleUseAuthorizer) Authorize(_ context.Context, _ string, token []byte) (volumeserver.Authorization, error) {
	a.calls++
	if a.spent == nil {
		a.spent = make(map[string]bool)
	}
	if a.spent[string(token)] {
		return volumeserver.Authorization{}, syscall.EPERM
	}
	a.spent[string(token)] = true
	return volumeserver.Authorization{Access: a.access, Deadline: time.Now().Add(time.Hour)}, nil
}

// A mount cannot know the volume's routing revision until it has read the
// declaration, and it cannot read the declaration without a session. The first
// attach of a mount that has never seen this volume is therefore expected to be
// refused, and that refusal is the bootstrap: it carries the active rules.
//
// Which makes the ordering load-bearing. A capability is single use, so if the
// routing check ran after it was verified, the bootstrap would spend it and the
// mount would need a second capability to complete the handshake it had just
// been told how to complete - every default mount failing to attach with EPERM.
// The check runs first, so a refused-for-revision attach costs nothing and the
// same capability re-attaches.
func TestAttachRefusedForRoutingLeavesTheCapabilityUnspent(t *testing.T) {
	authorizer := &singleUseAuthorizer{access: volumeserver.AccessRead | volumeserver.AccessWrite}
	h := testVolumeHandler()
	h.Store = &xfsstore.Volume{}
	h.Authorizer = authorizer
	h.Routes = loadedRoutes("node_modules\n")
	h.Visibility = h.Routes.Visibility
	runtime, err := volumeserver.New("routes-volume", volumeserver.Config{
		SessionLease: time.Minute, MaxReplaySlots: 4, MaxSessions: 4, MaxLockRecords: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.Runtime = runtime
	ctx := context.WithValue(context.Background(), peerIdentityKey{}, [32]byte{1})
	capability := []byte("one-shot-capability")
	attach := func(id uint64, revision []byte) *authoritypb.Response {
		return h.Handle(ctx, &authoritypb.Request{RequestId: id, Body: &authoritypb.Request_Attach{
			Attach: &authoritypb.AttachRequest{
				VolumeId: "routes-volume", AccessToken: capability, ReplaySlots: 2,
				RoutesRevision: revision, AttachAttemptId: testAttachAttempt(id),
				CoherenceProfile:   authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT,
				CachedNameCapacity: 1024, RepairBudgetMillis: 1000,
				NamespaceRepair: authoritypb.NamespaceRepair_NAMESPACE_REPAIR_PARENT_EXCLUSIVE,
			}}})
	}

	// The mount has never seen this volume, so it declares the empty rule set.
	unknown := routesRevisionOf("")
	refusal := attach(1, unknown[:])
	if refusal.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_ROUTES {
		t.Fatalf("first attach = errno %d failure %v, want a routing refusal", refusal.GetErrno(), refusal.GetFailure())
	}
	if authorizer.calls != 0 {
		t.Fatalf("the capability was presented for verification %d times before the routing check; a bootstrap must not spend it", authorizer.calls)
	}
	rules := refusal.GetRoutesMismatch().GetCanonicalRules()
	if len(rules) == 0 {
		t.Fatal("the refusal carried no declaration, so the mount has nothing to bootstrap from")
	}
	installed, err := localroutes.Parse(rules)
	if err != nil {
		t.Fatalf("the declaration in the refusal does not parse: %v", err)
	}

	// The same capability, now with the revision the refusal taught it. It must
	// reach verification, which is the thing a spent capability could not do.
	revision := installed.Revision()
	second := attach(2, revision[:])
	if authorizer.calls != 1 {
		t.Fatalf("the re-attach presented the capability %d times, want 1", authorizer.calls)
	}
	if second.GetFailure() == authoritypb.FailureClass_FAILURE_CLASS_ROUTES {
		t.Fatalf("the re-attach was refused for routing again: %s", second.GetRoutesMismatch().GetDetail())
	}
	if second.GetErrno() == errnos.EPERM {
		t.Fatal("the re-attach was refused EPERM; the bootstrap spent the capability")
	}
}

func TestAttachPureValidationLeavesTheCapabilityUnspentForRetry(t *testing.T) {
	for _, test := range []struct {
		name    string
		invalid *authoritypb.AttachRequest
		valid   *authoritypb.AttachRequest
	}{
		{
			name: "invalid replay slots",
			invalid: &authoritypb.AttachRequest{
				VolumeId: "routes-volume", ReplaySlots: 0,
			},
			valid: &authoritypb.AttachRequest{
				VolumeId: "routes-volume", ReplaySlots: 2,
			},
		},
		{
			name: "over-bound strict commitment",
			invalid: &authoritypb.AttachRequest{
				VolumeId: "routes-volume", ReplaySlots: 2,
				CoherenceProfile:   authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT,
				CachedNameCapacity: 1<<16 + 1, RepairBudgetMillis: 1000,
				NamespaceRepair: authoritypb.NamespaceRepair_NAMESPACE_REPAIR_PARENT_EXCLUSIVE,
			},
			valid: &authoritypb.AttachRequest{
				VolumeId: "routes-volume", ReplaySlots: 2,
				CoherenceProfile:   authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT,
				CachedNameCapacity: 1024, RepairBudgetMillis: 1000,
				NamespaceRepair: authoritypb.NamespaceRepair_NAMESPACE_REPAIR_PARENT_EXCLUSIVE,
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			authorizer := &singleUseAuthorizer{access: volumeserver.AccessRead | volumeserver.AccessWrite}
			h := testVolumeHandler()
			h.Store = &resourceAdmissionFaultStore{}
			h.Authorizer = authorizer
			h.Routes = loadedRoutes("")
			h.Visibility = h.Routes.Visibility
			runtime, err := volumeserver.New("routes-volume", volumeserver.Config{
				SessionLease: time.Minute, MaxReplaySlots: 4, MaxSessions: 4, MaxLockRecords: 8,
			})
			if err != nil {
				t.Fatal(err)
			}
			h.Runtime = runtime
			ctx := context.WithValue(context.Background(), peerIdentityKey{}, [32]byte{1})
			token := []byte("same-one-shot-token")
			revision := routesRevisionOf("")
			for _, attach := range []*authoritypb.AttachRequest{test.invalid, test.valid} {
				attach.AccessToken = token
				attach.RoutesRevision = append([]byte(nil), revision[:]...)
				attach.CoherenceProfile = authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT
				if attach.CachedNameCapacity == 0 {
					attach.CachedNameCapacity = 1024
				}
				if attach.RepairBudgetMillis == 0 {
					attach.RepairBudgetMillis = 1000
				}
				if attach.NamespaceRepair == authoritypb.NamespaceRepair_NAMESPACE_REPAIR_UNSPECIFIED {
					attach.NamespaceRepair = authoritypb.NamespaceRepair_NAMESPACE_REPAIR_PARENT_EXCLUSIVE
				}
			}
			test.invalid.AttachAttemptId = testAttachAttempt(1)
			test.valid.AttachAttemptId = testAttachAttempt(2)
			if response := h.Handle(ctx, &authoritypb.Request{RequestId: 1, Body: &authoritypb.Request_Attach{Attach: test.invalid}}); response.GetErrno() == 0 {
				t.Fatal("invalid attach was admitted")
			}
			if authorizer.calls != 0 {
				t.Fatalf("invalid attach spent the capability: authorizer calls = %d", authorizer.calls)
			}
			_ = h.Handle(ctx, &authoritypb.Request{RequestId: 2, Body: &authoritypb.Request_Attach{Attach: test.valid}})
			if authorizer.calls != 1 {
				t.Fatalf("valid retry reached authorization %d times, want 1", authorizer.calls)
			}
		})
	}
}

func TestPausedAttachPinsItsAdmittedTopologyUntilAdmissionFinishes(t *testing.T) {
	routes := loadedRoutes("")
	authorizer := blockingAuthorizer{entered: make(chan struct{}), release: make(chan struct{})}
	h := testVolumeHandler()
	h.Store = &resourceAdmissionFaultStore{}
	h.Authorizer = authorizer
	h.Routes, h.Visibility = routes, routes.Visibility
	runtime, err := volumeserver.New("routes-volume", volumeserver.Config{
		SessionLease: time.Minute, MaxReplaySlots: 4, MaxSessions: 4, MaxLockRecords: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.Runtime = runtime
	revision := routesRevisionOf("")
	attach := &authoritypb.AttachRequest{
		VolumeId: "routes-volume", AccessToken: []byte("token"), ReplaySlots: 2,
		RoutesRevision:     append([]byte(nil), revision[:]...),
		CoherenceProfile:   authoritypb.CoherenceProfile_COHERENCE_PROFILE_STRICT,
		CachedNameCapacity: 1024, RepairBudgetMillis: 1000,
		NamespaceRepair: authoritypb.NamespaceRepair_NAMESPACE_REPAIR_PARENT_EXCLUSIVE,
		AttachAttemptId: testAttachAttempt(1),
	}
	ctx := context.WithValue(context.Background(), peerIdentityKey{}, [32]byte{1})
	attachDone := make(chan struct{})
	go func() {
		defer close(attachDone)
		_ = h.Handle(ctx, &authoritypb.Request{RequestId: 1, Body: &authoritypb.Request_Attach{Attach: attach}})
	}()
	select {
	case <-authorizer.entered:
	case <-time.After(time.Second):
		t.Fatal("attach did not pause inside authorization")
	}

	checked := make(chan struct{})
	writerDone := make(chan error, 1)
	go func() {
		_, err := routes.Visibility.ExecuteRoutesChecked(context.Background(), volumeserver.RoutesChange{}, func() (bool, error) {
			close(checked)
			return false, nil
		}, func() (volumeserver.RoutesChange, error) { panic("no-op CAS committed") })
		writerDone <- err
	}()
	select {
	case <-checked:
		t.Fatal("route CAS ran while attach admission was paused")
	case <-time.After(50 * time.Millisecond):
	}
	close(authorizer.release)
	select {
	case <-attachDone:
	case <-time.After(time.Second):
		t.Fatal("attach did not finish after authorization resumed")
	}
	select {
	case err := <-writerDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("route writer did not resume after attach admission finished")
	}
}

func TestPausedFilesystemRequestPinsItsAdmittedTopologyUntilCompletion(t *testing.T) {
	routes := loadedRoutes("")
	h := testVolumeHandler()
	h.Routes, h.Visibility = routes, routes.Visibility
	id := volumeserver.SessionID{1}
	revision := routesRevisionOf("")
	if err := h.startSessionResources(id, xfsstore.Capability{1}, 2, revision, volumeserver.CoherenceStrict); err != nil {
		t.Fatal(err)
	}
	if err := routes.Visibility.Register(id, volumeserver.CoherenceStrict, make(chan struct{}), volumeserver.VisibilityCommitment{
		CachedNameCapacity: 1024, RepairBudget: time.Second,
		NamespaceRepair: volumeserver.NamespaceRepairParentExclusive,
	}); err != nil {
		t.Fatal(err)
	}
	initial, err := routes.Visibility.InitialCursor(id)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		after := initial
		for range 2 {
			event, err := routes.Visibility.Next(ctx, id, after)
			if err != nil {
				return
			}
			if err := routes.Visibility.Ack(id, event.Cursor); err != nil {
				return
			}
			after = event.Cursor
		}
	}()

	guard, err := h.beginTopologyRequest(id)
	if err != nil {
		t.Fatal(err)
	}
	checked := make(chan struct{})
	writerDone := make(chan error, 1)
	next := volumeserver.RoutesChange{Revision: [32]byte{1}, Canonical: []byte("node_modules\n")}
	go func() {
		_, err := routes.Visibility.ExecuteRoutesChecked(context.Background(), next, func() (bool, error) {
			close(checked)
			return true, nil
		}, func() (volumeserver.RoutesChange, error) { return next, nil })
		writerDone <- err
	}()
	select {
	case <-checked:
		t.Fatal("route CAS ran while an admitted filesystem request was paused")
	case <-time.After(50 * time.Millisecond):
	}
	guard.Release()
	select {
	case err := <-writerDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("route writer did not resume after filesystem completion")
	}
}
