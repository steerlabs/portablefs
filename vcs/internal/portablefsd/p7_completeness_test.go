package portablefsd

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/bench/lantrace"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/errnos"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

func p7Mkdir(t *testing.T, f *cachedV3Fixture, name string) *v3ItemRecord {
	t.Helper()
	body, errno := f.dispatch(&pfslocal.MkdirRequest{Dir: f.root, Name: []byte(name), Mode: 0o755})
	if errno != 0 {
		t.Fatal(errno)
	}
	return f.record(body.(*pfslocal.MkdirReply).Attr.Item)
}

func p7Create(t *testing.T, f *cachedV3Fixture, dir *v3ItemRecord, name string) pfslocal.Attr {
	t.Helper()
	body, errno := f.dispatch(&pfslocal.CreateRequest{Dir: dir.item, Name: []byte(name), Mode: 0o644})
	if errno != 0 {
		t.Fatal(errno)
	}
	return body.(*pfslocal.CreateReply).Attr
}

func p7Absence(t *testing.T, f *cachedV3Fixture, dir *v3ItemRecord, name string, local bool) {
	t.Helper()
	run := func() {
		if _, errno := f.dispatch(&pfslocal.LookupRequest{Dir: dir.item, Name: []byte(name)}); errno != darwinENOENT {
			t.Fatalf("absence errno=%d", errno)
		}
	}
	if local {
		f.requireServedLocally("certified absence", run)
	} else {
		f.requireAuthority("uncertified absence", run)
	}
}

func p7Members(t *testing.T, d *v3DataPlane, dir *v3ItemRecord, names ...string) {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	if dir.complete == nil || len(dir.complete.names) != len(names) {
		t.Fatalf("certificate=%+v, want %q", dir.complete, names)
	}
	for _, name := range names {
		if _, ok := dir.complete.names[name]; !ok {
			t.Fatalf("missing member %q", name)
		}
	}
}

func TestP7MkdirWitnessAndDeterministicCallReduction(t *testing.T) {
	t.Run("ordinary-cache", func(t *testing.T) {
		f := newCachedV3Fixture(t, v3FileObjects())
		dir := p7Mkdir(t, f, "dir")
		// Test-only ablation; the product has no cache-feature selector.
		f.d.mu.Lock()
		f.d.dropCompletenessLocked(dir, lantrace.CertDropNamespaceCut)
		f.d.mu.Unlock()
		before := f.authorityCalls()
		for i := range 64 {
			p7Absence(t, f, dir, fmt.Sprintf("first-%d", i), false)
		}
		if calls := f.authorityCalls() - before; calls != 64 {
			t.Fatalf("ordinary cache made %d calls, want 64", calls)
		}
	})
	for _, permitted := range []bool{false, true} {
		t.Run(fmt.Sprint(permitted), func(t *testing.T) {
			f := newCachedV3Fixture(t, v3FileObjects())
			f.ns.hold = func(req *authoritypb.Request, res *authoritypb.Response) {
				if req.GetMkdir() != nil {
					// A fixed-schema authority observation, never a daemon mode check.
					res.GetMkdir().ChildSearchPermitted = permitted
				}
			}
			dir := p7Mkdir(t, f, "dir")
			p7Members(t, f.d, dir)
			before := f.authorityCalls()
			for i := range 64 {
				p7Absence(t, f, dir, fmt.Sprintf("first-%d", i), permitted || i > 0)
			}
			want := 0
			if !permitted {
				want = 1 // A real stamped-negative child Lookup grants search.
			}
			if calls := f.authorityCalls() - before; calls != want {
				t.Fatalf("64 distinct names made %d calls, want %d", calls, want)
			}
			p7Members(t, f.d, dir)
		})
	}
}

func TestP7PermissionWitnessDenialAndSearchOnly(t *testing.T) {
	for _, tc := range []struct {
		mode      uint32
		permitted bool
	}{{0, false}, {0o111, true}, {0o100, false}} {
		t.Run(fmt.Sprintf("%o-%t", tc.mode, tc.permitted), func(t *testing.T) {
			f := newCachedV3Fixture(t, v3FileObjects())
			original := f.client.mutation
			f.client.mutation = func(ctx context.Context, id authorityrpc.MutationIdentity, req *authoritypb.Request) (*authoritypb.Response, error) {
				if req.GetLookup() != nil && !bytes.Equal(req.GetLookup().GetParent(), f.client.root.GetToken()) && !tc.permitted {
					r := exactTestMutationReply(id)
					r.Errno = errnos.EACCES
					return r, nil
				}
				r, err := original(ctx, id, req)
				if req.GetMkdir() != nil && err == nil {
					r.GetMkdir().ChildSearchPermitted = tc.permitted
					r.GetMkdir().Item.Attr.Mode = tc.mode
					for _, o := range r.PostState.Objects {
						if bytes.Equal(o.StableIdentity, r.GetMkdir().Item.StableIdentity) {
							o.Attr.Mode = tc.mode
						}
					}
				}
				return r, err
			}
			dir := p7Mkdir(t, f, "dir")
			if tc.permitted {
				p7Absence(t, f, dir, "missing", true)
			} else {
				f.requireAuthority("denied search", func() {
					if _, errno := f.dispatch(&pfslocal.LookupRequest{Dir: dir.item, Name: []byte("missing")}); errno != darwinEACCES {
						t.Fatalf("denied lookup=%d", errno)
					}
				})
				if dir.search != lantrace.SearchDenied {
					t.Fatal("failed Lookup manufactured permission")
				}
			}
		})
	}
}

func TestP7DelayedMkdirCannotEraseNewerChild(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	committed, release := make(chan struct{}), make(chan struct{})
	f.ns.hold = func(req *authoritypb.Request, _ *authoritypb.Response) {
		if req.GetMkdir() != nil {
			close(committed)
			<-release
		}
	}
	const op = 7701
	f.d.bridge.reserveFrontendPublication(testCallback(op))
	done := make(chan int32, 1)
	go func() {
		_, errno := dispatchV3Owned(f.d, context.Background(), op, &pfslocal.MkdirRequest{Dir: f.root, Name: []byte("dir"), Mode: 0o755})
		done <- errno
	}()
	<-committed
	body, errno := dispatchV3Owned(f.d, context.Background(), op, &pfslocal.LookupRequest{Dir: f.root, Name: []byte("dir")})
	if errno != 0 {
		t.Fatal(errno)
	}
	dir := f.record(body.(*pfslocal.LookupReply).Attr.Item)
	if _, errno := dispatchV3Owned(f.d, context.Background(), op, &pfslocal.CreateRequest{Dir: dir.item, Name: []byte("child"), Mode: 0o644}); errno != 0 {
		t.Fatal(errno)
	}
	close(release)
	if errno := <-done; errno != 0 {
		t.Fatal(errno)
	}
	if dir.complete != nil || dir.search == lantrace.SearchPermitted {
		t.Fatal("delayed mkdir installed empty/search knowledge")
	}
	_, _ = f.d.bridge.acknowledgePublication(testCallback(op), pfslocal.PublicationSemanticCommitPublished)
	f.d.bridge.releaseFrontendPublication(testCallback(op))
	_ = f.d.bridge.finishFrontendPublication(testCallback(op))
	p7Absence(t, f, dir, "unseen", false)
	f.lookup(dir.item, "child")
}

func TestP7ExactMkdirReplayPreservesMaintainedCertificate(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	dir := p7Mkdir(t, f, "dir")
	witness := *dir.mkdirWitness
	replay := &v3MutationEffect{snapshot: witness.snapshot, mkdir: dir, mkdirWitness: &witness}
	if err := f.d.applyMutation(replay); err != nil {
		t.Fatal(err)
	}
	p7Members(t, f.d, dir)
	p7Create(t, f, dir, "later")
	if err := f.d.applyMutation(replay); err != nil {
		t.Fatal(err)
	}
	p7Members(t, f.d, dir, "later")
	p7Absence(t, f, dir, "new", true)
}

func TestP7MembershipSurvivesAliasesEvictionAndReclaim(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	dir := p7Mkdir(t, f, "dir")
	file := p7Create(t, f, dir, "original")
	if _, errno := f.dispatch(&pfslocal.HardLinkRequest{Item: file.Item, Dir: dir.item, Name: []byte("alias")}); errno != 0 {
		t.Fatal(errno)
	}
	p7Members(t, f.d, dir, "original", "alias")
	f.requireAuthority("alias without remembered positive binding", func() { f.lookup(dir.item, "original") })
	if _, errno := f.dispatch(&pfslocal.ReclaimRequest{Item: file.Item}); errno != 0 {
		t.Fatal(errno)
	}
	p7Members(t, f.d, dir, "original", "alias")
	f.requireAuthority("present without held capability", func() { f.lookup(dir.item, "alias") })
	p7Absence(t, f, dir, "new", true)
	if _, errno := f.dispatch(&pfslocal.RemoveRequest{Dir: dir.item, Name: []byte("original")}); errno != 0 {
		t.Fatal(errno)
	}
	p7Members(t, f.d, dir, "alias")
	p7Create(t, f, dir, "original")
	p7Members(t, f.d, dir, "alias", "original")
	f.requireServedLocally("recreated positive binding", func() { f.lookup(dir.item, "original") })
}

func TestP7RenameReplacementCrossDirectoryAndRawNames(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	a, b := p7Mkdir(t, f, "a"), p7Mkdir(t, f, "b")
	raw := string([]byte{0xff, 0xfe, 'x'})
	p7Create(t, f, a, raw)
	p7Create(t, f, b, "victim")
	if _, errno := f.dispatch(&pfslocal.RenameRequest{FromDir: a.item, FromName: []byte(raw), ToDir: b.item, ToName: []byte("victim")}); errno != 0 {
		t.Fatal(errno)
	}
	p7Members(t, f.d, a)
	p7Members(t, f.d, b, "victim")
	p7Absence(t, f, a, raw, true)
	if _, errno := f.dispatch(&pfslocal.RenameRequest{FromDir: b.item, FromName: []byte("victim"), ToDir: b.item, ToName: []byte(raw)}); errno != 0 {
		t.Fatal(errno)
	}
	p7Members(t, f.d, b, raw)
	file := f.lookup(b.item, raw)
	if _, errno := f.dispatch(&pfslocal.HardLinkRequest{Item: file.Item, Dir: b.item, Name: []byte("same-inode")}); errno != 0 {
		t.Fatal(errno)
	}
	if _, errno := f.dispatch(&pfslocal.RenameRequest{FromDir: b.item, FromName: []byte(raw), ToDir: b.item, ToName: []byte("same-inode")}); errno != 0 {
		t.Fatal(errno)
	}
	p7Members(t, f.d, b, raw, "same-inode")
	// pfslocal exposes non-exchange rename only. An exchange-shaped authority
	// outcome is malformed, not a partial membership update.
}

func TestP7NestedMkdirAndSymlinkAreMembers(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	dir := p7Mkdir(t, f, "dir")
	if _, errno := f.dispatch(&pfslocal.MkdirRequest{Dir: dir.item, Name: []byte("nested"), Mode: 0o755}); errno != 0 {
		t.Fatal(errno)
	}
	original := f.client.mutation
	f.client.mutation = func(ctx context.Context, id authorityrpc.MutationIdentity, req *authoritypb.Request) (*authoritypb.Response, error) {
		if link := req.GetSymlink(); link != nil {
			f.ns.mu.Lock()
			defer f.ns.mu.Unlock()
			parent := f.ns.tokens[[16]byte(link.Parent)]
			const created = 0x91
			f.ns.objects[created] = &v3TestObject{inode: 401, kind: authoritypb.Attr_SYMLINK, nlink: 1}
			f.ns.names[f.ns.key(link.Parent, link.Name)] = created
			f.ns.commit(parent, created)
			r := exactTestMutationReply(id)
			r.PostState = f.ns.state(f.ns.object(parent, v3PostStateRoleParent), f.ns.object(created, v3PostStateRoleCreated))
			r.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: f.ns.issue(created)}}
			return r, nil
		}
		return original(ctx, id, req)
	}
	if _, errno := f.dispatch(&pfslocal.SymlinkRequest{Dir: dir.item, Name: []byte("link"), Target: []byte("target")}); errno != 0 {
		t.Fatal(errno)
	}
	p7Members(t, f.d, dir, "nested", "link")
	if _, errno := f.dispatch(&pfslocal.RemoveRequest{Dir: dir.item, Name: []byte("nested"), Directory: true}); errno != 0 {
		t.Fatal(errno)
	}
	p7Members(t, f.d, dir, "link")
	p7Absence(t, f, dir, "nested", true)
}

func TestP7UnsupportedExchangeOutcomeEndsCertificateEligibility(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	a, b := p7Mkdir(t, f, "a"), p7Mkdir(t, f, "b")
	p7Create(t, f, a, "source")
	p7Create(t, f, b, "destination")
	f.ns.hold = func(req *authoritypb.Request, res *authoritypb.Response) {
		if req.GetRename() != nil {
			for _, o := range res.PostState.Objects {
				if o.Roles == v3PostStateRoleMoved {
					o.Roles |= v3PostStateRoleExchanged
				}
			}
		}
	}
	if _, errno := f.dispatch(&pfslocal.RenameRequest{FromDir: a.item, FromName: []byte("source"), ToDir: b.item, ToName: []byte("destination")}); errno != darwinEIO {
		t.Fatal(errno)
	}
	if f.d.terminalError() == nil || a.complete != nil || b.complete != nil || f.d.completeDirs != 0 {
		t.Fatal("unsupported/partial exchange left local absence eligible")
	}
}

func TestP7OldDuplicateAmbiguousAndPartialEffectsDropWholeCertificate(t *testing.T) {
	for _, kind := range []string{"old", "duplicate-old", "same-cut-contradiction", "partial", "unknown-name", "ambiguous-coordinate", "missing-parent-coordinate"} {
		t.Run(kind, func(t *testing.T) {
			f := newCachedV3Fixture(t, v3FileObjects())
			dir := p7Mkdir(t, f, "dir")
			p7Create(t, f, dir, "kept")
			e := &v3MutationEffect{snapshot: dir.watermark + 1, namesComplete: true,
				names: []v3NameEffect{{parent: dir, name: "other", bound: true}}}
			switch kind {
			case "old":
				e.snapshot = dir.watermark - 1
			case "duplicate-old":
				if err := f.d.applyMutation(e); err != nil {
					t.Fatal(err)
				}
				if err := f.d.applyMutation(e); err != nil {
					t.Fatal(err)
				}
				p7Members(t, f.d, dir, "kept", "other")
				if err := f.d.applyMutation(&v3MutationEffect{snapshot: e.snapshot + 1, namesComplete: true,
					names: []v3NameEffect{{parent: dir, name: "later", bound: true}}}); err != nil {
					t.Fatal(err)
				}
			case "same-cut-contradiction":
				e.snapshot = dir.watermark
			case "partial":
				e.namesComplete = false
			case "unknown-name":
				e.names[0].name = "bad/name"
			case "ambiguous-coordinate":
				e.names = append(e.names, v3NameEffect{parent: dir, name: "other"})
			case "missing-parent-coordinate":
				e.names = nil
				e.objects = []v3Observation{{identity: dir.item.StableIdentity, attr: dir.attr, version: dir.version, roles: v3PostStateRoleParent}}
			}
			if err := f.d.applyMutation(e); err != nil {
				t.Fatal(err)
			}
			if dir.complete != nil || f.d.completeNames != 0 || f.d.completeBytes != 0 || f.d.completeDirs != 0 {
				t.Fatal("only part of the affected certificate was dropped")
			}
			p7Absence(t, f, dir, "fresh", false)
		})
	}
}

func TestP7PermissionABARejectsOldLookupAndMkdir(t *testing.T) {
	for _, field := range []string{"mode", "owner", "group", "same-mode-effect"} {
		t.Run(field, func(t *testing.T) {
			f := newCachedV3Fixture(t, v3FileObjects())
			dir := p7Mkdir(t, f, "dir")
			old := dir.mkdirWitness.snapshot
			back := cloneAuthorityAttr(dir.attr)
			away := cloneAuthorityAttr(back)
			switch field {
			case "mode":
				away.Mode = 0
			case "owner":
				away.Uid++
			case "group":
				away.Gid++
			}
			// Force a real old Lookup, then hold its stamped-negative response.
			f.d.mu.Lock()
			dir.search = lantrace.SearchDenied
			f.d.mu.Unlock()
			sampled, release := make(chan struct{}), make(chan struct{})
			f.ns.hold = func(req *authoritypb.Request, _ *authoritypb.Response) {
				if req.GetLookup() != nil {
					close(sampled)
					<-release
				}
			}
			done := make(chan int32, 1)
			go func() {
				_, errno := f.dispatch(&pfslocal.LookupRequest{Dir: dir.item, Name: []byte("stale")})
				done <- errno
			}()
			<-sampled
			// Deliver the ABA return first: current numeric attrs are equal,
			// then deliver the older away effect whose attrs will be ignored.
			for _, value := range []struct {
				attr *authoritypb.Attr
				cut  uint64
			}{{back, old + 2}, {away, old + 1}} {
				if err := f.d.applyMutation(&v3MutationEffect{snapshot: value.cut, permissionTarget: dir,
					objects: []v3Observation{{identity: dir.item.StableIdentity, attr: value.attr, version: value.cut}}}); err != nil {
					t.Fatal(err)
				}
			}
			close(release)
			if errno := <-done; errno != darwinENOENT {
				t.Fatal(errno)
			}
			f.d.mu.Lock()
			canSeed := f.d.mkdirSeedEligibleLocked(&v3MutationEffect{snapshot: old, mkdir: dir, mkdirWitness: dir.mkdirWitness})
			bad := canSeed || dir.complete != nil || dir.search == lantrace.SearchPermitted || len(dir.negatives) != 0 || dir.permissionCut != old+2
			f.d.mu.Unlock()
			if bad {
				t.Fatal("permission ABA resurrected old lookup or MKDIR knowledge")
			}
			f.ns.hold = nil
			p7Absence(t, f, dir, "fresh", false)
			if dir.complete != nil {
				t.Fatal("partial lookup re-seeded completeness")
			}
		})
	}
}

func TestP7ConservativeVersionInflationPreservesFacts(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	dir := p7Mkdir(t, f, "dir")
	p7Create(t, f, dir, "member")
	f.d.mu.Lock()
	err := f.d.observeLocked(dir, dir.attr, 100, 100)
	f.d.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	p7Members(t, f.d, dir, "member")
	p7Absence(t, f, dir, "absent", true)
	f.d.mu.Lock()
	dir.search = lantrace.SearchDenied
	err = f.d.observeLocked(dir, dir.attr, 101, 101)
	f.d.mu.Unlock()
	if err != nil || dir.search != lantrace.SearchDenied {
		t.Fatal("inflation granted search")
	}
}

func TestP7SetattrPermissionIntentDropsEvenEqualAttributes(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	dir := p7Mkdir(t, f, "dir")
	mode := dir.attr.Mode
	if _, errno := f.dispatch(&pfslocal.SetAttrRequest{Item: dir.item, Mode: &mode}); errno != 0 {
		t.Fatal(errno)
	}
	if dir.complete != nil || dir.permissionCut <= dir.mkdirWitness.snapshot {
		t.Fatal("equal mode effect retained permission knowledge")
	}
	p7Absence(t, f, dir, "unseen", false)
}

func TestP7ActiveSourceConflictAndSettledSourceRescueCountOnce(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	dir := p7Mkdir(t, f, "dir")
	coordinator := f.d.bridge.sourcePublication
	const op = 7791
	coordinator.reserve(testCallback(op))
	gate, _ := v3NamespaceSourceGate(dir.item, []byte("touched"), false)
	lease, err := coordinator.acquireSource(context.Background(), testCallback(op), gate)
	if err != nil {
		t.Fatal(err)
	}
	p7Absence(t, f, dir, "held", false)
	if err := lease.resolveNoBindings(gate); err != nil {
		t.Fatal(err)
	}
	lease.finishRequest()
	// No PublicationAck yet: settled source holds must not block completeness.
	p7Absence(t, f, dir, "settled", true)
	// Record a real source absence, making both caches able to rescue it.
	if err := f.d.applyMutation(&v3MutationEffect{snapshot: dir.watermark + 1, namesComplete: true,
		names: []v3NameEffect{{parent: dir, name: "both"}}}); err != nil {
		t.Fatal(err)
	}
	var stream bytes.Buffer
	r := p6Recorder(t, &stream, lantrace.LayerDaemon, lantrace.RecorderConfig{})
	trace := v3RequestTrace{FrontendPID: os.Getpid(), AttachRef: "p7", ConnRole: "fskit", RequestID: 1, Origin: 1, localOp: lantrace.LocalLookup, recorder: r}
	ctx := context.WithValue(context.Background(), v3RequestTraceContextKey{}, trace)
	collector := &v3ReplyResourceCollector{d: f.d}
	reply, errno := f.d.dispatchFrontend(context.WithValue(ctx, v3ReplyResourceContextKey{}, collector), 0,
		&pfslocal.LookupRequest{Dir: dir.item, Name: []byte("both")})
	if reply != nil || errno != darwinENOENT || collector.cached == nil {
		t.Fatalf("both caches = (%v,%d)", reply, errno)
	}
	if !collector.cached.revalidate() {
		t.Fatal("candidate refused")
	}
	collector.cached.traceFinal(trace, true)
	collector.retirePending()
	consumeV3ResponseConsumptions(collector.responseConsumptions)
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	report := p6TraceReport(t, stream.Bytes())
	if report.ProducerLost != 0 || report.Rejected != 0 {
		t.Fatalf("trace=%+v", report)
	}
	count := 0
	for _, e := range p6TraceEvents(t, stream.Bytes()) {
		if e.Kind == lantrace.KindCache && e.Phase == lantrace.PhaseFinal {
			count++
			if e.Candidate != lantrace.CandidateEntryCache || e.Cert != lantrace.CertPresent || e.Exposure != lantrace.ExposureAccepted {
				t.Fatalf("double-source attribution=%+v", e)
			}
		}
	}
	if count != 1 {
		t.Fatalf("rescues=%d", count)
	}
	_, _ = coordinator.acknowledge(testCallback(op), pfslocal.PublicationSemanticCommitPublished)
	coordinator.retire(testCallback(op))
}

func TestP7TraceRecordsCertificateAbsenceDropsAndSearchDenial(t *testing.T) {
	for _, kind := range []string{"absent", "permission", "namespace", "denied"} {
		t.Run(kind, func(t *testing.T) {
			f := newCachedV3Fixture(t, v3FileObjects())
			var dir *v3ItemRecord
			cert, drop, search := lantrace.CertAbsent, lantrace.CertDrop(""), lantrace.SearchUnknown
			miss := lantrace.MissUnknownName
			if kind == "absent" {
				f.getattr(f.root)
				dir = f.record(f.root)
			} else {
				if kind == "denied" {
					f.ns.hold = func(req *authoritypb.Request, res *authoritypb.Response) {
						if req.GetMkdir() != nil {
							res.GetMkdir().ChildSearchPermitted = false
						}
					}
				}
				dir = p7Mkdir(t, f, "dir")
				switch kind {
				case "permission":
					f.d.mu.Lock()
					f.d.permissionChangedLocked(dir, dir.watermark+1)
					f.d.mu.Unlock()
					cert, drop = lantrace.CertDropped, lantrace.CertDropPermissionCut
				case "namespace":
					f.d.settleNameErrno(dir, []byte("unseen"), darwinEEXIST)
					cert, drop = lantrace.CertDropped, lantrace.CertDropNamespaceCut
				case "denied":
					cert, search, miss = lantrace.CertPresent, lantrace.SearchDenied, lantrace.MissSearchPermission
				}
			}
			var stream bytes.Buffer
			r := p6Recorder(t, &stream, lantrace.LayerDaemon, lantrace.RecorderConfig{})
			trace := v3RequestTrace{FrontendPID: os.Getpid(), AttachRef: "p7", ConnRole: "fskit", RequestID: 1, Origin: 1, localOp: lantrace.LocalLookup, recorder: r}
			ctx := context.WithValue(context.Background(), v3RequestTraceContextKey{}, trace)
			if _, errno := dispatchV3Test(f.d, ctx, 0, &pfslocal.LookupRequest{Dir: dir.item, Name: []byte("unseen")}); errno != darwinENOENT {
				t.Fatal(errno)
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			report := p6TraceReport(t, stream.Bytes())
			if report.Rejected != 0 || report.ProducerLost != 0 {
				t.Fatalf("trace=%+v", report)
			}
			count := 0
			for _, e := range p6TraceEvents(t, stream.Bytes()) {
				if e.Kind != lantrace.KindCache {
					continue
				}
				count++
				if e.Cert != cert || e.CertDrop != drop || e.Search != search || e.MissReason != miss || e.CacheResult != lantrace.CacheMiss {
					t.Fatalf("decision=%+v", e)
				}
			}
			if count != 2 {
				t.Fatalf("candidate/final records=%d", count)
			}
		})
	}
}

func TestP7ContradictoryErrnoAndLookupDropWholeCertificate(t *testing.T) {
	for _, kind := range []string{"EEXIST", "ENOENT", "positive-lookup", "negative-lookup"} {
		t.Run(kind, func(t *testing.T) {
			f := newCachedV3Fixture(t, v3FileObjects())
			dir := p7Mkdir(t, f, "dir")
			file := p7Create(t, f, dir, "present")
			switch kind {
			case "EEXIST":
				f.d.settleNameErrno(dir, []byte("absent"), darwinEEXIST)
			case "ENOENT":
				f.d.settleNameErrno(dir, []byte("present"), darwinENOENT)
			default:
				f.d.mu.Lock()
				if kind == "positive-lookup" {
					f.d.fillLookupLocked(dir, "absent", f.d.itemsByID[file.Item.ItemID], dir.watermark)
				} else {
					f.d.fillLookupLocked(dir, "present", nil, dir.watermark)
				}
				f.d.mu.Unlock()
			}
			if dir.complete != nil || f.d.completeNames != 0 {
				t.Fatal("contradiction kept part of certificate")
			}
			p7Absence(t, f, dir, "unseen", false)
		})
	}
}

func TestP7ParentRetirementAndAdmissionLoss(t *testing.T) {
	for _, kind := range []string{"retirement", "horizon", "authorization", "client-admission", "terminal"} {
		t.Run(kind, func(t *testing.T) {
			f := newCachedV3Fixture(t, v3FileObjects())
			dir := p7Mkdir(t, f, "dir")
			switch kind {
			case "retirement":
				_, errno := f.dispatch(&pfslocal.ReclaimRequest{Item: dir.item})
				if errno != 0 || dir.complete != nil || f.d.completeDirs != 0 {
					t.Fatal("retirement retained certificate")
				}
				if _, errno := f.dispatch(&pfslocal.LookupRequest{Dir: dir.item, Name: []byte("a")}); errno != darwinESTALE {
					t.Fatal(errno)
				}
				fresh := f.record(f.lookup(f.root, "dir").Item)
				p7Absence(t, f, fresh, "new", false)
			case "horizon":
				f.clock.advance(10 * time.Minute)
				p7Absence(t, f, dir, "new", false)
			case "authorization":
				f.d.mu.Lock()
				f.d.authorizationDeadline = time.Now().Add(-time.Second)
				f.d.mu.Unlock()
				p7Absence(t, f, dir, "new", false)
			default:
				if kind == "terminal" {
					_ = f.d.stopServing(fmt.Errorf("ended"))
				} else {
					f.client.poisoned.Store(true)
				}
				if _, errno := f.dispatch(&pfslocal.LookupRequest{Dir: dir.item, Name: []byte("new")}); errno == darwinENOENT {
					t.Fatal("lost admission served local absence")
				}
			}
		})
	}
}

func TestP7ReadDirEOFNeverSeedsCompleteness(t *testing.T) {
	f := newCachedV3Fixture(t, v3FileObjects())
	f.ns.bind(0x20, "dir", 0x50)
	dir := f.record(f.lookup(f.root, "dir").Item)
	original := f.client.mutation
	f.client.mutation = func(ctx context.Context, id authorityrpc.MutationIdentity, req *authoritypb.Request) (*authoritypb.Response, error) {
		if req.GetReadDir() != nil {
			r := exactTestMutationReply(id)
			r.Body = &authoritypb.Response_ReadDir{ReadDir: &authoritypb.ReadDirReply{Eof: true, Verifier: testV3ID(1)}}
			return r, nil
		}
		return original(ctx, id, req)
	}
	body, errno := f.dispatch(&pfslocal.OpenRequest{Item: dir.item, Mode: pfslocal.OpenModeRead})
	if errno != 0 {
		t.Fatal(errno)
	}
	if _, errno := f.dispatch(&pfslocal.EnumerateEntriesRequest{Dir: dir.item, Handle: body.(*pfslocal.OpenReply).Handle, MaxEntries: 32}); errno != 0 {
		t.Fatal(errno)
	}
	if dir.complete != nil {
		t.Fatal("EOF seeded certificate")
	}
	p7Absence(t, f, dir, "new", false)
}

// Limits are exercised at their actual production values. The injected
// effects have no child capabilities; that is the independence being proved.
func TestP7EveryCompletenessLimit(t *testing.T) {
	for _, kind := range []string{"names", "bytes", "directories"} {
		t.Run(kind, func(t *testing.T) {
			f := newCachedV3Fixture(t, v3FileObjects())
			dir := p7Mkdir(t, f, "dir")
			if kind == "directories" {
				f.d.mu.Lock()
				for i := 1; i < v3MaxCompleteDirs; i++ {
					r := &v3ItemRecord{valid: true, kind: authoritypb.Attr_DIRECTORY,
						item:         pfslocal.Item{ItemID: uint64(i) + 10000, ItemGeneration: 9},
						mkdirWitness: &v3MkdirWitness{snapshot: 2, searchPermitted: true}}
					r.item.StableIdentity[0] = byte(i)
					r.item.StableIdentity[1] = byte(i >> 8)
					r.item.StableIdentity[2] = 1
					f.d.itemsByID[r.item.ItemID] = r
					f.d.itemsByIdentity[r.item.StableIdentity] = r
					f.d.seedMkdirLocked(r)
				}
				f.d.mu.Unlock()
				other := p7Mkdir(t, f, "overflow")
				if other.complete != nil || other.certificateDrop != lantrace.CertDropCapacity || f.d.completeDirs != v3MaxCompleteDirs {
					t.Fatal("directory bound")
				}
				p7Absence(t, f, other, "new", false)
				p7Absence(t, f, dir, "new", true)
				return
			}
			limit := v3MaxCompleteNames
			if kind == "bytes" {
				limit = v3MaxCompleteBytes / 128
			}
			for i := 0; i < limit; i++ {
				name := fmt.Sprintf("%05d", i)
				if kind == "bytes" {
					name += strings.Repeat("x", 128-len(name))
				}
				e := &v3MutationEffect{snapshot: uint64(i) + 3, namesComplete: true, names: []v3NameEffect{{parent: dir, name: name, bound: true}}}
				if err := f.d.applyMutation(e); err != nil {
					t.Fatal(err)
				}
			}
			if dir.complete == nil || f.d.completeNames != limit || kind == "bytes" && f.d.completeBytes != v3MaxCompleteBytes {
				t.Fatal("limit rejected exact capacity")
			}
			// At name capacity a same-directory rename has zero net growth.
			if kind == "names" {
				e := &v3MutationEffect{snapshot: uint64(limit) + 3, namesComplete: true, names: []v3NameEffect{{parent: dir, name: "00000"}, {parent: dir, name: "replacement", bound: true}}}
				if err := f.d.applyMutation(e); err != nil || dir.complete == nil || f.d.completeNames != limit {
					t.Fatal("rename at capacity lost certificate")
				}
			}
			if err := f.d.applyMutation(&v3MutationEffect{snapshot: uint64(limit) + 4, namesComplete: true, names: []v3NameEffect{{parent: dir, name: "overflow", bound: true}}}); err != nil {
				t.Fatal(err)
			}
			if dir.complete != nil || f.d.completeNames != 0 || f.d.completeBytes != 0 || f.d.completeDirs != 0 || dir.certificateDrop != lantrace.CertDropCapacity {
				t.Fatal("overflow retained certificate accounting")
			}
			p7Absence(t, f, dir, "new", false)
		})
	}
}

func TestP7FinalExposureAndTraceAttribution(t *testing.T) {
	for _, kind := range []string{"exposed", "expiry", "authorization", "retirement", "overlapping-effect", "write-failure"} {
		t.Run(kind, func(t *testing.T) {
			f := newCachedV3Fixture(t, v3FileObjects())
			dir := p7Mkdir(t, f, "dir")
			var stream bytes.Buffer
			r := p6Recorder(t, &stream, lantrace.LayerDaemon, lantrace.RecorderConfig{})
			a := &attach{ref: "p7", v3Data: f.d, v3Coherence: f.d.bridge}
			server, peer := net.Pipe()
			defer peer.Close()
			c := &frontendConn{origin: 1, conn: server, attach: a}
			defer c.close()
			const op = 7781
			initialize, ok := c.reserveLogicalOperation(op, true)
			if !initialize || !ok {
				t.Fatal("reserve")
			}
			f.d.bridge.reserveFrontendPublication(testCallback(op))
			var once sync.Once
			c.testBeforeReplyWrite = func(uint64) {
				once.Do(func() {
					switch kind {
					case "expiry":
						f.clock.advance(10 * time.Minute)
					case "authorization":
						f.d.mu.Lock()
						f.d.authorizationDeadline = time.Now().Add(-time.Second)
						f.d.mu.Unlock()
					case "write-failure":
						_ = peer.Close()
					case "overlapping-effect":
						if err := f.d.applyMutation(&v3MutationEffect{snapshot: dir.watermark + 1, namesComplete: true,
							names: []v3NameEffect{{parent: dir, name: "unseen", bound: true}}}); err != nil {
							t.Error(err)
						}
					case "retirement":
						f.d.mu.Lock()
						f.d.detachItemLocked(dir)
						f.d.mu.Unlock()
					}
				})
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			trace := v3RequestTrace{FrontendPID: os.Getpid(), AttachRef: "p7", ConnRole: "fskit", RequestID: 1, OperationID: op, Origin: 1, localOp: lantrace.LocalLookup, recorder: r}
			ctx = context.WithValue(ctx, v3RequestTraceContextKey{}, trace)
			before := f.authorityCalls()
			done := make(chan struct{})
			go func() {
				defer close(done)
				c.handleV3Attached(ctx, a, 1, op, true, &pfslocal.LookupRequest{Dir: dir.item, Name: []byte("unseen")})
			}()
			envelope, err := pfslocal.ReadFrame(peer)
			<-done
			if kind == "retirement" || kind == "write-failure" {
				if err == nil {
					t.Fatal("retired parent exposed local absence")
				}
			} else if err != nil || envelope.Body.(*pfslocal.ErrorReply).Errno != darwinENOENT {
				t.Fatalf("reply=%+v err=%v", envelope, err)
			}
			if (kind == "exposed" || kind == "overlapping-effect") && f.authorityCalls() != before || (kind == "expiry" || kind == "authorization") && f.authorityCalls() != before+1 {
				t.Fatal("wrong authority retry count")
			}
			if kind != "retirement" && kind != "write-failure" {
				_, _ = f.d.bridge.acknowledgePublication(testCallback(op), pfslocal.PublicationSemanticCommitPublished)
				_ = c.acknowledgePublication(op)
			}
			if err := r.Close(); err != nil {
				t.Fatal(err)
			}
			report := p6TraceReport(t, stream.Bytes())
			if report.ProducerLost != 0 || report.Rejected != 0 || report.InconsistentStreams != 0 {
				t.Fatalf("trace=%+v", report)
			}
			candidates, finals, accepted := 0, 0, 0
			for _, e := range p6TraceEvents(t, stream.Bytes()) {
				if e.Kind != lantrace.KindCache {
					continue
				}
				if e.Candidate != lantrace.CandidateCompleteness || e.Cert != lantrace.CertPresent || e.Search != lantrace.SearchPermitted {
					t.Fatalf("decision=%+v", e)
				}
				if e.Phase == lantrace.PhaseCandidate {
					candidates++
				} else {
					finals++
					if e.Exposure == lantrace.ExposureAccepted {
						accepted++
					}
				}
			}
			wantAccepted := 0
			if kind == "exposed" || kind == "overlapping-effect" {
				wantAccepted = 1
			}
			if candidates != 1 || finals != 1 || accepted != wantAccepted {
				t.Fatalf("candidate/final/exposed=%d/%d/%d", candidates, finals, accepted)
			}
		})
	}
}
