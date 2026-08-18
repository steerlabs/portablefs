//go:build linux

package authorityrpc

import (
	"context"
	"errors"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/errnos"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

const normalizationDevice = uint64(0x700000001)

func normalizationCoordinate(fill byte, inode uint64) visibilityCoordinate {
	return visibilityCoordinate{identity: [16]byte{fill}, ino: inode, device: normalizationDevice}
}

func normalizationSourceCoordinate(root xfsstore.Capability) visibilityCoordinate {
	return visibilityCoordinate{identity: [16]byte{root[0]}, ino: uint64(root[0]), device: 1}
}

func normalizationSetXattrRequest(root xfsstore.Capability) *authoritypb.Request {
	identity := [16]byte{root[0]}
	return &authoritypb.Request{
		SourcePublicationGate: &authoritypb.SourcePublicationGate{Targets: []*authoritypb.SourcePublicationTarget{{
			Coordinate: &authoritypb.SourcePublicationTarget_Item{Item: &authoritypb.SourcePublicationItem{
				Identity: identity[:], Attributes: true,
			}},
		}}},
		Body: &authoritypb.Request_SetXattr{SetXattr: &authoritypb.SetXattrRequest{
			Item: root[:], Name: []byte("user.normalization"), Value: []byte("value"),
		}},
	}
}

func newCoherentNormalizationMutation(t *testing.T, name string) (*VolumeHandler, volumeserver.SessionCredential, *authoritypb.Request) {
	t.Helper()
	runtime, err := volumeserver.New(name, volumeserver.Config{
		SessionLease: time.Minute, MaxReplaySlots: 2, MaxSessions: 1, MaxLockRecords: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := runtime.AttachActiveForTest(2, volumeserver.PeerIdentity{3}, volumeserver.Authorization{
		Access: volumeserver.AccessRead | volumeserver.AccessWrite, Deadline: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	visibility, err := volumeserver.NewVisibilityCoordinator(volumeserver.VisibilityConfig{
		Prior: volumeserver.PriorEpochStrictMountsFenced, Membership: noopMembership{}, Fencer: runtime,
		MaxCachedNameCapacity: 64, MaxRepairBudget: time.Minute, MaxClockSkew: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := runtime.SessionTerminal(credential.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := visibility.Register(credential.ID, volumeserver.CoherenceStrict, terminal, volumeserver.VisibilityCommitment{
		CachedNameCapacity: 32, RepairBudget: time.Second, NamespaceRepair: volumeserver.NamespaceRepairParentExclusive,
	}); err != nil {
		t.Fatal(err)
	}
	h := testVolumeHandler()
	h.Store = &resourceAdmissionFaultStore{}
	h.Runtime = runtime
	h.Visibility = visibility
	root := xfsstore.Capability{1}
	if err := h.startSessionResources(credential.ID, root, 2, [32]byte{}, volumeserver.CoherenceStrict); err != nil {
		t.Fatal(err)
	}
	request := normalizationSetXattrRequest(root)
	stampMutation(t, request, 0, 1)
	return h, credential, request
}

func TestNormalizeVisibilityTargetsCanonicalizesEveryCoordinateOrdering(t *testing.T) {
	one := normalizationCoordinate(1, 101)
	two := normalizationCoordinate(2, 202)
	parent := normalizationCoordinate(3, 303)
	name := namespaceTarget(parent, []byte("entry"))
	relatedOne := normalizationCoordinate(11, 1111)
	relatedTwo := normalizationCoordinate(12, 1212)
	nameWithRelated := namespaceTargetRelated(parent, []byte("related"), relatedOne, relatedOne)
	nameWithMoreRelated := namespaceTargetRelated(parent, []byte("related"), relatedOne, relatedTwo)
	wantRelated := namespaceTargetRelated(parent, []byte("related"), relatedOne, relatedTwo)
	attrOne := inodeTarget(volumeserver.VisibilityAttributes, one, 0)
	dataOne := inodeTarget(volumeserver.VisibilityData, one, 4096)
	attrTwo := inodeTarget(volumeserver.VisibilityAttributes, two, 0)
	dataTwo := inodeTarget(volumeserver.VisibilityData, two, 8192)

	tests := []struct {
		name string
		in   []volumeserver.VisibilityTarget
		want []volumeserver.VisibilityTarget
	}{
		{name: "nil stays nil", in: nil, want: nil},
		{name: "non-nil empty stays non-nil empty", in: []volumeserver.VisibilityTarget{}, want: []volumeserver.VisibilityTarget{}},
		{name: "one inode is unchanged", in: []volumeserver.VisibilityTarget{dataOne}, want: []volumeserver.VisibilityTarget{dataOne}},
		{name: "namespace duplicates collapse", in: []volumeserver.VisibilityTarget{name, name}, want: []volumeserver.VisibilityTarget{name}},
		{
			name: "one namespace deduplicates its own dependencies",
			in:   []volumeserver.VisibilityTarget{nameWithRelated},
			want: []volumeserver.VisibilityTarget{namespaceTargetRelated(parent, []byte("related"), relatedOne)},
		},
		{
			name: "namespace dependencies union in first-occurrence order",
			in:   []volumeserver.VisibilityTarget{nameWithRelated, nameWithMoreRelated},
			want: []volumeserver.VisibilityTarget{wantRelated},
		},
		{name: "duplicate attributes collapse", in: []volumeserver.VisibilityTarget{attrOne, attrOne}, want: []volumeserver.VisibilityTarget{attrOne}},
		{name: "duplicate data collapse", in: []volumeserver.VisibilityTarget{dataOne, dataOne}, want: []volumeserver.VisibilityTarget{dataOne}},
		{name: "data replaces earlier attributes in place", in: []volumeserver.VisibilityTarget{attrOne, dataOne}, want: []volumeserver.VisibilityTarget{dataOne}},
		{name: "earlier data dominates later attributes", in: []volumeserver.VisibilityTarget{dataOne, attrOne}, want: []volumeserver.VisibilityTarget{dataOne}},
		{
			name: "first coordinate occurrence orders interleaved targets",
			in:   []volumeserver.VisibilityTarget{attrOne, nameWithRelated, attrTwo, dataOne, nameWithMoreRelated, dataTwo, attrOne, dataTwo},
			want: []volumeserver.VisibilityTarget{dataOne, wantRelated, dataTwo},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := normalizeVisibilityTargets(test.in)
			if err != nil {
				t.Fatalf("normalize: %v", err)
			}
			if !reflect.DeepEqual(got, test.want) {
				t.Fatalf("normalized targets = %#v, want %#v", got, test.want)
			}
			if test.in != nil && got == nil {
				t.Fatal("normalization changed a non-nil no-change marker into nil")
			}
		})
	}
}

func TestNormalizeVisibilityTargetsValidatesAllRawTargetsBeforeDominance(t *testing.T) {
	coordinate := normalizationCoordinate(4, 404)
	validData := inodeTarget(volumeserver.VisibilityData, coordinate, 128)
	malformedAttributes := inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0)
	malformedAttributes.Size = 1

	_, err := normalizeVisibilityTargets([]volumeserver.VisibilityTarget{validData, malformedAttributes})
	if !errors.Is(err, volumeserver.ErrVisibilityTargets) {
		t.Fatalf("malformed dominated ATTRIBUTES target = %v, want ErrVisibilityTargets", err)
	}
}

func TestNormalizeVisibilityTargetsRejectsEveryMalformedAuthorityShape(t *testing.T) {
	object := normalizationCoordinate(5, 505)
	parent := normalizationCoordinate(6, 606)
	related := normalizationCoordinate(7, 707)
	validNamespace := func() volumeserver.VisibilityTarget {
		return namespaceTargetPost(parent, []byte("entry"), related)
	}
	validData := func() volumeserver.VisibilityTarget {
		return inodeTarget(volumeserver.VisibilityData, object, 64)
	}
	validAttributes := func() volumeserver.VisibilityTarget {
		return inodeTarget(volumeserver.VisibilityAttributes, object, 0)
	}

	tests := []struct {
		name   string
		target func() volumeserver.VisibilityTarget
	}{
		{"unknown scope", func() volumeserver.VisibilityTarget { target := validData(); target.Scope = 99; return target }},
		{"missing device", func() volumeserver.VisibilityTarget { target := validData(); target.Device = 0; return target }},
		{"namespace missing parent identity", func() volumeserver.VisibilityTarget {
			target := validNamespace()
			target.ParentIdentity = [16]byte{}
			return target
		}},
		{"namespace with object identity", func() volumeserver.VisibilityTarget {
			target := validNamespace()
			target.Identity = object.identity
			return target
		}},
		{"namespace invalid name", func() volumeserver.VisibilityTarget {
			target := validNamespace()
			target.Name = []byte("a/b")
			return target
		}},
		{"namespace with size", func() volumeserver.VisibilityTarget { target := validNamespace(); target.Size = 1; return target }},
		{"namespace with object kernel inode", func() volumeserver.VisibilityTarget { target := validNamespace(); target.KernelIno = 1; return target }},
		{"namespace missing parent kernel inode", func() volumeserver.VisibilityTarget {
			target := validNamespace()
			target.ParentKernelIno = 0
			return target
		}},
		{"namespace zero related identity", func() volumeserver.VisibilityTarget {
			target := validNamespace()
			target.RelatedIdentities = append(target.RelatedIdentities, [16]byte{})
			return target
		}},
		{"namespace post identity is not a dependency", func() volumeserver.VisibilityTarget {
			target := validNamespace()
			target.RelatedIdentities = [][16]byte{{8}}
			return target
		}},
		{"inode missing identity", func() volumeserver.VisibilityTarget {
			target := validData()
			target.Identity = [16]byte{}
			return target
		}},
		{"inode with parent identity", func() volumeserver.VisibilityTarget {
			target := validData()
			target.ParentIdentity = parent.identity
			return target
		}},
		{"inode with name", func() volumeserver.VisibilityTarget {
			target := validData()
			target.Name = []byte("entry")
			return target
		}},
		{"inode with post identity", func() volumeserver.VisibilityTarget {
			target := validData()
			target.PostIdentity = related.identity
			return target
		}},
		{"inode with namespace dependencies", func() volumeserver.VisibilityTarget {
			target := validData()
			target.RelatedIdentities = [][16]byte{related.identity}
			return target
		}},
		{"inode missing kernel inode", func() volumeserver.VisibilityTarget { target := validData(); target.KernelIno = 0; return target }},
		{"inode with parent kernel inode", func() volumeserver.VisibilityTarget {
			target := validData()
			target.ParentKernelIno = parent.ino
			return target
		}},
		{"data with negative size", func() volumeserver.VisibilityTarget { target := validData(); target.Size = -1; return target }},
		{"attributes with size", func() volumeserver.VisibilityTarget { target := validAttributes(); target.Size = 1; return target }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := normalizeVisibilityTargets([]volumeserver.VisibilityTarget{test.target()})
			if !errors.Is(err, volumeserver.ErrVisibilityTargets) {
				t.Fatalf("malformed target = %v, want ErrVisibilityTargets", err)
			}
		})
	}
}

func TestNormalizeVisibilityTargetsRejectsConflictingInodeClaims(t *testing.T) {
	coordinate := normalizationCoordinate(8, 808)
	data := inodeTarget(volumeserver.VisibilityData, coordinate, 100)

	tests := []struct {
		name   string
		second volumeserver.VisibilityTarget
	}{
		{"different authoritative DATA size", func() volumeserver.VisibilityTarget { target := data; target.Size = 101; return target }()},
		{"different kernel inode", func() volumeserver.VisibilityTarget { target := data; target.KernelIno++; return target }()},
		{"different device", func() volumeserver.VisibilityTarget { target := data; target.Device++; return target }()},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := normalizeVisibilityTargets([]volumeserver.VisibilityTarget{data, test.second})
			if !errors.Is(err, volumeserver.ErrVisibilityTargets) {
				t.Fatalf("conflicting inode targets = %v, want ErrVisibilityTargets", err)
			}
		})
	}
}

func TestNormalizeVisibilityTargetsRejectsConflictingNamespaceClaims(t *testing.T) {
	parent := normalizationCoordinate(13, 1313)
	postOne := normalizationCoordinate(14, 1414)
	postTwo := normalizationCoordinate(15, 1515)
	namespace := namespaceTargetPost(parent, []byte("entry"), postOne)

	tests := []struct {
		name   string
		second volumeserver.VisibilityTarget
	}{
		{"different parent kernel inode", func() volumeserver.VisibilityTarget { target := namespace; target.ParentKernelIno++; return target }()},
		{"different device", func() volumeserver.VisibilityTarget { target := namespace; target.Device++; return target }()},
		{"different post identity", namespaceTargetPost(parent, []byte("entry"), postTwo)},
		{"post identity versus no post identity", namespaceTarget(parent, []byte("entry"))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := normalizeVisibilityTargets([]volumeserver.VisibilityTarget{namespace, test.second})
			if !errors.Is(err, volumeserver.ErrVisibilityTargets) {
				t.Fatalf("conflicting namespace targets = %v, want ErrVisibilityTargets", err)
			}
		})
	}
}

func TestMutateVisibleNormalizesPrepareAndCompletionCentrally(t *testing.T) {
	runtime, err := volumeserver.New("authority-target-normalization", volumeserver.Config{
		SessionLease: time.Minute, MaxReplaySlots: 2, MaxSessions: 2, MaxLockRecords: 8,
	})
	if err != nil {
		t.Fatal(err)
	}
	source, err := runtime.AttachActiveForTest(2, volumeserver.PeerIdentity{1}, volumeserver.Authorization{
		Access: volumeserver.AccessRead | volumeserver.AccessWrite, Deadline: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	observer, err := runtime.AttachActiveForTest(2, volumeserver.PeerIdentity{2}, volumeserver.Authorization{
		Access: volumeserver.AccessRead, Deadline: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	visibility, err := volumeserver.NewVisibilityCoordinator(volumeserver.VisibilityConfig{
		Prior: volumeserver.PriorEpochStrictMountsFenced, Membership: noopMembership{}, Fencer: runtime,
		MaxCachedNameCapacity: 64, MaxRepairBudget: time.Minute, MaxClockSkew: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := runtime.SessionTerminal(observer.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := visibility.Register(observer.ID, volumeserver.CoherenceStrict, terminal, volumeserver.VisibilityCommitment{
		CachedNameCapacity: 32, RepairBudget: time.Second, NamespaceRepair: volumeserver.NamespaceRepairParentExclusive,
	}); err != nil {
		t.Fatal(err)
	}
	sourceTerminal, err := runtime.SessionTerminal(source.ID)
	if err != nil {
		t.Fatal(err)
	}
	if err := visibility.Register(source.ID, volumeserver.CoherenceStrict, sourceTerminal, volumeserver.VisibilityCommitment{
		CachedNameCapacity: 32, RepairBudget: time.Second, NamespaceRepair: volumeserver.NamespaceRepairParentExclusive,
	}); err != nil {
		t.Fatal(err)
	}

	root := xfsstore.Capability{1}
	// The sequencer requires PREPARE to be covered by the request's independently
	// declared source gate. Model the SETXATTR target with the same coordinate the
	// store returns instead of an unrelated synthetic inode identity.
	coordinate := normalizationSourceCoordinate(root)
	visibility.RecordResolvedInode(observer.ID, coordinate.identity)
	prepareData := inodeTarget(volumeserver.VisibilityData, coordinate, 100)
	completeData := inodeTarget(volumeserver.VisibilityData, coordinate, 200)
	attributes := inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0)

	h := testVolumeHandler()
	h.Store = &resourceAdmissionFaultStore{}
	h.Runtime = runtime
	h.Visibility = visibility
	if err := h.startSessionResources(source.ID, root, 2, [32]byte{}, volumeserver.CoherenceStrict); err != nil {
		t.Fatal(err)
	}
	request := normalizationSetXattrRequest(root)
	stampMutation(t, request, 0, 1)
	response := make(chan *authoritypb.Response, 1)
	go func() {
		response <- h.mutateVisible(context.Background(), request, source,
			func() ([]volumeserver.VisibilityTarget, error) {
				return []volumeserver.VisibilityTarget{attributes, prepareData, attributes}, nil
			},
			func() (*authoritypb.Response, []volumeserver.VisibilityTarget) {
				return h.success(0), []volumeserver.VisibilityTarget{attributes, completeData, completeData}
			})
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	initial := testInitialVisibilityCursor(t, visibility, observer.ID)
	prepare, err := visibility.Next(ctx, observer.ID, initial)
	if err != nil {
		t.Fatal(err)
	}
	if prepare.Cursor.Phase != volumeserver.VisibilityPrepare || !reflect.DeepEqual(prepare.Targets, []volumeserver.VisibilityTarget{prepareData}) {
		t.Fatalf("PREPARE targets = %#v, want one DATA target %#v", prepare.Targets, prepareData)
	}
	if err := visibility.Ack(observer.ID, prepare.Cursor); err != nil {
		t.Fatal(err)
	}
	complete, err := visibility.Next(ctx, observer.ID, prepare.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if complete.Cursor.Phase != volumeserver.VisibilityComplete || !reflect.DeepEqual(complete.Targets, []volumeserver.VisibilityTarget{completeData}) {
		t.Fatalf("COMPLETE targets = %#v, want one DATA target %#v", complete.Targets, completeData)
	}
	if err := visibility.Ack(observer.ID, complete.Cursor); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-response:
		if got.GetErrno() != 0 || got.GetUncertain() {
			t.Fatalf("normalized visible mutation = %+v, want success", got)
		}
	case <-ctx.Done():
		t.Fatal("normalized visible mutation did not complete")
	}
}

func TestMutateVisibleFailsClosedAroundNormalizationDefects(t *testing.T) {
	// These targets must use the SETXATTR fixture's source identity. Otherwise
	// dependency coverage rejects them before apply and the table cannot test the
	// pre- versus post-apply normalization boundary it is about.
	coordinate := normalizationSourceCoordinate(xfsstore.Capability{1})
	data := inodeTarget(volumeserver.VisibilityData, coordinate, 100)
	attributes := inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0)
	tests := []struct {
		name          string
		prepare       []volumeserver.VisibilityTarget
		complete      []volumeserver.VisibilityTarget
		wantApply     uint32
		wantUncertain bool
	}{
		{
			name: "malformed dominated prepare target is definite",
			prepare: func() []volumeserver.VisibilityTarget {
				malformed := attributes
				malformed.Size = 1
				return []volumeserver.VisibilityTarget{data, malformed}
			}(),
			complete: []volumeserver.VisibilityTarget{data},
		},
		{
			name:    "conflicting completion DATA sizes poison after apply",
			prepare: []volumeserver.VisibilityTarget{data},
			complete: func() []volumeserver.VisibilityTarget {
				conflict := data
				conflict.Size++
				return []volumeserver.VisibilityTarget{data, conflict}
			}(),
			wantApply:     1,
			wantUncertain: true,
		},
		{
			name:          "non-nil empty completion remains a post-apply defect",
			prepare:       []volumeserver.VisibilityTarget{data},
			complete:      []volumeserver.VisibilityTarget{},
			wantApply:     1,
			wantUncertain: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			h, credential, request := newCoherentNormalizationMutation(t, "authority-target-normalization-failure")
			var applyCalls atomic.Uint32
			response := h.mutateVisible(context.Background(), request, credential,
				func() ([]volumeserver.VisibilityTarget, error) { return test.prepare, nil },
				func() (*authoritypb.Response, []volumeserver.VisibilityTarget) {
					applyCalls.Add(1)
					return h.success(0), test.complete
				})
			if response.GetErrno() != errnos.EIO || response.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_COHERENCE {
				t.Fatalf("normalization defect response = %+v, want coherence EIO", response)
			}
			if response.GetUncertain() != test.wantUncertain {
				t.Fatalf("normalization defect uncertain = %v, want %v", response.GetUncertain(), test.wantUncertain)
			}
			if got := applyCalls.Load(); got != test.wantApply {
				t.Fatalf("apply calls = %d, want %d", got, test.wantApply)
			}
		})
	}
}

func TestMutateVisiblePreservesNilCompletionAsNoVisibleChange(t *testing.T) {
	coordinate := normalizationSourceCoordinate(xfsstore.Capability{1})
	data := inodeTarget(volumeserver.VisibilityData, coordinate, 100)
	h, credential, request := newCoherentNormalizationMutation(t, "authority-target-normalization-nil")
	response := h.mutateVisible(context.Background(), request, credential,
		func() ([]volumeserver.VisibilityTarget, error) { return []volumeserver.VisibilityTarget{data}, nil },
		func() (*authoritypb.Response, []volumeserver.VisibilityTarget) { return h.success(0), nil })
	if response.GetErrno() != 0 || response.GetUncertain() {
		t.Fatalf("nil completion = %+v, want successful no-visible-change result", response)
	}
}
