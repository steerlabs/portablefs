package workspaceguest

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	"github.com/steerlabs/portablefs/vcs/internal/workspacemount"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
)

func TestFreshIdentityRetiresExactlyCleanedPredecessorBeforeProvision(t *testing.T) {
	store, err := workspacemount.Open(filepath.Join(t.TempDir(), "identity"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	request := &pb.IdentityRequest{AuthorityId: make([]byte, 32), VolumeId: "volume"}
	request.AuthorityId[0] = 1
	identity, err := store.EnsureIdentity(request)
	if err != nil {
		t.Fatal(err)
	}
	s, err := New(id(1), id(2), id(3), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	s.ConfigureGuest(store, nil, nil)
	w := Witness{Process: "process"}
	if err = s.Register(context.Background(), identity.Mount, w, new(fakeMount)); err != nil {
		t.Fatal(err)
	}
	loss := []*pb.Loss{{Sequence: 1, AcceptedBytes: 7, AcceptedEntries: 1, Reason: "retained lost tail"}}
	if err = s.Terminal(identity.Mount, "terminal", loss); err != nil {
		t.Fatal(err)
	}
	if err = s.Cleanup(identity.Mount, CleanupProof{Witness: w, ProcessExited: true, KernelAbsent: true}); err != nil {
		t.Fatal(err)
	}
	if err = store.Reissue(request, false, func() error { return nil }); err != nil {
		t.Fatal(err)
	}
	fresh, err := s.Identity(request)
	if err != nil {
		t.Fatal(err)
	}
	if control.MountKey(fresh.Mount) == control.MountKey(identity.Mount) || s.Registered(identity.Mount) {
		t.Fatal("old membership blocks fresh provisioning")
	}
	retired := s.Retired()
	if len(retired) != 1 || retired[0].MountStatus.Cleanup != "complete" || retired[0].MountStatus.Loss[0].AcceptedBytes != 7 || retired[0].MountStatus.Outcome.Observation != "unobserved" {
		t.Fatal("replacement erased old evidence", retired)
	}
}

func TestRetirementPersistenceFailureCannotAcknowledgeOrBlockClose(t *testing.T) {
	s, err := New(id(1), id(2), id(3), true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RestoreCleaned(mountID(1), nil, control.UnknownOutcome()); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	s.ConfigureRetirementPersistence(func(ids []*pb.MountID) error {
		if len(ids) != 1 {
			t.Error(ids)
		}
		close(entered)
		<-release
		return errors.New("directory fsync failed")
	})
	done := make(chan error, 1)
	go func() { done <- s.AcknowledgeRetired(1) }()
	<-entered
	if _, err = s.BeginSuspend(suspension(s)); err != nil {
		t.Fatal("retirement fsync blocked Close", err)
	}
	close(release)
	if err = <-done; err == nil || len(s.Retired()) != 1 || s.acknowledgedSequence != 0 {
		t.Fatal("failed commit erased retained outcome", err)
	}
}
