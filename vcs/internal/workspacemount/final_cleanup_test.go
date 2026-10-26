package workspacemount

import (
	"bytes"
	"errors"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"google.golang.org/protobuf/proto"
	"testing"
)

// Only generated test certificates and t.TempDir state are used.
func TestProvisionOnlyColdBootAllowsFreshProvision(t *testing.T) {
	s, first := store(t)
	if err := s.AcceptProvision(t.Context(), provision(t, first, false), ready); err != nil {
		t.Fatal(err)
	}
	directory := s.directory
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	next, err := Open(directory)
	if err != nil {
		t.Fatal(err)
	}
	defer next.Close()
	if err = next.ReconcileProvisioning(func(id *pb.MountID) error { return nil }); err != nil {
		t.Fatal(err)
	}
	identity, err := next.EnsureIdentity(request())
	if err != nil {
		t.Fatal(err)
	}
	// There is no root mount inventory: the previous boot stopped after Provision.
	if err = next.AcceptProvision(t.Context(), provision(t, identity, false), ready); err != nil {
		t.Fatalf("fresh provision after a provision-only cold boot is permanently refused: %v", err)
	}
}

func TestProvisionReconciliationRequiresAbsenceAndPreservesIdentity(t *testing.T) {
	s, before := store(t)
	if err := s.AcceptProvision(t.Context(), provision(t, before, false), ready); err != nil {
		t.Fatal(err)
	}
	failure := errors.New("CLI or kernel resource still owned")
	if err := s.ReconcileProvisioning(func(id *pb.MountID) error { return failure }); !errors.Is(err, failure) {
		t.Fatal(err)
	}
	if _, _, err := s.Provisioned(before.Mount); err != nil {
		t.Fatal("refusal erased provision", err)
	}
	for n := 0; n < 2; n++ {
		if err := s.ReconcileProvisioning(func(id *pb.MountID) error {
			if !proto.Equal(id, before.Mount) {
				t.Fatal(id)
			}
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	after, err := s.EnsureIdentity(request())
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(before.Mount.Incarnation, after.Mount.Incarnation) || !bytes.Equal(before.PublicKey, after.PublicKey) || !bytes.Equal(before.GuestUuid, after.GuestUuid) || !bytes.Equal(before.IdentityIncarnation, after.IdentityIncarnation) || before.RenewalEpoch != after.RenewalEpoch {
		t.Fatal("mount cleanup changed persistent identity")
	}
	if err = s.AcceptProvision(t.Context(), provision(t, after, false), ready); err != nil {
		t.Fatal(err)
	}
}

func TestProvisionRemovalCannotRetireReplacementIncarnation(t *testing.T) {
	s, first := store(t)
	initial := provision(t, first, false)
	if err := s.AcceptProvision(t.Context(), initial, ready); err != nil {
		t.Fatal(err)
	}
	absent := func() error { return nil }
	if err := s.RetireProvision(first.Mount, absent); err != nil {
		t.Fatal(err)
	}
	if err := s.RetireProvision(first.Mount, absent); err != nil {
		t.Fatal("lost cleanup acknowledgement was not retryable", err)
	}
	replacement, err := s.EnsureIdentity(request())
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RetireProvision(first.Mount, absent); err == nil {
		t.Fatal("old cleanup retired a selected replacement awaiting issuance")
	}
	grant := provision(t, replacement, false)
	if err = s.AcceptProvision(t.Context(), grant, ready); err != nil {
		t.Fatal(err)
	}
	if err = s.RetireProvision(first.Mount, absent); err == nil {
		t.Fatal("old cleanup retired a replacement grant")
	}
	retained, _, err := s.Provisioned(replacement.Mount)
	if err != nil || !proto.Equal(retained, grant) {
		t.Fatal("replacement ownership changed", err)
	}
	if err = s.RetireProvision(replacement.Mount, func() error { return errors.New("kernel absence unknown") }); err == nil {
		t.Fatal("grant retired before absence")
	}
	if err = s.RetireProvision(replacement.Mount, absent); err != nil {
		t.Fatal("replacement cleanup failed", err)
	}
}
