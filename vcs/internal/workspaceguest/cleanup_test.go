package workspaceguest

import (
	"context"
	"testing"

	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
)

// A lost cleanup reply may cause retries with incomplete re-observations.
func TestGuestCompletedCleanupStaysCompleteAcrossRetriesAndReplacement(t *testing.T) {
	s, _, mid := fixture(t)
	if err := s.Terminal(mid, "session ended", nil); err != nil {
		t.Fatal(err)
	}
	w := s.mounts[control.MountKey(mid)].witness
	if err := s.Cleanup(mid, CleanupProof{Witness: w, ProcessExited: true, KernelAbsent: true}); err != nil {
		t.Fatal(err)
	}
	// Retry (e.g. after a lost reply) observes only one half on a re-probe.
	for _, p := range []CleanupProof{{Witness: w, ProcessExited: true}, {Witness: w, KernelAbsent: true}, {Witness: w}, {}} {
		if err := s.Cleanup(mid, p); err != nil {
			t.Fatal(err)
		}
		if s.Status().Mounts[0].Cleanup != "complete" {
			t.Fatal("completed cleanup regressed")
		}
		encodable(t, s.Status())
	}
	t.Logf("live cleanup after retry: %q", s.Status().Mounts[0].Cleanup)
	if err := s.Replace(context.Background(), mid, mountID(5), Witness{}, &fakeMount{}); err != nil {
		t.Fatalf("replace refused: %v", err)
	}
	st := s.Status()
	if _, err := control.Encode(&pb.Envelope{Version: 8, RequestId: 1, Body: &pb.Envelope_StatusReply{StatusReply: st}}); err != nil {
		t.Fatalf("Status unencodable after cleanup retry + replace (Serve would return, channel lost): %v", err)
	}
}
