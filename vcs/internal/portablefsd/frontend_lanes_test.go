package portablefsd

import (
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// The live failure this pins: the frontend's control lane (visibility
// acknowledgments, liveness) deliberately overtakes queued ordinary requests,
// so under a mutation storm a barrier acknowledgment legally arrives with a
// LOWER request id than an ordinary frame already received. A single global
// watermark read that as replay and closed the connection — killing the mount
// the moment it was busy enough for the ack to overtake anything.
func TestControlLaneMayOvertakeOrdinaryRequests(t *testing.T) {
	var lastRequest, lastControl uint64
	admit := func(body any, id uint64) bool {
		_, ok := admitLaneRequestID(body, id, &lastRequest, &lastControl)
		return ok
	}
	lookup := &pfslocal.LookupRequest{}
	ack := &pfslocal.VisibilityAckRequest{}
	liveness := &pfslocal.V3LivenessRequest{}

	if !admit(lookup, 5) {
		t.Fatal("ordinary request 5 refused")
	}
	// The storm shape: the ack was allocated id 3 before the burst but its
	// lane delivered it after ordinary id 5.
	if !admit(ack, 3) {
		t.Fatal("a control frame with a lower id than the ordinary watermark was refused; the priority lane's whole point is overtaking the request burst")
	}
	if !admit(lookup, 6) {
		t.Fatal("ordinary request 6 refused after a control frame")
	}
	if !admit(liveness, 4) {
		t.Fatal("liveness with a lower id than the ordinary watermark was refused")
	}

	// Replay protection survives per lane.
	if admit(lookup, 6) {
		t.Fatal("a replayed ordinary id was admitted")
	}
	if admit(ack, 4) {
		t.Fatal("a replayed control id was admitted")
	}
	if admit(lookup, 0) {
		t.Fatal("request id zero was admitted")
	}
}
