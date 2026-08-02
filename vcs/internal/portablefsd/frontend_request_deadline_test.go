package portablefsd

import (
	"errors"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// THE BOUND THE FRONTEND WAITS FOR IS DERIVED FROM THE BOUND THE DAEMON KEEPS.
//
// D1a was not a bug in either number, it was the absence of any relationship
// between them: the extension carried a compiled-in 60s reply deadline and the
// daemon gave one request a 50s admission budget, in different languages, with
// nothing connecting them. Ten seconds is not a margin — one cold create that
// legitimately used most of its admission budget expired the frontend's bound
// first, the frontend closed the WHOLE connection over it, and the daemon's
// disconnect path turned that into a permanent whole-mount coherence failure.
//
// The daemon now advertises the bound (HelloReply.RequestDeadlineMs, protocol
// minor 7) so the two cannot drift apart again. This test is the guard on the
// only property that actually matters: the advertised bound must STRICTLY
// EXCEED the daemon's own per-operation budget, with real room, whatever either
// number is changed to.
func TestAdvertisedFrontendDeadlineStrictlyExceedsOperationBudget(t *testing.T) {
	budget := clientcore.OperationAdmissionBudget()
	advertised := frontendRequestDeadline()
	if advertised <= budget {
		t.Fatalf(
			"advertised frontend request deadline %s must strictly exceed the "+
				"daemon's own operation admission budget %s; a frontend bound at "+
				"or below it expires on requests the daemon is still answering",
			advertised, budget,
		)
	}
	if frontendRequestDeadlineFactor < 2 {
		t.Fatalf(
			"frontendRequestDeadlineFactor = %d leaves no room for the part of a "+
				"handler that is not admission; the live battery recorded an "+
				"80s rmdir that SUCCEEDED against a 50s admission budget",
			frontendRequestDeadlineFactor,
		)
	}
	// It must also survive the wire as milliseconds in a uint32.
	ms := advertised.Milliseconds()
	if ms <= 0 || ms > int64(^uint32(0)) {
		t.Fatalf("advertised deadline %s does not fit HelloReply.RequestDeadlineMs", advertised)
	}
}

// The advertised bound must actually reach the wire: a frontend that reads zero
// keeps its own constant, which is the state this whole mechanism removes.
func TestHelloReplyCarriesTheRequestDeadlineAcrossTheWire(t *testing.T) {
	sent := &pfslocal.HelloReply{
		ProtocolMajor:     pfslocal.ProtocolMajor,
		ProtocolMinor:     pfslocal.ProtocolMinor,
		DaemonVersion:     "test",
		RequestDeadlineMs: uint32(frontendRequestDeadline().Milliseconds()),
	}
	if sent.RequestDeadlineMs == 0 {
		t.Fatal("daemon advertised a zero request deadline")
	}
	round, err := roundTripHelloReply(sent)
	if err != nil {
		t.Fatal(err)
	}
	if round.RequestDeadlineMs != sent.RequestDeadlineMs {
		t.Fatalf(
			"RequestDeadlineMs did not survive the wire: got %d, want %d",
			round.RequestDeadlineMs, sent.RequestDeadlineMs,
		)
	}
	if round.ProtocolMinor != pfslocal.ProtocolMinor {
		t.Fatalf("ProtocolMinor = %d, want %d", round.ProtocolMinor, pfslocal.ProtocolMinor)
	}
	// The field is only meaningful if the minor gate keeps a frontend that
	// ignores it from pairing at all.
	if pfslocal.ProtocolMinor < 7 {
		t.Fatalf(
			"ProtocolMinor = %d: the advertised deadline needs a minor bump, or a "+
				"frontend that ignores it can still pair and keep the constant that broke",
			pfslocal.ProtocolMinor,
		)
	}
	_ = time.Duration(0)
}

func roundTripHelloReply(in *pfslocal.HelloReply) (*pfslocal.HelloReply, error) {
	encoded, err := pfslocal.MarshalEnvelope(&pfslocal.Envelope{RequestID: 1, Body: in})
	if err != nil {
		return nil, err
	}
	decoded, err := pfslocal.UnmarshalEnvelope(encoded)
	if err != nil {
		return nil, err
	}
	reply, ok := decoded.Body.(*pfslocal.HelloReply)
	if !ok {
		return nil, errUnexpectedHelloReplyBody
	}
	return reply, nil
}

var errUnexpectedHelloReplyBody = errors.New("decoded envelope did not carry a HelloReply")
