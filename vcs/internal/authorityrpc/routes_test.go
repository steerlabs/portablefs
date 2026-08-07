package authorityrpc

import (
	"bytes"
	"errors"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
)

// A routing refusal exists so a mount that has never seen this volume can adopt
// its declaration and retry on the same capability. Flattening it to a string
// at the client boundary leaves the refusal self-sufficient on the wire and
// useless in Go: there is nothing to adopt in a sentence. The decoded error has
// to carry the revision and the rules, and still answer errors.Is for callers
// that only want to know what kind of failure it is.
func TestRoutesRefusalDecodesToAnAdoptablePayload(t *testing.T) {
	rules := []byte("node_modules\n")
	parsed, err := localroutes.Parse(rules)
	if err != nil {
		t.Fatal(err)
	}
	active := parsed.Revision()
	presented := [32]byte{9}
	wire := (&RoutesMismatchError{
		Active: active, Presented: presented, Declared: true, Subject: "attach",
		Canonical: parsed.Canonical(),
	}).proto()

	var decoded error = routesMismatchError(wire)
	if !errors.Is(decoded, ErrRoutesMismatch) {
		t.Fatal("a decoded routing refusal does not classify as ErrRoutesMismatch")
	}
	var mismatch *RoutesMismatchError
	if !errors.As(decoded, &mismatch) {
		t.Fatal("a decoded routing refusal carries no payload")
	}
	if mismatch.Active != active {
		t.Fatalf("active revision = %x, want %x", mismatch.Active, active)
	}
	if mismatch.Presented != presented || !mismatch.Declared {
		t.Fatalf("presented revision = %x declared=%v, want %x declared=true", mismatch.Presented, mismatch.Declared, presented)
	}
	// The declaration has to be the thing a mount can parse and adopt, and
	// adopting it has to produce exactly the revision the authority is running.
	adopted, err := localroutes.Parse(mismatch.Canonical)
	if err != nil {
		t.Fatalf("the declaration in the refusal does not parse: %v", err)
	}
	if adopted.Revision() != active {
		t.Fatalf("adopting the declaration yields %x, want %x", adopted.Revision(), active)
	}
	// The message an operator reads is the one the authority wrote, not one
	// recomposed here from fields a different build might render differently.
	if mismatch.Error() != wire.GetDetail() {
		t.Fatalf("Error() = %q, want the authority's detail %q", mismatch.Error(), wire.GetDetail())
	}
}

// A refusal with no revision presented is still a refusal, and a caller must
// not be able to mistake "the peer said nothing" for "the peer said zero".
func TestRoutesRefusalWithoutAPresentedRevisionSaysSo(t *testing.T) {
	wire := (&RoutesMismatchError{Active: [32]byte{1}, Subject: "attach", Canonical: []byte("target\n")}).proto()
	decoded := routesMismatchError(wire)
	if decoded.Declared {
		t.Fatal("a refusal of a mount that declared nothing reports a presented revision")
	}
	if decoded.Presented != ([32]byte{}) {
		t.Fatalf("presented revision = %x, want zero", decoded.Presented)
	}
	if !bytes.Equal(decoded.Canonical, []byte("target\n")) {
		t.Fatalf("declaration = %q, want the volume's", decoded.Canonical)
	}
	if routesMismatchError(nil) != nil {
		t.Fatal("a response with no routing mismatch decoded to a refusal")
	}
	// A revision of the wrong length is dropped rather than guessed at.
	short := routesMismatchError(&authoritypb.RoutesMismatch{ActiveRevision: []byte{1, 2, 3}, PresentedRevision: []byte{4}})
	if short.Active != ([32]byte{}) || short.Declared {
		t.Fatalf("a malformed revision was accepted: active=%x declared=%v", short.Active, short.Declared)
	}
}
