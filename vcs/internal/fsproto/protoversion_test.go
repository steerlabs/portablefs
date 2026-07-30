package fsproto

import (
	"strings"
	"testing"
)

// TestProtocolVersionProbe: a current server answers the probe with its version,
// end to end over a real connection.
func TestProtocolVersionProbe(t *testing.T) {
	cli := serve(t)
	v, err := cli.NegotiateProtocolVersion()
	if err != nil {
		t.Fatalf("negotiate: %v", err)
	}
	if v != ProtocolVersion {
		t.Fatalf("negotiated version = %d, want %d", v, ProtocolVersion)
	}
}

// TestProtocolVersionMismatchIsClear: an authority speaking any other
// version fails negotiation with an error naming both versions — the v2
// compat story is the wire-level version error, never a downgrade.
func TestProtocolVersionMismatchIsClear(t *testing.T) {
	err := &ErrProtocolVersionMismatch{ServerVersion: 4}
	if msg := err.Error(); msg == "" {
		t.Fatal("mismatch error must carry a message")
	} else if want := "protocol version 4"; !contains(msg, want) || !contains(msg, "requires exactly 8") {
		t.Fatalf("mismatch error %q must name both versions", msg)
	}
	// A pre-negotiation authority (probe rejected / no version) is reported
	// as such, not mapped to a silent downgrade.
	old := &ErrProtocolVersionMismatch{ServerVersion: 0}
	if msg := old.Error(); !contains(msg, "predates protocol negotiation") {
		t.Fatalf("pre-negotiation error %q must say so", msg)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && strings.Contains(s, sub)
}

// TestProtocolVersionProbeDoesNotDisturbSession: the probe is a plain request on the
// pooled connection; filesystem ops before and after it behave identically.
func TestProtocolVersionProbeDoesNotDisturbSession(t *testing.T) {
	cli := serve(t)
	if _, st, err := cli.Create("probe.txt", 0o644); err != nil || st != OK {
		t.Fatalf("create before probe: st=%d err=%v", st, err)
	}
	if _, st, err := cli.Write("probe.txt", 0, []byte("before"), 0o644); err != nil || st != OK {
		t.Fatalf("write before probe: st=%d err=%v", st, err)
	}
	if _, err := cli.NegotiateProtocolVersion(); err != nil {
		t.Fatalf("negotiate: %v", err)
	}
	data, _, _, st, err := cli.ReadV("probe.txt", 0, 6)
	if err != nil || st != OK || string(data) != "before" {
		t.Fatalf("read after probe = %q st=%d err=%v", data, st, err)
	}
}
