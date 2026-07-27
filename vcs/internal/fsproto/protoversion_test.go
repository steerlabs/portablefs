package fsproto

import "testing"

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

// TestProtocolVersionLegacyServer: a server that predates the probe answers EINVAL
// (the dispatch default), which the client must interpret as version 1 — never an
// error, so old servers keep working with new clients.
func TestProtocolVersionLegacyServer(t *testing.T) {
	if got := interpretVersionResponse(&Response{Status: EINVAL}); got != 1 {
		t.Fatalf("EINVAL response mapped to %d, want 1", got)
	}
	// A hypothetical server that answers OK without setting the field is legacy too.
	if got := interpretVersionResponse(&Response{Status: OK}); got != 1 {
		t.Fatalf("OK response without ProtoVersion mapped to %d, want 1", got)
	}
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
