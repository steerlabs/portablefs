package fsproto

import (
	"errors"
	"strings"
	"testing"
)

// ── THE MOUNT THAT WAS TOLD TO LOG IN WITH 4.5 MINUTES OF LEASE LEFT ─────────
//
// The router answered ack 1 for four unrelated conditions, and the client read
// every one of them as "your credential is dead". A mount that lost a race for
// one of the lease's 64 tunnel slots therefore LATCHED a terminal credential
// verdict and told its operator to run `portablefs login` — while the lease it
// was holding had four and a half minutes of validity left, and while re-login
// was not the remedy.
//
// A retryable refusal must leave the credential exactly as unproven as it was.

func TestCapacityRefusalDoesNotLatchACredentialVerdict(t *testing.T) {
	_, backend := serveFS(t)
	router := newFakeRouter(t, backend, "tok-epoch1")
	src := &tokenCell{}
	src.set("tok-epoch1")

	cli, err := DialTLSAuth(router.addr(), 1, nil, src.get)
	if err != nil {
		t.Fatalf("dial through router: %v", err)
	}
	defer cli.Close()
	if _, st, err := cli.Create("f.txt", 0o644); err != nil || st != OK {
		t.Fatalf("seed create: st=%d err=%v", st, err)
	}

	// The lease is at maxTunnelsPerLease. The token is perfectly valid.
	router.refuseEveryDialWith(ackAtCapacity)
	router.rotate("tok-epoch1") // sever the live tunnel, forcing a redial

	_, _, err = cli.Getattr("f.txt")
	if !errors.Is(err, ErrTunnelCapacity) {
		t.Fatalf("a capacity refusal must classify as ErrTunnelCapacity, got %v", err)
	}
	if !errors.Is(err, ErrDialRefused) {
		t.Fatalf("every refusal must stay under the dial-refused umbrella, got %v", err)
	}
	if errors.Is(err, ErrCredentialRefused) {
		t.Fatalf("a capacity refusal must make NO credential claim, got %v", err)
	}
	if cli.CredentialRejected() {
		t.Fatal("a capacity refusal latched a terminal credential verdict; the " +
			"operator is now being told to run `portablefs login` over a lease " +
			"that is not the problem")
	}
	if cli.FailFast() {
		t.Fatal("the router ANSWERED, so the authority is reachable; a capacity " +
			"refusal must not trip the transport breaker either")
	}
	if remedy := RefusalRemedy(err); !strings.Contains(remedy, "tunnel limit") ||
		strings.Contains(remedy, "portablefs login`") {
		t.Fatalf("the operator message must name the real condition and must not "+
			"prescribe re-authentication, got %q", remedy)
	}
}

func TestLeaseTransitionRefusalDoesNotLatchACredentialVerdict(t *testing.T) {
	_, backend := serveFS(t)
	router := newFakeRouter(t, backend, "tok-epoch1")
	src := &tokenCell{}
	src.set("tok-epoch1")

	cli, err := DialTLSAuth(router.addr(), 1, nil, src.get)
	if err != nil {
		t.Fatalf("dial through router: %v", err)
	}
	defer cli.Close()
	if _, st, err := cli.Create("f.txt", 0o644); err != nil || st != OK {
		t.Fatalf("seed create: st=%d err=%v", st, err)
	}

	router.refuseEveryDialWith(ackLeaseTransition)
	router.rotate("tok-epoch1")

	_, _, err = cli.Getattr("f.txt")
	if !errors.Is(err, ErrLeaseTransition) || errors.Is(err, ErrCredentialRefused) {
		t.Fatalf("a lease-transition refusal must classify as itself and claim "+
			"nothing about the credential, got %v", err)
	}
	if cli.CredentialRejected() {
		t.Fatal("a lease-transition race latched a terminal credential verdict")
	}
}

func TestRouterBackendOutageIsNotACredentialVerdict(t *testing.T) {
	_, backend := serveFS(t)
	router := newFakeRouter(t, backend, "tok-epoch1")
	src := &tokenCell{}
	src.set("tok-epoch1")

	cli, err := DialTLSAuth(router.addr(), 1, nil, src.get)
	if err != nil {
		t.Fatalf("dial through router: %v", err)
	}
	defer cli.Close()
	if _, st, err := cli.Create("f.txt", 0o644); err != nil || st != OK {
		t.Fatalf("seed create: st=%d err=%v", st, err)
	}

	router.refuseEveryDialWith(ackAuthorityUnavailable)
	router.rotate("tok-epoch1")

	_, _, err = cli.Getattr("f.txt")
	if !errors.Is(err, ErrRouterBackendUnavailable) || errors.Is(err, ErrCredentialRefused) {
		t.Fatalf("an authority-side outage must not be a credential verdict, got %v", err)
	}
	if cli.CredentialRejected() {
		t.Fatal("an authority outage behind the router latched a credential verdict")
	}
	if remedy := RefusalRemedy(err); !strings.Contains(remedy, "authority-side outage") {
		t.Fatalf("the operator message must name the authority, got %q", remedy)
	}
}

// A code this client has never heard of is what a NEWER router looks like from
// here. It must be a refusal that claims nothing, not an invented verdict.
func TestUnknownRefusalCodeClaimsNothing(t *testing.T) {
	_, backend := serveFS(t)
	router := newFakeRouter(t, backend, "tok-epoch1")
	src := &tokenCell{}
	src.set("tok-epoch1")

	cli, err := DialTLSAuth(router.addr(), 1, nil, src.get)
	if err != nil {
		t.Fatalf("dial through router: %v", err)
	}
	defer cli.Close()
	if _, st, err := cli.Create("f.txt", 0o644); err != nil || st != OK {
		t.Fatalf("seed create: st=%d err=%v", st, err)
	}

	router.refuseEveryDialWith(200)
	router.rotate("tok-epoch1")

	_, _, err = cli.Getattr("f.txt")
	if !errors.Is(err, ErrDialRefusedUnclassified) || errors.Is(err, ErrCredentialRefused) {
		t.Fatalf("an unknown refusal code must classify as unclassified, got %v", err)
	}
	if cli.CredentialRejected() {
		t.Fatal("an unknown refusal code invented a terminal credential verdict")
	}
}

// THE OTHER DIRECTION MUST NOT REGRESS. ack 1 is still a credential verdict,
// it still latches, and it still names login + remount — because for THAT
// condition, that is the truth.
func TestCredentialRefusalStillLatchesAndNamesLogin(t *testing.T) {
	_, backend := serveFS(t)
	router := newFakeRouter(t, backend, "tok-epoch1")
	src := &tokenCell{}
	src.set("tok-epoch1")

	cli, err := DialTLSAuth(router.addr(), 1, nil, src.get)
	if err != nil {
		t.Fatalf("dial through router: %v", err)
	}
	defer cli.Close()
	if _, st, err := cli.Create("f.txt", 0o644); err != nil || st != OK {
		t.Fatalf("seed create: st=%d err=%v", st, err)
	}

	router.rotate("tok-epoch2") // every predecessor token is dead: ack 1

	_, _, err = cli.Getattr("f.txt")
	if !errors.Is(err, ErrCredentialRefused) {
		t.Fatalf("ack 1 must still be the credential verdict, got %v", err)
	}
	if !cli.CredentialRejected() {
		t.Fatal("a genuine credential refusal must still latch")
	}
	if remedy := RefusalRemedy(err); !strings.Contains(remedy, "portablefs login") {
		t.Fatalf("a genuine credential refusal must still name login, got %q", remedy)
	}
}

// An OLD router only ever speaks 0 and 1, and this client must keep reading
// both exactly as it always did.
func TestClassificationIsExactAcrossTheWholeAckByte(t *testing.T) {
	if err := classifyRouterAck(ackAdmitted); err != nil {
		t.Fatalf("ack 0 must admit, got %v", err)
	}
	for ack, want := range map[byte]error{
		ackCredentialRejected:   ErrCredentialRefused,
		ackAtCapacity:           ErrTunnelCapacity,
		ackLeaseTransition:      ErrLeaseTransition,
		ackAuthorityUnavailable: ErrRouterBackendUnavailable,
	} {
		got := classifyRouterAck(ack)
		if !errors.Is(got, want) || !errors.Is(got, ErrDialRefused) {
			t.Fatalf("ack %d = %v, want %v under the refusal umbrella", ack, got, want)
		}
		if ack != ackCredentialRejected && errors.Is(got, ErrCredentialRefused) {
			t.Fatalf("ack %d must not be a credential verdict", ack)
		}
		if RefusalRemedy(got) == "" {
			t.Fatalf("ack %d has no operator remedy", ack)
		}
	}
	for _, ack := range []byte{5, 6, 127, 255} {
		got := classifyRouterAck(ack)
		if !errors.Is(got, ErrDialRefusedUnclassified) || errors.Is(got, ErrCredentialRefused) {
			t.Fatalf("ack %d = %v, want an unclassified refusal", ack, got)
		}
	}
}
