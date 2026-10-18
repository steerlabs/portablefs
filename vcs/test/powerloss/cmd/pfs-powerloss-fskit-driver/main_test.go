package main

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
)

func completeArguments() []string {
	return []string{
		"--authority", "127.0.0.1:1", "--volume-id", "powerloss-volume", "--volume", "powerloss-volume",
		"--access-token-file", "/creds/access-1.token", "--tls-cert", "/creds/client.crt", "--tls-key", "/creds/client.key",
		"--tls-server-ca", "/creds/ca.pem", "--tls-server-name", "authority.portablefs.test",
		"--ledger", "/ledgers/fskit.json", "--label", "unit",
	}
}

func TestParseOptionsRejectsIncompleteInvocations(t *testing.T) {
	without := func(flag string) []string {
		var arguments []string
		complete := completeArguments()
		for index := 0; index < len(complete); index += 2 {
			if complete[index] != flag {
				arguments = append(arguments, complete[index], complete[index+1])
			}
		}
		return arguments
	}
	tests := map[string][]string{
		"nothing":              {},
		"no authority":         without("--authority"),
		"no token":             without("--access-token-file"),
		"no ledger":            without("--ledger"),
		"no label":             without("--label"),
		"escaping prefix":      append(completeArguments(), "--prefix", "../escape"),
		"volume that is path":  append(without("--volume"), "--volume", "cell/volume"),
		"positional arguments": append(completeArguments(), "stray"),
	}
	for name, arguments := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := parseOptions(arguments, io.Discard); err == nil {
				t.Fatalf("parseOptions(%v) accepted an invocation it cannot honour", arguments)
			}
		})
	}
	opts, err := parseOptions(completeArguments(), io.Discard)
	if err != nil {
		t.Fatalf("parseOptions(complete): %v", err)
	}
	if opts.prefix != "fskit" {
		t.Fatalf("default prefix = %q", opts.prefix)
	}
}

// TestClientConfigIsTheMacAttachShape pins what makes this the FSKit
// instrument rather than another Linux client: the exclusive-writer profile on
// a MOUNT session, the empty routing declaration, and absence evidence that is
// complete enough for the authority's Detach.
func TestClientConfigIsTheMacAttachShape(t *testing.T) {
	opts, err := parseOptions(completeArguments(), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	config := clientConfig(opts, nil, []byte("token"))
	if config.FrontendProfile != authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE ||
		config.Purpose != authoritypb.SessionPurpose_SESSION_PURPOSE_MOUNT {
		t.Fatalf("profile %s purpose %s, want FSKit exclusive MOUNT", config.FrontendProfile, config.Purpose)
	}
	if config.RoutesRevision != (localroutes.RuleSet{}).Revision() {
		t.Fatal("the session does not declare the empty routing revision a freshly provisioned volume runs")
	}
	if config.MaxInFlight < 2 || uint64(config.ReplaySlots) < uint64(config.MaxInFlight) {
		t.Fatalf("bounds %d in flight over %d replay slots cannot be admitted", config.MaxInFlight, config.ReplaySlots)
	}
	proof, err := config.ObservePreKernelMountAbsence(t.Context())
	if err != nil || len(proof.GetObservation()) == 0 || proof.GetComponent() == "" || proof.GetObservedUnixNanos() <= 0 {
		t.Fatalf("absence evidence = %v, %v; the authority would refuse it at Detach", proof, err)
	}
}

func TestRenewalIntervalIsTheDaemonCadence(t *testing.T) {
	tests := []struct {
		lease time.Duration
		want  time.Duration
	}{
		{2 * time.Minute, 5 * time.Second},
		{9 * time.Second, 3 * time.Second},
		{4500 * time.Millisecond, 1500 * time.Millisecond},
		{1000 * time.Millisecond, 333 * time.Millisecond},
	}
	for _, test := range tests {
		got, err := renewalInterval(test.lease)
		if err != nil || got != test.want {
			t.Errorf("renewalInterval(%s) = %s, %v; want %s", test.lease, got, err, test.want)
		}
	}
	for _, lease := range []time.Duration{0, time.Millisecond} {
		if got, err := renewalInterval(lease); err == nil {
			t.Errorf("renewalInterval(%s) = %s, want a refusal", lease, got)
		}
	}
}

func TestRenewStopsTheWorkloadWhenARenewalFails(t *testing.T) {
	var calls atomic.Int32
	keepAlive := func(context.Context) (time.Duration, error) {
		if calls.Add(1) == 3 {
			return 0, errors.New("session refused")
		}
		return time.Second, nil
	}
	var stopped atomic.Bool
	err := renew(t.Context(), keepAlive, time.Millisecond, time.Second, func() { stopped.Store(true) })
	if err == nil || !strings.Contains(err.Error(), "session refused") {
		t.Fatalf("renew error = %v, want the refused renewal", err)
	}
	if !stopped.Load() {
		t.Fatal("a failed renewal did not stop the workload")
	}
}

func TestRenewEndsQuietlyWithTheWorkload(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	keepAlive := func(context.Context) (time.Duration, error) {
		cancel()
		return 0, context.Canceled
	}
	if err := renew(ctx, keepAlive, time.Millisecond, time.Second, func() { t.Error("stop called for an ordinary end") }); err != nil {
		t.Fatalf("renew error = %v after the workload ended", err)
	}
}
