package mountenrollment

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
)

type scriptedSource struct {
	mu       sync.Mutex
	failures int
	calls    []uint64
	grant    controlplane.MountAuthorization
	err      error
}

func (source *scriptedSource) Refresh(_ context.Context, _ string, sequence uint64) (controlplane.MountAuthorization, error) {
	source.mu.Lock()
	defer source.mu.Unlock()
	source.calls = append(source.calls, sequence)
	if source.failures > 0 {
		source.failures--
		return controlplane.MountAuthorization{}, errors.New("temporary Manager failure")
	}
	if source.err != nil {
		return controlplane.MountAuthorization{}, source.err
	}
	grant := source.grant
	grant.Sequence = sequence
	return grant, nil
}

func TestRenewerRetriesOneExactSequenceAndStopsWithItsOwner(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	grantDeadline := now.Add(2 * time.Minute)
	source := &scriptedSource{
		failures: 1,
		grant: controlplane.MountAuthorization{
			Capability: "grant", ClientCertificatePEM: "certificate", ExpiresUnix: grantDeadline.Unix(),
		},
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	renewer := &Renewer{Source: source, Observe: func(status RenewalStatus) {
		if !status.LastSuccess.IsZero() {
			cancel()
		}
	}}
	err := renewer.Run(ctx, "c2Vzc2lvbi1pZC0xMjM0NQ", now.Add(time.Minute),
		func(_ context.Context, capability string, sequence uint64, certificate []byte) (time.Time, error) {
			if capability != "grant" || sequence != 1 || string(certificate) != "certificate" {
				t.Fatalf("install = %q, %d, %q", capability, sequence, certificate)
			}
			return grantDeadline, nil
		})
	if err != nil {
		t.Fatal(err)
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	if len(source.calls) != 2 || source.calls[0] != 1 || source.calls[1] != 1 {
		t.Fatalf("refresh sequences = %v, want [1 1]", source.calls)
	}
}

func TestRenewerFailsClosedImmediatelyOnDefinitiveDenial(t *testing.T) {
	source := &scriptedSource{err: ErrDefinitiveDenial}
	start := time.Now()
	err := (&Renewer{Source: source}).Run(context.Background(), "session", start.Add(time.Minute),
		func(context.Context, string, uint64, []byte) (time.Time, error) {
			t.Fatal("definitively denied grant reached installer")
			return time.Time{}, nil
		})
	if !errors.Is(err, ErrDefinitiveDenial) {
		t.Fatalf("definitive denial = %v", err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("definitive denial was retried for %v", time.Since(start))
	}
}

func TestRenewerRefusesToStartInsideSafetyMargin(t *testing.T) {
	source := &scriptedSource{}
	err := (&Renewer{Source: source}).Run(context.Background(), "session", time.Now().Add(4*time.Second),
		func(context.Context, string, uint64, []byte) (time.Time, error) { return time.Time{}, nil })
	if err == nil {
		t.Fatal("renewer started after its safe cutoff")
	}
	if len(source.calls) != 0 {
		t.Fatalf("unsafe refresh calls = %v", source.calls)
	}
}

func TestRenewerReservesThePlatformFailClosedBudget(t *testing.T) {
	source := &scriptedSource{}
	err := (&Renewer{Source: source, MinimumSafetyMargin: 15 * time.Second}).Run(
		context.Background(), "session", time.Now().Add(10*time.Second),
		func(context.Context, string, uint64, []byte) (time.Time, error) { return time.Time{}, nil },
	)
	if err == nil || len(source.calls) != 0 {
		t.Fatalf("renewer entered a window shorter than the platform safety budget: calls=%v err=%v", source.calls, err)
	}
}

func TestRefreshJitterUsesTheWholeDeclaredMiddleBand(t *testing.T) {
	now := time.Unix(1000, 0)
	deadline := now.Add(100 * time.Second)
	minimum, maximum := int64(100), int64(0)
	for sequence := uint64(1); sequence <= 1000; sequence++ {
		seconds := int64(refreshTime(now, deadline, "stable-session", sequence).Sub(now) / time.Second)
		if seconds < minimum {
			minimum = seconds
		}
		if seconds > maximum {
			maximum = seconds
		}
	}
	if minimum != 40 || maximum != 60 {
		t.Fatalf("refresh jitter band = %d-%d%%, want 40-60%%", minimum, maximum)
	}
}
