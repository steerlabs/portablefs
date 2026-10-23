package mountenrollment

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"
)

func TestManagerRechecksClockAfterTCP(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	ca, key, caPEM := testEnrollmentCA(t, now)
	serverCert, _ := testSignedCertificate(t, ca, key, now, "manager", nil, []string{"manager.test"}, false)
	id := "22222222-2222-4222-8222-222222222222"
	uri, _ := url.Parse("spiffe://portablefs/mount-enrollment/" + id)
	cert, keyPEM := testSignedCertificate(t, ca, key, now, id, uri, nil, true)
	var ready, called atomic.Bool
	ready.Store(true)
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called.Store(true); w.Write([]byte(`{}`)) }))
	roots := x509.NewCertPool()
	roots.AddCert(ca)
	server.TLS = &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{serverCert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: roots}
	server.StartTLS()
	defer server.Close()
	unavailable := errors.New("clock withdrawn")
	client, err := NewClient(Config{Managed: true, AwaitTLS: func(context.Context) error {
		if !ready.Load() {
			return unavailable
		}
		return nil
	}, ManagerURL: server.URL, ManagerServerName: "manager.test", ManagerCAPEM: []byte(caPEM), EnrollmentID: id, EnrollmentCertificatePEM: []byte(certificatePEM(cert.Certificate[0])), ClientKeyPEM: []byte(keyPEM), VolumeID: "volume", AuthorityGeneration: 1, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	ctx := httptrace.WithClientTrace(t.Context(), &httptrace.ClientTrace{ConnectDone: func(_, _ string, err error) {
		if err == nil {
			ready.Store(false)
		}
	}})
	var out struct{}
	err = client.do(ctx, "POST", "close", "test", struct{}{}, &out)
	if called.Load() || err == nil {
		t.Fatalf("Manager TLS/HTTP dispatched after clock withdrawal: called=%v err=%v", called.Load(), err)
	}
	ready.Store(true)
	if err := client.do(t.Context(), "POST", "close", "test", struct{}{}, &out); err != nil || !called.Load() {
		t.Fatalf("fresh ready clock did not restore verified Manager TLS: called=%v err=%v", called.Load(), err)
	}
}

// Fake a CLOCK_REALTIME step in a copied Go timestamp; never sets a real clock.
func TestCorrectionBeforeWaitIsNotLost(t *testing.T) {
	before := time.Now()
	after := before
	// Go time.Time's high bit and packed seconds are checked before editing.
	wall := (*uint64)(unsafe.Pointer(&after))
	if *wall>>63 != 1 {
		t.Fatal("fixture has no monotonic reading")
	}
	*wall += uint64(60) << 30
	if after.Unix()-before.Unix() != 60 || after.Sub(before) != 0 {
		t.Fatal("fixture did not isolate wall step")
	}
	// This correction was published after Run computed its target, but before
	// wait called Corrections(). The source already replaced its closed channel.
	current := make(chan struct{})
	close(current) // source publishes correction and replaces its notification
	current = make(chan struct{})
	r := &Renewer{initialized: true, session: "s", sequence: 2, authorizedAt: before, deadline: before.Add(2 * time.Minute).Round(0), Now: func() time.Time { return after }, WallChanges: func() <-chan struct{} { return current }}
	r.status.NextAttempt = before.Add(30 * time.Second)
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
	defer cancel()
	if err := r.wait(ctx, r.status.NextAttempt, current); err != nil {
		t.Fatalf("missed material correction: wall target passed by 30s but stale monotonic timer waited until cancellation: %v", err)
	}
}

func TestRunCapturesCorrectionBeforeSchedulingSnapshot(t *testing.T) {
	base := time.Now().Round(0)
	var wall atomic.Int64
	wall.Store(base.UnixNano())
	changes := make(chan struct{})
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	r := &Renewer{Now: func() time.Time { return time.Unix(0, wall.Load()) }, WallChanges: func() <-chan struct{} { return changes }}
	deadline := time.Unix(base.Add(2*time.Minute).Unix(), 0)
	r.Source = sourceFunc(func(_ context.Context, s string, n uint64) (controlplane.MountAuthorization, error) {
		return grantFor(s, n, deadline), nil
	})
	decisions := 0
	r.scheduleHook = func(_ Permit, target time.Time) {
		if target.IsZero() {
			return
		}
		decisions++
		if decisions == 1 {
			// Remove earlier wake tokens so only the correction can release this wait.
			r.mu.Lock()
			select {
			case <-r.wake:
			default:
			}
			r.mu.Unlock()
			wall.Add(int64(10 * time.Second))
			close(changes)
			changes = make(chan struct{})
		} else {
			cancel()
		}
	}
	err := r.Run(ctx, "session", deadline, func(context.Context, string, uint64, []byte) (time.Time, error) { return deadline, nil })
	if err != nil || decisions < 2 {
		t.Fatalf("correction in snapshot/wait gap was lost: decisions=%d err=%v", decisions, err)
	}
	if r.sequence != 2 || r.pending != nil || r.Failure() != nil {
		t.Fatal("correction changed renewal ownership")
	}
}
