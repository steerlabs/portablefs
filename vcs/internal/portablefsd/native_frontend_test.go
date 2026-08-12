package portablefsd

import (
	"context"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

func nativeWitnessTestAttach(t *testing.T, cachePolicy string) (*attach, *Server) {
	t.Helper()
	ref := "att_NNNNNNNNNNNNNNNNNNNNNN"
	a := newAttach(ref, "native-witness", ensureAttachRequest{
		AttachRef:          ref,
		VolumeID:           "vol-native-witness",
		Branch:             "main",
		MountPath:          "/Volumes/NativeWitness",
		AuthorityURL:       "127.0.0.1:1",
		DataPlaneTransport: "plaintext",
	}, privateTestDir(t))
	a.v3Config = &v3AttachConfig{cachePolicy: cachePolicy}
	a.v3Data = testV3DataPlane(t, newFakeV3DataClient())
	a.v3Coherence = a.v3Data.bridge

	r := newRegistry(privateTestDir(t))
	t.Cleanup(r.stopPersister)
	r.byRef[ref] = a
	r.byKey[a.key] = a
	s := NewServer(Config{Version: "native-witness-test"})
	s.registry = r
	return a, s
}

func serveNativeWitnessTestConnection(
	t *testing.T,
	cachePolicy string,
	clientName string,
) (*attach, *pfsTestClient, <-chan struct{}) {
	t.Helper()
	a, s := nativeWitnessTestAttach(t, cachePolicy)
	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	fc := &frontendConn{srv: s, conn: serverConn}
	go func() {
		fc.serve(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		_ = clientConn.Close()
		<-done
	})
	client := &pfsTestClient{t: t, conn: clientConn}
	client.call(&pfslocal.Hello{
		ProtocolMajor: pfslocal.ProtocolMajor,
		ClientName:    clientName,
		ClientVersion: "native-witness-test",
	})
	client.call(&pfslocal.ResolveRequest{AttachRef: a.ref})
	return a, client, done
}

func waitNativeWitness(t *testing.T, a *attach, wantReady bool) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		err := a.requireNativeFrontendReady()
		if (err == nil) == wantReady {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("native witness ready=%t, error=%v", err == nil, err)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestNativeFrontendWitnessRequiresExactClientResolveAndRetiresOnClose(t *testing.T) {
	a, client, done := serveNativeWitnessTestConnection(
		t,
		v3CachePolicyFSKit,
		nativeFSKitFrontendClientName,
	)
	waitNativeWitness(t, a, true)

	// Exercise close/readiness synchronization under the race detector. A
	// successful sample before close begins is valid; after serve returns the
	// witness must be synchronously absent.
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				_ = a.requireNativeFrontendReady()
			}
		}()
	}
	client.close()
	<-done
	wg.Wait()
	waitNativeWitness(t, a, false)
}

func TestNativeFrontendWitnessRejectsDaemonSelfPreflightName(t *testing.T) {
	for _, clientName := range []string{
		"portablefsd-control-preflight",
		"portablefskit-copy",
		"",
	} {
		t.Run(clientName, func(t *testing.T) {
			a, _, _ := serveNativeWitnessTestConnection(
				t,
				v3CachePolicyFSKit,
				clientName,
			)
			if err := a.requireNativeFrontendReady(); !errors.Is(err, errNativeFrontendNotReady) {
				t.Fatalf("wrong-client witness error = %v", err)
			}
		})
	}
}

func TestNativeFrontendWitnessRejectsLegacyPolicy(t *testing.T) {
	a, _, _ := serveNativeWitnessTestConnection(
		t,
		v3CachePolicyMacOS26,
		nativeFSKitFrontendClientName,
	)
	if err := a.requireNativeFrontendReady(); !errors.Is(err, errNativeFrontendWrongPolicy) {
		t.Fatalf("legacy-policy witness error = %v", err)
	}
}

func TestNativeFrontendWitnessRequiresDeliveredResolveReply(t *testing.T) {
	a, s := nativeWitnessTestAttach(t, v3CachePolicyFSKit)
	serverConn, clientConn := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		(&frontendConn{srv: s, conn: serverConn}).serve(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		_ = clientConn.Close()
		<-done
	})

	if err := pfslocal.WriteFrame(clientConn, &pfslocal.Envelope{
		RequestID: 1,
		Body: &pfslocal.Hello{
			ProtocolMajor: pfslocal.ProtocolMajor,
			ProtocolMinor: pfslocal.ProtocolMinor,
			ClientName:    nativeFSKitFrontendClientName,
		},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := pfslocal.ReadFrame(clientConn); err != nil {
		t.Fatal(err)
	}
	if err := pfslocal.WriteFrame(clientConn, &pfslocal.Envelope{
		RequestID: 2,
		Body:      &pfslocal.ResolveRequest{AttachRef: a.ref},
	}); err != nil {
		t.Fatal(err)
	}
	// net.Pipe makes the server's Resolve reply fail synchronously once this
	// peer closes; registration must happen only after a delivered reply.
	_ = clientConn.Close()
	<-done
	if err := a.requireNativeFrontendReady(); !errors.Is(err, errNativeFrontendNotReady) {
		t.Fatalf("failed Resolve reply created witness: %v", err)
	}
}

func TestNativeFrontendWitnessIsRetiredByDetachTransition(t *testing.T) {
	a, _, _ := serveNativeWitnessTestConnection(
		t,
		v3CachePolicyFSKit,
		nativeFSKitFrontendClientName,
	)
	waitNativeWitness(t, a, true)
	a.mu.Lock()
	a.detached = true
	a.retireNativeFrontendWitnessesLocked()
	a.mu.Unlock()
	if err := a.requireNativeFrontendReady(); !errors.Is(err, errNativeFrontendNotReady) {
		t.Fatalf("detached attach retained native witness: %v", err)
	}
}

func TestNativeFrontendWitnessCannotMakeUnavailableAttachReady(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*attach)
	}{
		{"credential pending", func(a *attach) { a.credentialPending = true }},
		{"detach prepared", func(a *attach) { a.detachPrepared = true }},
		{"detach forced", func(a *attach) { a.detachForce = true }},
		{"detach barrier", func(a *attach) { a.detachBarrier = true }},
		{"detach quarantined", func(a *attach) { a.detachFailFrozen = true }},
		{"coherence frozen", func(a *attach) { a.coherenceFailFrozen = true }},
		{"coherence repair active", func(a *attach) { a.coherenceRepairs = 1 }},
		{"coherence repair gave up", func(a *attach) { a.coherenceRepairGaveUp = true }},
		{"last error", func(a *attach) { a.lastErr = "degraded" }},
		{"degraded state", func(a *attach) { a.state = pfslocal.AttachStateDegraded }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, _, _ := serveNativeWitnessTestConnection(
				t,
				v3CachePolicyFSKit,
				nativeFSKitFrontendClientName,
			)
			waitNativeWitness(t, a, true)
			a.mu.Lock()
			tc.mutate(a)
			a.mu.Unlock()
			if err := a.requireNativeFrontendReady(); !errors.Is(err, errNativeFrontendNotReady) {
				t.Fatalf("unavailable attach readiness error = %v", err)
			}
		})
	}
}

func TestNativeFrontendWitnessCannotMakeTerminalSessionReady(t *testing.T) {
	a, _, _ := serveNativeWitnessTestConnection(
		t,
		v3CachePolicyFSKit,
		nativeFSKitFrontendClientName,
	)
	waitNativeWitness(t, a, true)
	_ = a.v3Data.fail(errors.New("terminal test session"))
	if err := a.requireNativeFrontendReady(); !errors.Is(err, errNativeFrontendNotReady) {
		t.Fatalf("terminal session readiness error = %v", err)
	}
}
