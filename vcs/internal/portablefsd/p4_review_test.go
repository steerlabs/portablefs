package portablefsd

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/daemonctl"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

func TestP4CloseBeforeHandlerRetiresPublicationReservation(t *testing.T) {
	a, d := publicationTestAttach(t)
	server, peer := net.Pipe()
	defer peer.Close()
	c := &frontendConn{origin: 91, conn: server, attach: a}
	const operation = uint64(7)
	initialize, ok := c.reserveLogicalOperation(operation, true)
	if !ok || !initialize {
		t.Fatal("reservation refused")
	}
	d.bridge.reserveFrontendPublication(c.callback(operation))
	c.handlerWG.Add(1)
	closed := make(chan struct{})
	go func() { c.close(); close(closed) }()
	waitV3PublicationCondition(t, func() bool {
		c.publicationMu.Lock()
		defer c.publicationMu.Unlock()
		return c.publicationClosed
	})
	c.handleAttached(context.Background(), a, 3, operation, initialize, &pfslocal.GetAttrRequest{})
	c.handlerWG.Done()
	select {
	case <-closed:
	case <-time.After(5 * time.Second):
		t.Fatal("close did not join queued handler")
	}
	d.bridge.sourcePublication.mu.Lock()
	_, retained := d.bridge.sourcePublication.operations[c.callback(operation)]
	d.bridge.sourcePublication.mu.Unlock()
	if retained || d.terminalError() != nil {
		t.Fatalf("unexposed reservation retained=%t terminal=%v", retained, d.terminalError())
	}
}

func TestP4ClockFaultKeepsRenewingOriginalSessionUntilAbsence(t *testing.T) {
	pki := newV3TestPKI(t)
	h := newV3TestAuthority()
	h.leaseMillis = 3000
	address := startV3TestAuthority(t, h, pki.serverTLS)
	r := newRegistry(privateTestDir(t))
	a := ensureV3TestAttach(t, r, v3TestEnsureRequest(address, pki, "/Volumes/ClockFault"))
	d := a.v3Backend()
	clock := newFakeV3Clock()
	clock.fail(errors.New("continuous clock unavailable"))
	d.mu.Lock()
	d.clock = clock.read
	d.mu.Unlock()
	renewed := make(chan struct{}, 16)
	h.mu.Lock()
	h.keepAliveHook = func(_ context.Context, req *authoritypb.Request) {
		if !bytes.Equal(req.GetEpoch(), h.epoch) || !bytes.Equal(req.GetSession().GetId(), h.session) {
			t.Error("renewal left the activated original session")
		}
		renewed <- struct{}{}
	}
	h.mu.Unlock()
	// Observe more than a full lease of periodic renewal after the fault.
	for range 4 {
		select {
		case <-renewed:
		case <-time.After(5 * time.Second):
			t.Fatal("clock fault stopped authority renewal")
		}
	}
	clock.fail(nil)
	if !d.scheduledRenewal() || v3Horizon(d) != 0 || d.terminalError() == nil || !d.client.LocalAdmissionOpen() {
		t.Fatal("clock recovery revived serving or lost the original transport")
	}
	found, err := r.unmountFSKitWith(a.ref, false, fskitKernelOps{
		present: func(string, string) (bool, error) { return false, nil },
	})
	proof := h.recordedDetach()
	if !found || err != nil || proof == nil || proof.GetMountAbsence() == nil {
		t.Fatalf("exact absence delivery: found=%t err=%v detach=%v", found, err, proof)
	}
}

func TestP4RenewalDoesNotValidateProofAgainstLocalAuthorizationClock(t *testing.T) {
	for _, reauthorize := range []bool{false, true} {
		t.Run(map[bool]string{false: "wall-skew", true: "reauthorize-in-flight"}[reauthorize], func(t *testing.T) {
			c := newFakeV3DataClient()
			c.authorization = time.Now().Add(20 * time.Second)
			c.proof = 10 * time.Second
			clock := newFakeV3Clock()
			replacement := &reauthorizingV3Client{fakeV3DataClient: c, deadline: time.Now().Add(2 * time.Minute)}
			d := testV3DataPlaneOnClient(t, replacement, c, clock)
			entered, release := make(chan struct{}), make(chan struct{})
			c.mu.Lock()
			c.keepAlive = func(context.Context) (time.Duration, error) {
				close(entered)
				<-release
				return time.Minute, nil // valid authority scalar, longer than local wall remainder
			}
			c.mu.Unlock()
			done := make(chan bool, 1)
			go func() { done <- d.scheduledRenewal() }()
			<-entered
			if reauthorize {
				// Exercise the real daemon installation boundary, not just a
				// replacement of the deadline snapshot used by renewHorizon.
				c.mu.Lock()
				c.authorization = time.Now().Add(2 * time.Minute)
				c.mu.Unlock()
				if _, err := d.reauthorize(context.Background(), []byte("replacement"), 1); err != nil {
					t.Fatal(err)
				}
			}
			close(release)
			if !<-done || d.terminalError() != nil {
				t.Fatalf("local wall snapshot rejected authority proof: %v", d.terminalError())
			}
			d.mu.Lock()
			admitted := d.cacheAdmissionLocked() == v3CacheHit
			d.authorizationDeadline = time.Now().Add(-time.Second)
			denied := d.cacheAdmissionLocked() != v3CacheHit
			d.mu.Unlock()
			if !admitted || !denied {
				t.Fatal("wall time must deny expired authorization without validating R")
			}
		})
	}
}

func TestP4CredentialRejectsUnknownAndTrailingInput(t *testing.T) {
	s := NewServer(Config{})
	s.registry = newRegistry(privateTestDir(t))
	a := &attach{ref: "strict-credential"}
	s.registry.byRef[a.ref] = a
	for _, body := range []string{`{"authToken":"unused","unknown":true}`, `{"authToken":"unused"} {}`, `{"authToken":"unused"} trailing`} {
		w := httptest.NewRecorder()
		s.handleAttach(w, httptest.NewRequest(http.MethodPost, "/v2/attaches/"+a.ref+"/credential", strings.NewReader(body)))
		if w.Code != http.StatusBadRequest {
			t.Fatalf("credential input %q returned %d", body, w.Code)
		}
	}
}

func TestP4ForcedUnmountReturnsEmpty204(t *testing.T) {
	s := NewServer(Config{})
	s.registry = newRegistry(privateTestDir(t))
	// A completed teardown may still be registered pending durable removal.
	// It exercises the actual HTTP route without making any host kernel call.
	a := &attach{ref: "already-absent", key: "absent", detached: true}
	s.registry.byRef[a.ref], s.registry.byKey[a.key] = a, a
	w := httptest.NewRecorder()
	s.handleAttach(w, httptest.NewRequest(http.MethodPost, "/v2/attaches/"+a.ref+"/unmount?force=1", nil))
	if w.Code != http.StatusNoContent || w.Body.Len() != 0 || s.registry.get(a.ref) != nil {
		t.Fatalf("force response=%d %q", w.Code, w.Body.String())
	}
}

func TestP4StopIfIdleDelivers204AndExitsRunPromptly(t *testing.T) {
	dir := shortDaemonSocketDir(t)
	s := NewServer(Config{
		StateDir: privateTestDir(t), MountLogDir: privateTestDir(t),
		ControlSocket: filepath.Join(dir, "ctl.sock"), FrontendSocket: filepath.Join(dir, "front.sock"),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	waitUnix(t, s.cfg.ControlSocket)
	client := rawHTTPUDSClient(s.cfg.ControlSocket)
	defer client.CloseIdleConnections()
	res, err := client.Post("http://unix"+daemonctl.LifecycleStopIfIdlePath, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(res.Body)
	res.Body.Close()
	if err != nil || res.StatusCode != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("stop response=%d %q err=%v", res.StatusCode, body, err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("daemon stayed alive after delivering idle 204")
	}
}

func TestP4NonzeroRequestsUseOneFIFOSequence(t *testing.T) {
	var last uint64
	for _, test := range []struct {
		id   uint64
		want bool
	}{{1, true}, {2, true}, {0, false}, {9, true}, {4, false}, {9, false}, {10, true}} {
		before := last
		if got := admitRequestID(test.id, &last); got != test.want || !got && last != before {
			t.Fatalf("admit %d after %d=%t last=%d", test.id, before, got, last)
		}
	}
}

func TestP4DegradedEventRequiresTerminalServingState(t *testing.T) {
	c := newFakeV3DataClient()
	d := testV3DataPlaneWithClock(t, c, newFakeV3Clock())
	events := make(chan *pfslocal.Event, 1)
	done := make(chan error, 1)
	go func() {
		done <- d.bridge.runBound(context.Background(), func(event *pfslocal.Event) error {
			if _, terminal := event.Kind.(*pfslocal.AttachState); terminal {
				events <- event
			}
			return nil
		})
	}()
	c.mu.Lock()
	c.keepAlive = func(context.Context) (time.Duration, error) { return 0, context.DeadlineExceeded }
	c.mu.Unlock()
	if !d.scheduledRenewal() {
		t.Fatal("settled local wait ended session")
	}
	select {
	case <-events:
		t.Fatal("nonterminal local wait emitted DEGRADED")
	default:
	}
	cause := errors.New("terminal serving failure")
	_ = d.stopServing(cause)
	select {
	case event := <-events:
		state, ok := event.Kind.(*pfslocal.AttachState)
		if !ok || state.State != pfslocal.AttachStateDegraded {
			t.Fatalf("terminal event=%v", event)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("terminal serving failure did not deliver DEGRADED")
	}
	if err := <-done; !errors.Is(err, cause) {
		t.Fatalf("event owner lost terminal cause: %v", err)
	}
}

func TestP4ControlRequestSizeCannotHideTrailingData(t *testing.T) {
	var value struct {
		Token string `json:"authToken"`
	}
	body := `{"authToken":"unused"}` + strings.Repeat(" ", maxControlRequestBytes) + `{}`
	if err := decodeControlRequest(strings.NewReader(body), &value); err == nil {
		t.Fatal("size limit hid trailing input from the control decoder")
	}
}
