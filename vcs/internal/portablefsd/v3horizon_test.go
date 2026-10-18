package portablefsd

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// fakeV3Clock is a controlled continuous clock. advance models elapsed time,
// including a host sleep that Go's monotonic clock would not count.
type fakeV3Clock struct {
	mu  sync.Mutex
	now uint64
	err error
}

func newFakeV3Clock() *fakeV3Clock { return &fakeV3Clock{now: uint64(time.Hour)} }

func (c *fakeV3Clock) read() (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now, c.err
}

func (c *fakeV3Clock) advance(elapsed time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now += uint64(elapsed)
}

func (c *fakeV3Clock) rewind(elapsed time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now -= uint64(elapsed)
}

func (c *fakeV3Clock) fail(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.err = err
}

// testV3DataPlaneWithClock is testV3DataPlane on a controlled clock, returned
// after its initial keepalive proof has been adopted (or refused).
func testV3DataPlaneWithClock(t *testing.T, client *fakeV3DataClient, clock *fakeV3Clock) *v3DataPlane {
	t.Helper()
	return testV3DataPlaneOnClient(t, client, client, clock)
}

// testV3DataPlaneOnClient serves through a wrapper of the fake client.
func testV3DataPlaneOnClient(t *testing.T, wrapper v3DataPlaneClient, client *fakeV3DataClient, clock *fakeV3Clock) *v3DataPlane {
	t.Helper()
	client.mu.Lock()
	if client.proof == 0 {
		// A clocked data plane is for horizon and cache tests: give it the
		// longest proof the session lease allows.
		client.proof = min(client.lease, authorityrpc.MaxCacheProof)
	}
	client.mu.Unlock()
	d, err := newV3DataPlane(context.Background(), v3DataPlaneConfig{
		Client: wrapper, VolumeID: "volume", VolumeName: "Volume", ItemGeneration: 9,
		PrincipalUID: 501, PrincipalGID: 20, CachePolicy: v3CachePolicyFSKit, Clock: clock.read,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := d.bridge.bind(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.fail(errors.New("test cleanup")) })
	deadline := time.Now().Add(2 * time.Second)
	for {
		client.mu.Lock()
		renewed := client.keepAlives
		client.mu.Unlock()
		d.mu.Lock()
		settled := renewed != 0 && (d.horizon != 0 || d.terminal != nil || client.keepErr != nil)
		d.mu.Unlock()
		if settled || client.keepAlive != nil {
			return d
		}
		if time.Now().After(deadline) {
			t.Fatal("initial keepalive proof did not settle")
		}
		time.Sleep(time.Millisecond)
	}
}

func v3Horizon(d *v3DataPlane) uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.horizon
}

func TestV3HorizonCandidateArithmetic(t *testing.T) {
	for _, test := range []struct {
		name   string
		start  uint64
		proof  time.Duration
		want   uint64
		usable bool
	}{
		{name: "max-cache-proof", start: 7, proof: authorityrpc.MaxCacheProof, want: 7 + uint64(authorityrpc.MaxCacheProof-time.Second-60*time.Millisecond), usable: true},
		{name: "rate-term-rounds-up", start: 0, proof: 2*time.Second + 1, want: uint64(2*time.Second+1) - uint64(time.Second) - (2_000_000 + 1), usable: true},
		{name: "zero", proof: 0},
		{name: "negative", proof: -time.Second},
		{name: "just-below-epsilon", proof: time.Second + time.Second/999},
		{name: "below-epsilon", proof: time.Second},
		{name: "overflow", start: math.MaxUint64 - uint64(time.Second), proof: authorityrpc.MaxCacheProof},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, usable := v3HorizonCandidate(test.start, test.proof)
			if usable != test.usable || usable && got != test.want {
				t.Fatalf("candidate(%d, %s) = (%d,%t), want (%d,%t)", test.start, test.proof, got, usable, test.want, test.usable)
			}
		})
	}
}

// The horizon is anchored at the request's start: time spent before the reply
// consumes it, and a proof fully consumed by delay supplies no horizon.
func TestV3HorizonIsAnchoredAtRequestStart(t *testing.T) {
	clock := newFakeV3Clock()
	client := newFakeV3DataClient()
	client.proof = 30 * time.Second
	d := testV3DataPlaneWithClock(t, client, clock)
	start := clock.now
	want, _ := v3HorizonCandidate(start, 30*time.Second)
	if got := v3Horizon(d); got != want {
		t.Fatalf("initial horizon = %d, want start + R - epsilon = %d", got, want)
	}

	client.mu.Lock()
	client.keepAlive = func(context.Context) (time.Duration, error) {
		clock.advance(29 * time.Second) // the reply was delayed past its usable life
		return 30 * time.Second, nil
	}
	client.mu.Unlock()
	clock.advance(time.Second)
	if err := d.renewHorizon(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := v3Horizon(d); got != want {
		t.Fatalf("delay-consumed proof moved the horizon to %d, want %d", got, want)
	}
}

// Out-of-order receipts can never move the horizon backwards.
func TestV3HorizonNeverRegresses(t *testing.T) {
	clock := newFakeV3Clock()
	client := newFakeV3DataClient()
	d := testV3DataPlaneWithClock(t, client, clock)
	first := v3Horizon(d)
	client.mu.Lock()
	client.keepAlive = func(context.Context) (time.Duration, error) { return 5 * time.Second, nil }
	client.mu.Unlock()
	if err := d.renewHorizon(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := v3Horizon(d); got != first {
		t.Fatalf("a shorter later receipt moved the horizon from %d to %d", first, got)
	}
}

// A short authorization remaining shortens R and therefore the horizon, even
// under a much longer configured lease.
func TestV3ShortAuthorizationRemainingShortensTheHorizon(t *testing.T) {
	clock := newFakeV3Clock()
	client := newFakeV3DataClient()
	client.lease = 2 * time.Minute
	client.proof = 3 * time.Second
	d := testV3DataPlaneWithClock(t, client, clock)
	want, _ := v3HorizonCandidate(clock.now, 3*time.Second)
	if got := v3Horizon(d); got != want {
		t.Fatalf("horizon = %d, want the short proof's %d", got, want)
	}
}

// Reauthorization invalidates the horizon before it is admitted; a proof
// sampled before or during it never counts, and success obtains a new one.
func TestV3ReauthorizationInvalidatesAndRenewsTheHorizon(t *testing.T) {
	clock := newFakeV3Clock()
	client := &reauthorizingV3Client{fakeV3DataClient: newFakeV3DataClient()}
	client.deadline = time.Now().Add(time.Hour)
	d := testV3DataPlaneOnClient(t, client, client.fakeV3DataClient, clock)
	if v3Horizon(d) == 0 {
		t.Fatal("no initial horizon")
	}

	// A keepalive whose request started before reauthorization replies after it
	// began: its proof was sampled under the old authorization.
	entered, release := make(chan struct{}), make(chan struct{})
	client.mu.Lock()
	client.keepAlive = func(context.Context) (time.Duration, error) {
		close(entered)
		<-release
		return time.Minute, nil
	}
	client.mu.Unlock()
	stale := make(chan error, 1)
	go func() { stale <- d.renewHorizon(context.Background()) }()
	<-entered
	client.duringReauthorize = func() {
		if v3Horizon(d) != 0 {
			t.Error("horizon remained usable while reauthorization was admitted")
		}
	}
	client.mu.Lock()
	client.keepAlive = nil
	client.mu.Unlock()
	clock.advance(time.Second)
	if _, err := d.reauthorize(context.Background(), []byte("token"), 1); err != nil {
		t.Fatal(err)
	}
	renewed := v3Horizon(d)
	want, _ := v3HorizonCandidate(clock.now, time.Minute)
	if renewed != want {
		t.Fatalf("horizon after reauthorization = %d, want a fresh proof's %d", renewed, want)
	}
	close(release)
	if err := <-stale; err != nil {
		t.Fatal(err)
	}
	if got := v3Horizon(d); got != renewed {
		t.Fatalf("a pre-reauthorization proof moved the horizon to %d", got)
	}
	d.mu.Lock()
	installed := d.authorizationDeadline
	d.mu.Unlock()
	if !installed.Equal(client.deadline) {
		t.Fatalf("installed deadline %s, want the reauthorized %s", installed, client.deadline)
	}
}

type reauthorizingV3Client struct {
	*fakeV3DataClient
	deadline          time.Time
	duringReauthorize func()
}

func (c *reauthorizingV3Client) Reauthorize(context.Context, []byte, uint64) (time.Time, error) {
	if c.duringReauthorize != nil {
		c.duringReauthorize()
	}
	return c.deadline, nil
}

// Terminal is irreversible: it clears the horizon and no later receipt
// restores it.
func TestV3TerminalClearsTheHorizonIrreversibly(t *testing.T) {
	clock := newFakeV3Clock()
	client := newFakeV3DataClient()
	d := testV3DataPlaneWithClock(t, client, clock)
	_ = d.stopServing(errors.New("frontend lost"))
	if got := v3Horizon(d); got != 0 {
		t.Fatalf("terminal left horizon %d", got)
	}
	if err := d.renewHorizon(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := v3Horizon(d); got != 0 {
		t.Fatalf("a receipt after terminal restored horizon %d", got)
	}
}

// A failed explicit renewal is terminal, as before; a missing or stale proof
// never silently becomes a usable horizon.
func TestV3RefusedRenewalIsTerminal(t *testing.T) {
	clock := newFakeV3Clock()
	client := newFakeV3DataClient()
	d := testV3DataPlaneWithClock(t, client, clock)
	client.mu.Lock()
	client.keepErr = errors.New("authority refused keepalive")
	client.mu.Unlock()
	if _, errno := dispatchV3Test(d, context.Background(), 0, newV3LivenessRequest(client)); errno != darwinEIO {
		t.Fatalf("refused liveness errno=%d", errno)
	}
	if d.terminalError() == nil || v3Horizon(d) != 0 {
		t.Fatalf("refused renewal terminal=%v horizon=%d", d.terminalError(), v3Horizon(d))
	}
}

func TestV3DataPlaneRefusesAnUnusableClockOrLease(t *testing.T) {
	brokenClock := newFakeV3Clock()
	brokenClock.err = errors.New("no continuous clock")
	if _, err := newV3DataPlane(context.Background(), v3DataPlaneConfig{
		Client: newFakeV3DataClient(), VolumeID: "volume", VolumeName: "Volume", ItemGeneration: 9,
		CachePolicy: v3CachePolicyFSKit, Clock: brokenClock.read,
	}); err == nil {
		t.Fatal("data plane started without a continuous clock")
	}
	shortLease := newFakeV3DataClient()
	shortLease.lease = time.Second
	if _, err := newV3DataPlane(context.Background(), v3DataPlaneConfig{
		Client: shortLease, VolumeID: "volume", VolumeName: "Volume", ItemGeneration: 9,
		CachePolicy: v3CachePolicyFSKit, Clock: newFakeV3Clock().read,
	}); err == nil {
		t.Fatal("data plane started with a lease that can never carry a usable proof")
	}
}

func TestV3TicksToNanosIsChecked(t *testing.T) {
	if got, err := v3TicksToNanos(3_000_000, 125, 3); err != nil || got != 125_000_000 {
		t.Fatalf("Apple silicon timebase conversion = (%d,%v)", got, err)
	}
	if _, err := v3TicksToNanos(math.MaxUint64, 125, 3); err == nil {
		t.Fatal("overflowing tick conversion was accepted")
	}
	if _, err := v3TicksToNanos(1, 1, 0); err == nil {
		t.Fatal("zero timebase denominator was accepted")
	}
	now, err := v3ContinuousNanos()
	if err != nil {
		t.Fatalf("platform continuous clock: %v", err)
	}
	later, err := v3ContinuousNanos()
	if err != nil || later < now {
		t.Fatalf("platform continuous clock went backwards: %d then %d (%v)", now, later, err)
	}
}

func newV3LivenessRequest(client *fakeV3DataClient) *pfslocal.V3LivenessRequest {
	return &pfslocal.V3LivenessRequest{AuthorityEpoch: client.Epoch(), SessionID: client.SessionID()}
}

// v3ClockFaults are the two observable clock faults, each with the repair that
// makes the clock readable again.
var v3ClockFaults = []struct {
	name    string
	fault   func(*fakeV3Clock)
	recover func(*fakeV3Clock)
}{
	{name: "read-error", fault: func(c *fakeV3Clock) { c.fail(errors.New("timebase lost")) }, recover: func(c *fakeV3Clock) { c.fail(nil) }},
	{name: "regression", fault: func(c *fakeV3Clock) { c.rewind(time.Second) }, recover: func(c *fakeV3Clock) { c.advance(time.Second) }},
}

// requireV3ClockTerminal requires the state every observed clock fault leaves:
// no horizon and no serving, even once the clock reads again, with the
// authority transport kept for the exact absence proof.
func requireV3ClockTerminal(t *testing.T, d *v3DataPlane, client *fakeV3DataClient) {
	t.Helper()
	if v3Horizon(d) != 0 || d.terminalError() == nil {
		t.Fatalf("after a clock fault horizon=%d terminal=%v, want no horizon and no serving", v3Horizon(d), d.terminalError())
	}
	select {
	case <-client.SessionDone():
		t.Fatal("a clock fault closed the authority transport needed for the absence proof")
	default:
	}
}

// A clock fault at either end of a renewal voids every horizon measured on
// that clock: no candidate is installed and serving ends, at once when the
// fault is seen at request start, while the renewal itself still runs on the
// transport the absence proof needs.
func TestV3ClockFaultDuringRenewalEndsServing(t *testing.T) {
	for _, fault := range v3ClockFaults {
		for _, atStart := range []bool{true, false} {
			name := fault.name + "/receipt"
			if atStart {
				name = fault.name + "/start"
			}
			t.Run(name, func(t *testing.T) {
				clock := newFakeV3Clock()
				client := newFakeV3DataClient()
				d := testV3DataPlaneWithClock(t, client, clock)
				if v3Horizon(d) == 0 {
					t.Fatal("no initial horizon")
				}
				if atStart {
					fault.fault(clock)
				}
				client.mu.Lock()
				client.keepAlive = func(context.Context) (time.Duration, error) {
					if atStart && d.terminalError() == nil {
						t.Error("a clock fault at renewal start still served while the renewal was in flight")
					}
					if !atStart {
						fault.fault(clock)
					}
					return time.Minute, nil
				}
				client.mu.Unlock()
				if err := d.renewHorizon(context.Background()); err != nil {
					t.Fatalf("renewal returned %v; the clock fault is not a session failure", err)
				}
				fault.recover(clock)
				if err := d.renewHorizon(context.Background()); err != nil {
					t.Fatalf("renewal after the clock recovered returned %v", err)
				}
				requireV3ClockTerminal(t, d, client)
			})
		}
	}
}

// A clock fault observed by a request (at hit admission, or at a namespace
// mutation's request start) fails that request without reaching the
// authority and ends serving for good; the recovered clock revives nothing.
func TestV3ClockFaultObservedByARequestIsTerminal(t *testing.T) {
	for _, fault := range v3ClockFaults {
		for _, test := range []struct {
			name    string
			prepare func(*cachedV3Fixture) any
		}{
			{name: "hit-admission", prepare: func(f *cachedV3Fixture) any {
				f.ns.bind(0x20, "file", 0x70)
				file := f.lookup(f.root, "file")
				f.requireServedLocally("GetAttr before the fault", func() { f.getattr(file.Item) })
				return &pfslocal.GetAttrRequest{Item: file.Item}
			}},
			{name: "request-start", prepare: func(f *cachedV3Fixture) any {
				f.getattr(f.root)
				if _, errno := f.dispatch(&pfslocal.LookupRequest{Dir: f.root, Name: []byte("n")}); errno != darwinENOENT {
					f.t.Fatalf("negative lookup errno=%d", errno)
				}
				return &pfslocal.CreateRequest{Dir: f.root, Name: []byte("n"), Mode: 0o644, Exclusive: true}
			}},
		} {
			t.Run(fault.name+"/"+test.name, func(t *testing.T) {
				f := newCachedV3Fixture(t, v3FileObjects())
				body := test.prepare(f)
				fault.fault(f.clock)
				before := f.authorityCalls()
				if _, errno := f.dispatch(body); errno == 0 {
					t.Fatal("a request succeeded across an observed clock fault")
				}
				if after := f.authorityCalls(); after != before {
					t.Fatalf("a request that observed a clock fault reached the authority %d time(s)", after-before)
				}
				fault.recover(f.clock)
				if _, errno := f.dispatch(body); errno == 0 {
					t.Fatal("serving revived after the clock recovered")
				}
				requireV3ClockTerminal(t, f.d, f.client)
			})
		}
	}
}
