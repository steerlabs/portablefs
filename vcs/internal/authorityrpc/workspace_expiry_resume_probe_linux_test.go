//go:build linux

package authorityrpc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"reflect"
	"sort"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"google.golang.org/protobuf/proto"
)

// R3: a second CA-valid identity probes LIVE, unknown, expired (tombstoned)
// and purged session IDs. Responses, post-refusal connection behaviour and
// timing must not distinguish them; the victim must be untouched; the
// legitimate expired client must still latch ErrSessionEnded.
func TestOpusR3ResumeProbeUniform(t *testing.T) {
	f := newTopologyHandlerFixture(t)
	var elapsed atomic.Int64
	now := time.Now()
	rt, err := volumeserver.New("handler-fskit", volumeserver.Config{SessionLease: time.Minute, MaxReplaySlots: 16, MaxSessions: 8, MaxLockRecords: 64, Now: func() time.Time { return now.Add(time.Duration(elapsed.Load())) }, ContinuousNow: func() (time.Duration, error) { return time.Second + time.Duration(elapsed.Load()), nil }})
	if err != nil {
		t.Fatal(err)
	}
	f.h.Runtime = rt
	f.h.MaxRetainedReplyBytes = 8 << 20
	serverTLS, clientTLS, foreignTLS := testTLSIdentityConfigs(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	server := &Server{Handler: f.h, MaxFrame: f.h.MaxFrame, MaxInFlight: 16, MaxConnections: 64, MaxFrameBytesInFlight: controlFrameReserve() + 8<<20, HandshakeTimeout: time.Second, IdleTimeout: time.Minute, WriteTimeout: time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, ln, serverTLS) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	addr := ln.Addr().String()
	open := func(c *Client) *transportNegotiation {
		t.Helper()
		n, err := c.openTransport(t.Context(), authoritypb.TransportRole_TRANSPORT_ROLE_DATA)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	type legit struct {
		set           [32]byte
		proof         *authoritypb.SessionProof
		id            volumeserver.SessionID
		attempt       []byte
		data, control *transportNegotiation
	}
	nextAttach := uint64(10)
	attachSession := func(set byte) legit {
		t.Helper()
		c := newReconnectTestClient(addr, clientTLS)
		c.connectionSetID = [32]byte{set}
		data := open(c)
		control, err := c.openTransport(t.Context(), authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL)
		if err != nil {
			t.Fatal(err)
		}
		nextAttach++
		attach := fskitAttachRequest(nextAttach)
		attach.GetAttach().FrontendProfile = authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX
		attach.GetAttach().ReplaySlots = 9
		attached, err := rawRoundTrip(data.conn, data.maxFrame, attach)
		if err != nil || attached.GetErrno() != 0 {
			t.Fatal(attached, err)
		}
		proof := proofFromAttach(attached)
		if out, err := rawRoundTrip(control.conn, control.maxFrame, &authoritypb.Request{RequestId: 2, Epoch: f.h.Epoch(), Session: proof, Body: &authoritypb.Request_Resume{Resume: &authoritypb.ResumeRequest{}}}); err != nil || out.GetErrno() != 0 {
			t.Fatal(out, err)
		}
		q := &authoritypb.Request{RequestId: 3, Epoch: f.h.Epoch(), Session: proof, Body: &authoritypb.Request_Activate{Activate: &authoritypb.ActivateRequest{AttachAttemptId: attach.GetAttach().AttachAttemptId, DataBindingGeneration: attached.GetAttach().DataBindingGeneration, ControlBindingGeneration: attached.GetAttach().ControlBindingGeneration}}}
		if out, err := rawRoundTrip(control.conn, control.maxFrame, q); err != nil || out.GetErrno() != 0 {
			t.Fatal(out, err)
		}
		var id volumeserver.SessionID
		copy(id[:], proof.Id)
		return legit{set: c.connectionSetID, proof: proof, id: id, attempt: attach.GetAttach().AttachAttemptId, data: data, control: control}
	}
	// P: expired and purged; X: expired, tombstone retained; V: LIVE victim.
	p := attachSession(0x10)
	elapsed.Store(int64(61 * time.Second))
	rt.Sweep()
	elapsed.Store(int64(4 * time.Minute))
	rt.Sweep()
	if _, known := rt.SessionStateByID(p.id); known {
		t.Fatal("P not purged")
	}
	x := attachSession(0x11)
	elapsed.Store(int64(4*time.Minute + 61*time.Second))
	rt.Sweep()
	xs, xknown := rt.SessionStateByID(x.id)
	t.Logf("X after expiry: state=%v known=%v", xs, xknown)
	t2 := 4*time.Minute + 61*time.Second
	v := attachSession(0x12)
	cert := clientTLS.Certificates[0]
	parsed, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	var cred volumeserver.SessionCredential
	copy(cred.Epoch[:], f.h.Epoch())
	cred.ID = v.id
	copy(cred.Secret[:], v.proof.ResumeSecret)
	cred.Generation = v.proof.Generation
	cred.Peer = volumeserver.PeerIdentity(sha256.Sum256(parsed.RawSubjectPublicKeyInfo))
	var applied atomic.Int32
	mutation := volumeserver.MutationID{Slot: 0, Sequence: 1, Fingerprint: volumeserver.RequestFingerprint{1}}
	if _, err := rt.ExecuteMutation(t.Context(), cred, mutation, func(context.Context) volumeserver.Outcome {
		applied.Add(1)
		return volumeserver.Outcome{Reply: []byte("retained")}
	}); err != nil {
		t.Fatal(err)
	}
	snapshot := func() transportPairSnapshot {
		server.registry.mu.Lock()
		defer server.registry.mu.Unlock()
		pr := server.registry.pairs[transportPairKey{peer: cred.Peer, set: v.set}]
		if pr == nil {
			return transportPairSnapshot{}
		}
		return transportPairSnapshot{session: pr.session, state: pr.state, dataGeneration: generation(pr.data.current), controlGeneration: generation(pr.control.current)}
	}
	before := snapshot()
	// Any lease renewal by a probe would move expiry from t2+60s to >= t2+90s.
	elapsed.Store(int64(t2 + 30*time.Second))

	random := func(n int) []byte { b := make([]byte, n); _, _ = rand.Read(b); return b }
	withID := func(base *authoritypb.SessionProof, id []byte, secret []byte) *authoritypb.SessionProof {
		q := proto.Clone(base).(*authoritypb.SessionProof)
		if id != nil {
			q.Id = id
		}
		if secret != nil {
			q.ResumeSecret = secret
		}
		return q
	}
	categories := []struct {
		name  string
		proof func() *authoritypb.SessionProof
	}{
		{"live-stolen-secret", func() *authoritypb.SessionProof { return withID(v.proof, nil, nil) }},
		{"live-bogus-secret", func() *authoritypb.SessionProof { return withID(v.proof, nil, random(32)) }},
		{"unknown", func() *authoritypb.SessionProof { return withID(v.proof, random(16), random(32)) }},
		{"expired-tombstone", func() *authoritypb.SessionProof { return withID(x.proof, nil, nil) }},
		{"expired-tombstone-bogus", func() *authoritypb.SessionProof { return withID(x.proof, nil, random(32)) }},
		{"purged", func() *authoritypb.SessionProof { return withID(p.proof, nil, nil) }},
	}
	canonical := func(r *authoritypb.Response) string {
		q := proto.Clone(r).(*authoritypb.Response)
		q.RequestId = 0
		b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(q)
		return fmt.Sprintf("%x", b)
	}
	// 1. Fresh connection per category: first response, second Resume on the
	// same connection, then a non-lifecycle request (connection fate).
	var reference string
	for _, cat := range categories {
		c := newReconnectTestClient(addr, foreignTLS)
		c.connectionSetID = [32]byte(random(32))
		n := open(c)
		out, err := rawRoundTrip(n.conn, n.maxFrame, &authoritypb.Request{RequestId: 2, Epoch: f.h.Epoch(), Session: cat.proof(), Body: &authoritypb.Request_Resume{Resume: &authoritypb.ResumeRequest{}}})
		if err != nil {
			t.Fatalf("%s: %v", cat.name, err)
		}
		second, serr := rawRoundTrip(n.conn, n.maxFrame, &authoritypb.Request{RequestId: 3, Epoch: f.h.Epoch(), Session: cat.proof(), Body: &authoritypb.Request_Resume{Resume: &authoritypb.ResumeRequest{}}})
		_, kerr := rawRoundTrip(n.conn, n.maxFrame, &authoritypb.Request{RequestId: 4, Epoch: f.h.Epoch(), Session: cat.proof(), Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}})
		closed := errors.Is(kerr, io.EOF) || errors.Is(kerr, io.ErrUnexpectedEOF) || kerr != nil
		fate := fmt.Sprintf("second=%s/%v keepalive-closed=%v", canonical(second), serr != nil, closed)
		got := canonical(out) + " " + fate
		t.Logf("%-24s errno=%d terminal=%v body=%v fate: %s", cat.name, out.GetErrno(), out.GetSessionTerminal(), out.GetBody() != nil, fate)
		if out.GetErrno() != int32(syscall.ESTALE) || !out.GetSessionTerminal() || out.GetBody() != nil {
			t.Errorf("%s: unexpected refusal %v", cat.name, out)
		}
		if reference == "" {
			reference = got
		} else if got != reference {
			t.Errorf("DISTINGUISHABLE: %s response/fate %q differs from %q", cat.name, got, reference)
		}
		_ = n.conn.Close()
	}
	// 2. Timing: one long-lived foreign connection, interleaved categories.
	c := newReconnectTestClient(addr, foreignTLS)
	c.connectionSetID = [32]byte(random(32))
	n := open(c)
	defer n.conn.Close()
	_ = n.conn.SetDeadline(time.Time{}) // the handshake deadline is not part of the probe
	const rounds = 600
	samples := make(map[string][]float64)
	order := make([]int, len(categories))
	for i := range order {
		order[i] = i
	}
	id := uint64(10)
	for r := 0; r < rounds+50; r++ {
		perm := random(len(order))
		sort.SliceStable(order, func(a, b int) bool { return perm[a] < perm[b] })
		for _, i := range order {
			cat := categories[i]
			id++
			q := &authoritypb.Request{RequestId: id, Epoch: f.h.Epoch(), Session: cat.proof(), Body: &authoritypb.Request_Resume{Resume: &authoritypb.ResumeRequest{}}}
			start := time.Now()
			out, err := rawRoundTrip(n.conn, n.maxFrame, q)
			d := time.Since(start)
			if err != nil || out.GetErrno() != int32(syscall.ESTALE) || !out.GetSessionTerminal() {
				t.Fatalf("%s round %d: %v %v", cat.name, r, out, err)
			}
			if r >= 50 { // warm-up excluded
				samples[cat.name] = append(samples[cat.name], float64(d.Microseconds()))
			}
		}
	}
	quant := func(s []float64, q float64) float64 {
		c := append([]float64(nil), s...)
		sort.Float64s(c)
		return c[int(math.Min(float64(len(c)-1), q*float64(len(c))))]
	}
	var medians []float64
	for _, cat := range categories {
		s := samples[cat.name]
		var sum float64
		for _, v := range s {
			sum += v
		}
		med := quant(s, 0.5)
		medians = append(medians, med)
		t.Logf("TIMING %-24s n=%d p10=%.0fus median=%.0fus p90=%.0fus mean=%.1fus", cat.name, len(s), quant(s, 0.1), med, quant(s, 0.9), sum/float64(len(s)))
	}
	sort.Float64s(medians)
	if spread := medians[len(medians)-1] - medians[0]; spread > math.Max(20, 0.2*medians[0]) {
		t.Errorf("TIMING spread between category medians %.0fus exceeds bound", spread)
	} else {
		t.Logf("TIMING median spread %.0fus", spread)
	}
	// 3. Victim untouched: binding, state, replay, lease.
	if after := snapshot(); !reflect.DeepEqual(before, after) {
		t.Errorf("victim binding changed: %+v -> %+v", before, after)
	}
	if state, err := rt.SessionState(cred, volumeserver.AttachAttemptID(v.attempt[:32])); err != nil || state != volumeserver.SessionStateActive {
		t.Errorf("victim state %v %v", state, err)
	}
	elapsed.Store(int64(t2 + 59*time.Second))
	rt.Sweep()
	if s, known := rt.SessionStateByID(v.id); !known || s != volumeserver.SessionStateActive {
		t.Errorf("victim ended early: %v %v", s, known)
	}
	// Replay check renews; do it on a clone credential after the lease probe.
	elapsed.Store(int64(t2 + 61*time.Second))
	rt.Sweep()
	vs, vknown := rt.SessionStateByID(v.id)
	t.Logf("victim at t2+61s (no renewal since t2): state=%v known=%v", vs, vknown)
	if vknown && vs == volumeserver.SessionStateActive {
		t.Errorf("victim lease was renewed by a foreign probe")
	}
	// 4. The legitimate expired clients (tombstoned X, purged P, and now V)
	// latch ErrSessionEnded through the real reconnect path.
	for _, s := range []struct {
		name string
		l    legit
	}{{"expired-tombstone", x}, {"purged", p}, {"victim-now-expired", v}} {
		cl := newReconnectTestClient(addr, clientTLS)
		cl.connectionSetID = s.l.set
		cl.epoch = append([]byte(nil), f.h.Epoch()...)
		cl.proof = proto.Clone(s.l.proof).(*authoritypb.SessionProof)
		cl.negotiatedFrame, cl.negotiatedInFlight, cl.maxRead, cl.maxWrite = s.l.data.maxFrame, s.l.data.maxInFlight, s.l.data.maxRead, s.l.data.maxWrite
		err := cl.reconnectTransport(t.Context(), authoritypb.TransportRole_TRANSPORT_ROLE_DATA)
		t.Logf("legit %s reconnect: err=%v SessionEndCause=%v", s.name, err, cl.SessionEndCause())
		if !errors.Is(err, ErrSessionEnded) || !errors.Is(cl.SessionEndCause(), ErrSessionEnded) {
			t.Errorf("legit %s did not latch ErrSessionEnded: %v / %v", s.name, err, cl.SessionEndCause())
		}
	}
	_ = bytes.Equal
}

// R3: the positive control. A LIVE legitimate client whose DATA dropped still
// resumes (the uniform refusal is not reachable for its own binding), and the
// foreign probes in between do not disturb it.
func TestOpusR3LegitLiveResumeUnaffected(t *testing.T) {
	f := newTopologyHandlerFixture(t)
	now := time.Now()
	rt, err := volumeserver.New("handler-fskit", volumeserver.Config{SessionLease: time.Minute, MaxReplaySlots: 16, MaxSessions: 8, MaxLockRecords: 64, Now: func() time.Time { return now }, ContinuousNow: func() (time.Duration, error) { return time.Second, nil }})
	if err != nil {
		t.Fatal(err)
	}
	f.h.Runtime = rt
	f.h.MaxRetainedReplyBytes = 8 << 20
	serverTLS, clientTLS, foreignTLS := testTLSIdentityConfigs(t)
	ln, lerr := net.Listen("tcp", "127.0.0.1:0")
	if lerr != nil {
		t.Fatal(lerr)
	}
	ctx, cancel := context.WithCancel(t.Context())
	server := &Server{Handler: f.h, MaxFrame: f.h.MaxFrame, MaxInFlight: 16, MaxConnections: 64, MaxFrameBytesInFlight: controlFrameReserve() + 8<<20, HandshakeTimeout: time.Second, IdleTimeout: time.Minute, WriteTimeout: time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, ln, serverTLS) }()
	defer func() { cancel(); <-done }()
	addr := ln.Addr().String()
	c := newReconnectTestClient(addr, clientTLS)
	c.connectionSetID = [32]byte{0x21}
	data, err := c.openTransport(t.Context(), authoritypb.TransportRole_TRANSPORT_ROLE_DATA)
	if err != nil {
		t.Fatal(err)
	}
	control, err := c.openTransport(t.Context(), authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL)
	if err != nil {
		t.Fatal(err)
	}
	defer control.conn.Close()
	attach := fskitAttachRequest(77)
	attach.GetAttach().FrontendProfile = authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX
	attach.GetAttach().ReplaySlots = 9
	attached, err := rawRoundTrip(data.conn, data.maxFrame, attach)
	if err != nil || attached.GetErrno() != 0 {
		t.Fatal(attached, err)
	}
	proof := proofFromAttach(attached)
	if out, err := rawRoundTrip(control.conn, control.maxFrame, &authoritypb.Request{RequestId: 2, Epoch: f.h.Epoch(), Session: proof, Body: &authoritypb.Request_Resume{Resume: &authoritypb.ResumeRequest{}}}); err != nil || out.GetErrno() != 0 {
		t.Fatal(out, err)
	}
	q := &authoritypb.Request{RequestId: 3, Epoch: f.h.Epoch(), Session: proof, Body: &authoritypb.Request_Activate{Activate: &authoritypb.ActivateRequest{AttachAttemptId: attach.GetAttach().AttachAttemptId, DataBindingGeneration: attached.GetAttach().DataBindingGeneration, ControlBindingGeneration: attached.GetAttach().ControlBindingGeneration}}}
	if out, err := rawRoundTrip(control.conn, control.maxFrame, q); err != nil || out.GetErrno() != 0 {
		t.Fatal(out, err)
	}
	parsedCert, perr := x509.ParseCertificate(clientTLS.Certificates[0].Certificate[0])
	if perr != nil {
		t.Fatal(perr)
	}
	var cred volumeserver.SessionCredential
	copy(cred.Epoch[:], f.h.Epoch())
	copy(cred.ID[:], proof.Id)
	copy(cred.Secret[:], proof.ResumeSecret)
	cred.Generation = proof.Generation
	cred.Peer = volumeserver.PeerIdentity(sha256.Sum256(parsedCert.RawSubjectPublicKeyInfo))
	var applied atomic.Int32
	mutation := volumeserver.MutationID{Slot: 0, Sequence: 1, Fingerprint: volumeserver.RequestFingerprint{7}}
	if _, err := rt.ExecuteMutation(t.Context(), cred, mutation, func(context.Context) volumeserver.Outcome {
		applied.Add(1)
		return volumeserver.Outcome{Reply: []byte("retained")}
	}); err != nil {
		t.Fatal(err)
	}
	// Foreign probes with the stolen proof.
	for i := 0; i < 20; i++ {
		fc := newReconnectTestClient(addr, foreignTLS)
		fc.connectionSetID = [32]byte{0x30, byte(i)}
		n, err := fc.openTransport(t.Context(), authoritypb.TransportRole_TRANSPORT_ROLE_DATA)
		if err != nil {
			t.Fatal(err)
		}
		out, err := rawRoundTrip(n.conn, n.maxFrame, &authoritypb.Request{RequestId: 2, Epoch: f.h.Epoch(), Session: proof, Body: &authoritypb.Request_Resume{Resume: &authoritypb.ResumeRequest{}}})
		if err != nil || out.GetErrno() != int32(syscall.ESTALE) {
			t.Fatal(out, err)
		}
		_ = n.conn.Close()
	}
	// The legitimate DATA connection drops; the real reconnect path resumes.
	_ = data.conn.Close()
	time.Sleep(100 * time.Millisecond)
	c.epoch = append([]byte(nil), f.h.Epoch()...)
	c.proof = proto.Clone(proof).(*authoritypb.SessionProof)
	c.negotiatedFrame, c.negotiatedInFlight, c.maxRead, c.maxWrite = data.maxFrame, data.maxInFlight, data.maxRead, data.maxWrite
	err = c.reconnectTransport(t.Context(), authoritypb.TransportRole_TRANSPORT_ROLE_DATA)
	t.Logf("legit LIVE reconnect: err=%v SessionEndCause=%v", err, c.SessionEndCause())
	if err != nil || c.SessionEndCause() != nil {
		t.Fatal("legitimate LIVE Resume failed", err, c.SessionEndCause())
	}
	out, rerr := rt.ExecuteMutation(t.Context(), cred, mutation, func(context.Context) volumeserver.Outcome { applied.Add(1); return volumeserver.Outcome{} })
	t.Logf("victim replay after probes: applied=%d reply=%q err=%v", applied.Load(), out.Reply, rerr)
	if rerr != nil || applied.Load() != 1 || string(out.Reply) != "retained" {
		t.Fatal("victim replay altered by foreign probes", out, rerr)
	}
}
