//go:build linux

package authorityrpc

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"net"
	"reflect"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"google.golang.org/protobuf/proto"
)

// The production VolumeHandler, TLS handshake, connection-set registry and
// runtime all participate. A refusal must neither renew nor fence the target.
func TestResumeRefusalIsUniformAndDoesNotTouchVictim(t *testing.T) {
	for _, variant := range []struct{ active, replay bool }{{true, false}, {true, true}, {false, false}} {
		active := variant.active
		state := "provisional"
		if active {
			state = "active"
			if variant.replay {
				state += "-replay"
			}
		}
		t.Run(state, func(t *testing.T) {
			f := newTopologyHandlerFixture(t)
			var elapsed atomic.Int64
			now := time.Now()
			runtime, err := volumeserver.New("handler-fskit", volumeserver.Config{SessionLease: time.Minute, MaxReplaySlots: 16, MaxSessions: 8, MaxLockRecords: 64, Now: func() time.Time { return now.Add(time.Duration(elapsed.Load())) }, ContinuousNow: func() (time.Duration, error) { return time.Second + time.Duration(elapsed.Load()), nil }})
			if err != nil {
				t.Fatal(err)
			}
			f.h.Runtime = runtime
			f.h.MaxRetainedReplyBytes = 8 << 20
			serverTLS, clientTLS, foreignTLS := testTLSIdentityConfigs(t)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(t.Context())
			server := &Server{Handler: f.h, MaxFrame: f.h.MaxFrame, MaxInFlight: 16, MaxConnections: 16, MaxFrameBytesInFlight: controlFrameReserve() + 8<<20, HandshakeTimeout: time.Second, IdleTimeout: time.Minute, WriteTimeout: time.Second}
			done := make(chan error, 1)
			go func() { done <- server.Serve(ctx, ln, serverTLS) }()
			defer func() {
				cancel()
				if err := <-done; err != nil {
					t.Error(err)
				}
			}()
			victim := newReconnectTestClient(ln.Addr().String(), clientTLS)
			victim.connectionSetID = [32]byte{1}
			open := func(c *Client) *transportNegotiation {
				t.Helper()
				n, err := c.openTransport(t.Context(), authoritypb.TransportRole_TRANSPORT_ROLE_DATA)
				if err != nil {
					t.Fatal(err)
				}
				return n
			}
			data := open(victim)
			defer data.conn.Close()
			control, err := victim.openTransport(t.Context(), authoritypb.TransportRole_TRANSPORT_ROLE_CONTROL)
			if err != nil {
				t.Fatal(err)
			}
			defer control.conn.Close()
			attach := fskitAttachRequest(2)
			attach.GetAttach().FrontendProfile = authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX
			attach.GetAttach().ReplaySlots = 9
			attached, err := rawRoundTrip(data.conn, data.maxFrame, attach)
			if err != nil || attached.GetErrno() != 0 {
				t.Fatal(attached, err)
			}
			proof := proofFromAttach(attached)
			var id volumeserver.SessionID
			copy(id[:], proof.Id)
			resume := func(n *transportNegotiation, p *authoritypb.SessionProof, requestID uint64) (*authoritypb.Response, error) {
				return rawRoundTrip(n.conn, n.maxFrame, &authoritypb.Request{RequestId: requestID, Epoch: f.h.Epoch(), Session: p, Body: &authoritypb.Request_Resume{Resume: &authoritypb.ResumeRequest{}}})
			}
			if out, err := resume(control, proof, 2); err != nil || out.GetResume().GetState() != authoritypb.SessionState_SESSION_STATE_PROVISIONAL {
				t.Fatal(out, err)
			}
			if active {
				q := &authoritypb.Request{RequestId: 3, Epoch: f.h.Epoch(), Session: proof, Body: &authoritypb.Request_Activate{Activate: &authoritypb.ActivateRequest{AttachAttemptId: attach.GetAttach().AttachAttemptId, DataBindingGeneration: attached.GetAttach().DataBindingGeneration, ControlBindingGeneration: attached.GetAttach().ControlBindingGeneration}}}
				out, err := rawRoundTrip(control.conn, control.maxFrame, q)
				if err != nil || out.GetErrno() != 0 {
					t.Fatal(out, err)
				}
			}
			if active {
				if out, err := resume(data, proof, 4); err != nil || out.GetResume().GetState() != authoritypb.SessionState_SESSION_STATE_ACTIVE {
					t.Fatal("valid active Resume", out, err)
				}
			}
			// Peer identity is SPKI, not the certificate DER.
			cert := clientTLS.Certificates[0]
			parsed, err := x509.ParseCertificate(cert.Certificate[0])
			if err != nil {
				t.Fatal(err)
			}
			peer := sha256.Sum256(parsed.RawSubjectPublicKeyInfo)
			var cred volumeserver.SessionCredential
			copy(cred.Epoch[:], f.h.Epoch())
			cred.ID = id
			copy(cred.Secret[:], proof.ResumeSecret)
			cred.Generation = proof.Generation
			cred.Peer = volumeserver.PeerIdentity(peer)
			var applied atomic.Int32
			mutation := volumeserver.MutationID{Slot: 0, Sequence: 1, Fingerprint: volumeserver.RequestFingerprint{1}}
			if active {
				if _, err := runtime.ExecuteMutation(t.Context(), cred, mutation, func(context.Context) volumeserver.Outcome {
					applied.Add(1)
					return volumeserver.Outcome{Reply: []byte("retained")}
				}); err != nil {
					t.Fatal(err)
				}
			}
			snapshot := func() transportPairSnapshot {
				server.registry.mu.Lock()
				defer server.registry.mu.Unlock()
				p := server.registry.pairs[transportPairKey{peer: cred.Peer, set: victim.connectionSetID}]
				return transportPairSnapshot{session: p.session, state: p.state, dataGeneration: generation(p.data.current), controlGeneration: generation(p.control.current)}
			}
			before := snapshot()
			elapsed.Store(int64(30 * time.Second))
			// All CA-valid but foreign/unbound requests receive the identical existing
			// protocol-8 refusal, whether their target is LIVE, provisional or unknown.
			for _, tc := range []struct {
				name            string
				tls             *tls.Config
				set             [32]byte
				unknown, secret bool
			}{
				{"foreign-live", foreignTLS, [32]byte{2}, false, false},
				{"foreign-unknown", foreignTLS, [32]byte{3}, true, false},
				{"wrong-set", clientTLS, [32]byte{4}, false, false},
				{"wrong-secret-unbound", clientTLS, [32]byte{5}, false, true},
				{"unknown", clientTLS, [32]byte{6}, true, true},
			} {
				t.Run(tc.name, func(t *testing.T) {
					c := newReconnectTestClient(ln.Addr().String(), tc.tls)
					c.connectionSetID = tc.set
					n := open(c)
					defer n.conn.Close()
					p := proto.Clone(proof).(*authoritypb.SessionProof)
					if tc.unknown {
						p.Id = bytes.Repeat([]byte{0x77}, 16)
					}
					if tc.secret {
						p.ResumeSecret = bytes.Repeat([]byte{0x88}, 32)
					}
					out, err := resume(n, p, 2)
					if err != nil || out.GetErrno() != int32(syscall.ESTALE) || !out.GetSessionTerminal() || out.GetBody() != nil {
						t.Fatal("nonuniform refusal", out, err)
					}
				})
			}
			for _, name := range []string{"no-certificate", "untrusted-certificate"} {
				t.Run(name, func(t *testing.T) {
					cfg := clientTLS.Clone()
					cfg.Certificates = nil
					if name == "untrusted-certificate" {
						_, other := testTLSConfigs(t)
						cfg.Certificates = other.Certificates
					}
					c := newReconnectTestClient(ln.Addr().String(), cfg)
					c.connectionSetID = [32]byte{9}
					n, err := c.openTransport(t.Context(), authoritypb.TransportRole_TRANSPORT_ROLE_DATA)
					if n != nil {
						n.conn.Close()
					}
					if err == nil {
						t.Fatal("untrusted peer reached Hello")
					}
				})
			}
			wrong := proto.Clone(proof).(*authoritypb.SessionProof)
			wrong.ResumeSecret = bytes.Repeat([]byte{0x88}, 32)
			out, err := resume(data, wrong, 5)
			if err != nil || out.GetErrno() != int32(syscall.ESTALE) || !out.GetSessionTerminal() {
				t.Fatal("bound wrong-secret refusal differs", out, err)
			}
			if after := snapshot(); !reflect.DeepEqual(before, after) {
				t.Fatal("foreign Resume altered victim binding", before, after)
			}
			if state, err := runtime.SessionState(cred, volumeserver.AttachAttemptID(attach.GetAttach().AttachAttemptId)); err != nil || active && state != volumeserver.SessionStateActive || !active && state != volumeserver.SessionStateProvisional {
				t.Fatal("victim fenced", state, err)
			}
			if variant.replay {
				out, err := runtime.ExecuteMutation(t.Context(), cred, mutation, func(context.Context) volumeserver.Outcome { applied.Add(1); return volumeserver.Outcome{} })
				if err != nil || applied.Load() != 1 || string(out.Reply) != "retained" {
					t.Fatal("victim replay altered", out, err)
				}
			}
			// No refusal renewed the original lease. This also removes authentication
			// evidence; the legitimate expired client must receive the same refusal.
			elapsed.Store(int64(61 * time.Second))
			if n := runtime.Sweep(); n != 1 && !variant.replay || n != 0 && variant.replay {
				t.Fatal("victim lease was changed by a refusal", n)
			}
			elapsed.Store(int64(3 * time.Minute))
			runtime.Sweep()
			if _, known := runtime.SessionStateByID(id); known {
				t.Fatal("expiry authentication evidence was not purged")
			}
			deadline := time.Now().Add(time.Second)
			for {
				server.registry.mu.Lock()
				gone := server.registry.pairs[transportPairKey{peer: cred.Peer, set: victim.connectionSetID}] == nil
				server.registry.mu.Unlock()
				if gone {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("expired transport binding was not cleaned up")
				}
				time.Sleep(time.Millisecond)
			}
			expired := newReconnectTestClient(ln.Addr().String(), clientTLS)
			expired.connectionSetID = victim.connectionSetID
			n := open(expired)
			defer n.conn.Close()
			out, err = resume(n, proof, 2)
			if err != nil || out.GetErrno() != int32(syscall.ESTALE) || !out.GetSessionTerminal() {
				t.Fatal("expiry has no definitive result", out, err)
			}
		})
	}
}
