package authorityrpc

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

type clientTestHandler struct {
	epoch             []byte
	started           chan struct{}
	once              *sync.Once
	omitHelloFeature  bool
	omitAttachFeature bool
	keepAliveErrno    int32
}

func (h clientTestHandler) Handle(ctx context.Context, req *authoritypb.Request) *authoritypb.Response {
	response := &authoritypb.Response{RequestId: req.GetRequestId(), Epoch: append([]byte(nil), h.epoch...)}
	switch req.GetBody().(type) {
	case *authoritypb.Request_Hello:
		features := append([]string(nil), requiredHelloFeatures...)
		if h.omitHelloFeature {
			features = features[1:]
		}
		response.Body = &authoritypb.Response_Hello{Hello: &authoritypb.HelloReply{ProtocolMajor: ProtocolMajor, Features: features, MaxFrameBytes: 4 << 20, MaxReadBytes: 1 << 20, MaxWriteBytes: 1 << 20, MaxInFlight: 8}}
	case *authoritypb.Request_Attach:
		features := append([]string(nil), requiredAttachFeatures...)
		if h.omitAttachFeature {
			features = features[1:]
		}
		response.Body = &authoritypb.Response_Attach{Attach: &authoritypb.AttachReply{SessionId: make([]byte, 16), SessionGeneration: 1, ResumeSecret: make([]byte, 32), Root: &authoritypb.Item{Token: make([]byte, 16)}, Features: features, SessionLeaseMilliseconds: 30_000}}
	case *authoritypb.Request_Resume:
	case *authoritypb.Request_KeepAlive:
		response.Errno = h.keepAliveErrno
	case *authoritypb.Request_Cancel:
	case *authoritypb.Request_StatFs:
		if h.started != nil {
			h.once.Do(func() { close(h.started) })
		}
		<-ctx.Done()
		response.Errno = 4
	default:
		response.Errno = 95
	}
	return response
}

func TestClientSignalsTerminalSessionOnExpiredKeepAlive(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	server := &Server{
		Handler:  clientTestHandler{epoch: make([]byte, 16), keepAliveErrno: int32(syscall.ESTALE)},
		MaxFrame: 4 << 20, MaxInFlight: 2, MaxConnections: 4,
		HandshakeTimeout: time.Second, IdleTimeout: time.Minute, WriteTimeout: time.Second,
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener, serverTLS) }()
	client, err := DialClient(context.Background(), ClientConfig{
		Address: listener.Addr().String(), TLS: clientTLS, VolumeID: "volume", AccessToken: []byte("cap"),
		ReplaySlots: 2, MaxFrame: 4 << 20, DialTimeout: time.Second, CancelDrainTimeout: time.Second, MaxInFlight: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.CallRead(context.Background(), &authoritypb.Request{Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}})
	if err != nil || response.GetErrno() != int32(syscall.ESTALE) {
		t.Fatalf("KeepAlive = %v, %v", response, err)
	}
	select {
	case <-client.SessionDone():
		if !errors.Is(client.SessionError(), ErrSessionEnded) {
			t.Fatalf("SessionError = %v", client.SessionError())
		}
	case <-time.After(time.Second):
		t.Fatal("terminal session signal was not delivered")
	}
	_ = client.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestIdleConnectionClosureSignalsTerminalSession(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	server := &Server{
		Handler: clientTestHandler{epoch: make([]byte, 16)}, MaxFrame: 4 << 20,
		MaxInFlight: 2, MaxConnections: 4, HandshakeTimeout: time.Second,
		IdleTimeout: 50 * time.Millisecond, WriteTimeout: time.Second,
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener, serverTLS) }()
	client, err := DialClient(context.Background(), ClientConfig{
		Address: listener.Addr().String(), TLS: clientTLS, VolumeID: "volume", AccessToken: []byte("cap"),
		ReplaySlots: 2, MaxFrame: 4 << 20, DialTimeout: time.Second, CancelDrainTimeout: time.Second, MaxInFlight: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-client.SessionDone():
		if !errors.Is(client.SessionError(), ErrTransportUncertain) {
			t.Fatalf("SessionError = %v", client.SessionError())
		}
	case <-time.After(time.Second):
		t.Fatal("idle connection death was not signaled")
	}
	_ = client.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestClientRequiresArchitectureFeatures(t *testing.T) {
	for _, tc := range []struct {
		name    string
		handler clientTestHandler
	}{
		{name: "hello", handler: clientTestHandler{epoch: make([]byte, 16), omitHelloFeature: true}},
		{name: "attach", handler: clientTestHandler{epoch: make([]byte, 16), omitAttachFeature: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serverTLS, clientTLS := testTLSConfigs(t)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			server := &Server{Handler: tc.handler, MaxFrame: 4 << 20, MaxInFlight: 2, MaxConnections: 8, HandshakeTimeout: time.Second, IdleTimeout: time.Minute, WriteTimeout: time.Second}
			done := make(chan error, 1)
			go func() { done <- server.Serve(ctx, listener, serverTLS) }()
			_, err = DialClient(context.Background(), ClientConfig{Address: listener.Addr().String(), TLS: clientTLS, VolumeID: "volume", AccessToken: []byte("cap"), ReplaySlots: 2, MaxFrame: 4 << 20, DialTimeout: time.Second, CancelDrainTimeout: time.Second, MaxInFlight: 2})
			if err == nil {
				t.Fatal("DialClient accepted an authority missing a required feature")
			}
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestClientCancellationDrainsAuthorityOutcome(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverCtx, stopServer := context.WithCancel(context.Background())
	defer stopServer()
	started := make(chan struct{})
	server := &Server{Handler: clientTestHandler{epoch: make([]byte, 16), started: started, once: new(sync.Once)}, MaxFrame: 4 << 20, MaxInFlight: 1, MaxConnections: 8, HandshakeTimeout: time.Second, IdleTimeout: time.Minute, WriteTimeout: time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(serverCtx, listener, serverTLS) }()
	client, err := DialClient(context.Background(), ClientConfig{Address: listener.Addr().String(), TLS: clientTLS, VolumeID: "volume", AccessToken: []byte("cap"), ReplaySlots: 2, MaxFrame: 4 << 20, DialTimeout: time.Second, CancelDrainTimeout: time.Second, MaxInFlight: 2})
	if err != nil {
		t.Fatal(err)
	}
	callCtx, cancel := context.WithCancel(context.Background())
	result := make(chan callResult, 1)
	go func() {
		response, err := client.CallRead(callCtx, &authoritypb.Request{Body: &authoritypb.Request_StatFs{StatFs: &authoritypb.StatFSRequest{}}})
		result <- callResult{response: response, err: err}
	}()
	<-started
	cancel()
	select {
	case outcome := <-result:
		if outcome.err != nil || outcome.response.GetErrno() != 4 {
			t.Fatalf("canceled call = (%v, %v), want exact EINTR response", outcome.response, outcome.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled call did not drain")
	}
	_ = client.Close()
	stopServer()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestTLSClientAttachAndMultiplexedCall(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := &Server{Handler: clientTestHandler{epoch: make([]byte, 16)}, MaxFrame: 4 << 20, MaxInFlight: 8, MaxConnections: 8, HandshakeTimeout: time.Second, IdleTimeout: time.Minute, WriteTimeout: time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener, serverTLS) }()

	client, err := DialClient(context.Background(), ClientConfig{Address: listener.Addr().String(), TLS: clientTLS, VolumeID: "volume", AccessToken: []byte("cap"), ReplaySlots: 4, MaxFrame: 4 << 20, DialTimeout: time.Second, CancelDrainTimeout: time.Second, MaxInFlight: 4})
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Call(context.Background(), &authoritypb.Request{Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}})
	if err != nil || response.GetErrno() != 0 || response.GetRequestId() == 0 {
		t.Fatalf("Call = %v, %v", response, err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentCallsReconnectWhenConnectionIsTransientlyMissing(t *testing.T) {
	serverTLS, clientTLS := testTLSConfigs(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	server := &Server{
		Handler: clientTestHandler{epoch: make([]byte, 16)}, MaxFrame: 4 << 20,
		MaxInFlight: 8, MaxConnections: 8, HandshakeTimeout: time.Second,
		IdleTimeout: time.Minute, WriteTimeout: time.Second,
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener, serverTLS) }()
	client, err := DialClient(context.Background(), ClientConfig{
		Address: listener.Addr().String(), TLS: clientTLS, VolumeID: "volume", AccessToken: []byte("cap"),
		ReplaySlots: 4, MaxFrame: 4 << 20, DialTimeout: time.Second, CancelDrainTimeout: time.Second, MaxInFlight: 4,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Model a transport break that had an in-flight caller. It is recoverable in
	// the same epoch, unlike an idle break, and leaves a short conn==nil window.
	client.pendingMu.Lock()
	oldConn := client.conn
	fakePending := make(chan callResult, 1)
	client.pending[999] = fakePending
	client.pendingMu.Unlock()
	client.failConnection(oldConn, ErrTransportUncertain)
	<-fakePending

	start := make(chan struct{})
	results := make(chan error, 2)
	go func() {
		<-start
		response, err := client.CallRead(context.Background(), &authoritypb.Request{Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}})
		if err == nil && response.GetErrno() != 0 {
			err = syscall.Errno(response.GetErrno())
		}
		results <- err
	}()
	go func() {
		<-start
		response, err := client.CallMutation(context.Background(), &authoritypb.Request{Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}})
		if err == nil && response.GetErrno() != 0 {
			err = syscall.Errno(response.GetErrno())
		}
		results <- err
	}()
	close(start)
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("same-epoch concurrent reconnect call: %v", err)
		}
	}
	select {
	case <-client.SessionDone():
		t.Fatalf("recoverable connection gap ended session: %v", client.SessionError())
	default:
	}
	_ = client.Close()
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func testTLSConfigs(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	now := time.Now()
	caPub, caKey, _ := ed25519.GenerateKey(rand.Reader)
	caTemplate := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "PortableFS test CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, caPub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(serial int64, name string, usages []x509.ExtKeyUsage, dns []string) tls.Certificate {
		pub, key, _ := ed25519.GenerateKey(rand.Reader)
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name}, DNSNames: dns, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages}
		der, err := x509.CreateCertificate(rand.Reader, template, ca, pub, caKey)
		if err != nil {
			t.Fatal(err)
		}
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			t.Fatal(err)
		}
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})
		cert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	serverCert := issue(2, "server", []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, []string{"localhost"})
	clientCert := issue(3, "client", []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, nil)
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, Certificates: []tls.Certificate{serverCert}}, &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, Certificates: []tls.Certificate{clientCert}, ServerName: "localhost"}
}
