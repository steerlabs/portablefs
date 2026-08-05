package portablefsd

// Shared pfslocal/control-plane test client. The daemon speaks two local
// protocols — the pfslocal frontend socket and the HTTP control socket — and
// every test that drives either one goes through these helpers.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/daemonctl"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

func waitUnix(t *testing.T, p string) {
	t.Helper()
	// Generous: a freshly BUILT daemon binary's first exec can queue behind
	// macOS binary assessment for several seconds when the machine is under
	// concurrent build/test load.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("unix", p, 50*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("socket %s did not become ready", p)
}

type protocolTransport struct {
	base *http.Transport
}

func (t protocolTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.Header.Set(daemonctl.ControlProtocolHeader, fmt.Sprint(daemonctl.ControlProtocolVersion))
	return t.base.RoundTrip(req)
}

func httpUDSClient(sock string) *http.Client {
	base := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}
	return &http.Client{Transport: protocolTransport{base: base}}
}

func rawHTTPUDSClient(sock string) *http.Client {
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", sock)
	}}}
}

func controlJSON(t *testing.T, hc *http.Client, method, path string, body any, want int, out any) {
	t.Helper()
	var r io.Reader
	if body != nil {
		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatal(err)
		}
		r = &buf
	}
	req, err := http.NewRequest(method, "http://portablefsd"+path, r)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != want {
		data, _ := io.ReadAll(resp.Body)
		t.Fatalf("%s %s status=%d want=%d body=%s", method, path, resp.StatusCode, want, data)
	}
	if out != nil {
		if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
			t.Fatal(err)
		}
	}
}

type pfsTestClient struct {
	t    *testing.T
	conn net.Conn
	next uint64
}

func dialPFS(t *testing.T, sock string) *pfsTestClient {
	t.Helper()
	c, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	return &pfsTestClient{t: t, conn: c}
}

func (c *pfsTestClient) close() { _ = c.conn.Close() }

func currentTestProtocol(body any) any {
	hello, ok := body.(*pfslocal.Hello)
	if !ok || hello.ProtocolMinor != 0 {
		return body
	}
	copy := *hello
	copy.ProtocolMinor = pfslocal.ProtocolMinor
	return &copy
}

func testOperationID(body any, requestID uint64) uint64 {
	if frontendRequestPublishes(body) {
		return requestID
	}
	return 0
}

func (c *pfsTestClient) call(body any) any {
	c.t.Helper()
	body = currentTestProtocol(body)
	c.next++
	id := c.next
	operationID := testOperationID(body, id)
	if err := pfslocal.WriteFrame(c.conn, &pfslocal.Envelope{
		RequestID: id, OperationID: operationID, Body: body,
	}); err != nil {
		c.t.Fatal(err)
	}
	for {
		env, err := pfslocal.ReadFrame(c.conn)
		if err != nil {
			c.t.Fatal(err)
		}
		if env.RequestID == 0 {
			continue
		}
		if env.RequestID != id {
			c.t.Fatalf("reply id=%d want %d", env.RequestID, id)
		}
		if er, ok := env.Body.(*pfslocal.ErrorReply); ok {
			c.t.Fatalf("unexpected error reply: %+v", er)
		}
		if env.PublicationAckRequired {
			if err := pfslocal.WriteFrame(c.conn, &pfslocal.Envelope{
				Body: &pfslocal.PublicationAck{OperationID: operationID},
			}); err != nil {
				c.t.Fatal(err)
			}
		}
		return env.Body
	}
}

func (c *pfsTestClient) callMaybe(body any) (any, *pfslocal.ErrorReply) {
	c.t.Helper()
	body = currentTestProtocol(body)
	c.next++
	id := c.next
	operationID := testOperationID(body, id)
	if err := pfslocal.WriteFrame(c.conn, &pfslocal.Envelope{
		RequestID: id, OperationID: operationID, Body: body,
	}); err != nil {
		c.t.Fatal(err)
	}
	for {
		env, err := pfslocal.ReadFrame(c.conn)
		if err != nil {
			c.t.Fatal(err)
		}
		if env.RequestID == 0 {
			continue
		}
		if env.RequestID != id {
			c.t.Fatalf("reply id=%d want %d", env.RequestID, id)
		}
		if er, ok := env.Body.(*pfslocal.ErrorReply); ok {
			if env.PublicationAckRequired {
				if err := pfslocal.WriteFrame(c.conn, &pfslocal.Envelope{
					Body: &pfslocal.PublicationAck{OperationID: operationID},
				}); err != nil {
					c.t.Fatal(err)
				}
			}
			return nil, er
		}
		if env.PublicationAckRequired {
			if err := pfslocal.WriteFrame(c.conn, &pfslocal.Envelope{
				Body: &pfslocal.PublicationAck{OperationID: operationID},
			}); err != nil {
				c.t.Fatal(err)
			}
		}
		return env.Body, nil
	}
}

func (c *pfsTestClient) callErr(body any) *pfslocal.ErrorReply {
	c.t.Helper()
	body = currentTestProtocol(body)
	c.next++
	id := c.next
	operationID := testOperationID(body, id)
	if err := pfslocal.WriteFrame(c.conn, &pfslocal.Envelope{
		RequestID: id, OperationID: operationID, Body: body,
	}); err != nil {
		c.t.Fatal(err)
	}
	for {
		env, err := pfslocal.ReadFrame(c.conn)
		if err != nil {
			c.t.Fatal(err)
		}
		if env.RequestID == 0 {
			continue
		}
		if env.RequestID != id {
			c.t.Fatalf("reply id=%d want %d", env.RequestID, id)
		}
		er, ok := env.Body.(*pfslocal.ErrorReply)
		if !ok {
			c.t.Fatalf("reply = %T, want ErrorReply", env.Body)
		}
		if env.PublicationAckRequired {
			if err := pfslocal.WriteFrame(c.conn, &pfslocal.Envelope{
				Body: &pfslocal.PublicationAck{OperationID: operationID},
			}); err != nil {
				c.t.Fatal(err)
			}
		}
		return er
	}
}

func readPFSReply(t *testing.T, conn net.Conn, requestID uint64) *pfslocal.Envelope {
	t.Helper()
	for {
		env, err := pfslocal.ReadFrame(conn)
		if err != nil {
			t.Fatal(err)
		}
		if env.RequestID == 0 {
			continue
		}
		if env.RequestID != requestID {
			t.Fatalf("reply id=%d want %d", env.RequestID, requestID)
		}
		return env
	}
}

func expectPFSConnectionClosed(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if env, err := pfslocal.ReadFrame(conn); err == nil {
		t.Fatalf("connection remained open; unexpected envelope %#v", env)
	}
}

func (c *pfsTestClient) subscribeAndWaitAttachState(want pfslocal.AttachStateState) *pfslocal.AttachState {
	c.t.Helper()
	c.next++
	id := c.next
	if err := pfslocal.WriteFrame(c.conn, &pfslocal.Envelope{RequestID: id, Body: &pfslocal.SubscribeEventsRequest{}}); err != nil {
		c.t.Fatal(err)
	}
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	defer c.conn.SetReadDeadline(time.Time{})
	var (
		gotReply bool
		gotState *pfslocal.AttachState
	)
	for !gotReply || gotState == nil {
		env, err := pfslocal.ReadFrame(c.conn)
		if err != nil {
			c.t.Fatalf("wait attach state: %v", err)
		}
		switch env.RequestID {
		case id:
			if er, ok := env.Body.(*pfslocal.ErrorReply); ok {
				c.t.Fatalf("subscribe error: %+v", er)
			}
			if _, ok := env.Body.(*pfslocal.SubscribeEventsReply); !ok {
				c.t.Fatalf("subscribe reply = %T", env.Body)
			}
			gotReply = true
		case 0:
			ev, ok := env.Body.(*pfslocal.Event)
			if !ok {
				continue
			}
			st, ok := ev.Kind.(*pfslocal.AttachState)
			if !ok {
				continue
			}
			if st.State == want {
				gotState = st
			}
		default:
			c.t.Fatalf("reply id=%d want %d or event", env.RequestID, id)
		}
	}
	return gotState
}

// startDaemonNoAttach runs a real daemon over private sockets with no attach
// at all — the state every daemon lifecycle test starts from.
func startDaemonNoAttach(t *testing.T, _ string) (Config, *http.Client, context.CancelFunc) {
	t.Helper()
	dir, err := os.MkdirTemp("", "pfsd-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	cfg := Config{
		FrontendSocket: filepath.Join(dir, "run", "frontend.sock"),
		ControlSocket:  filepath.Join(dir, "run", "control.sock"),
		StateDir:       filepath.Join(dir, "state"),
		Version:        "portablefsd-test",
	}
	ctx, cancel := context.WithCancel(context.Background())
	s := NewServer(cfg)
	runDone := make(chan error, 1)
	go func() {
		runDone <- s.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-runDone:
			if err != nil {
				t.Errorf("daemon Run: %v", err)
			}
		case <-time.After(35 * time.Second):
			t.Error("daemon did not complete its bounded cooperative shutdown")
		}
	})
	waitUnix(t, cfg.ControlSocket)
	waitUnix(t, cfg.FrontendSocket)
	return cfg, httpUDSClient(cfg.ControlSocket), cancel
}
