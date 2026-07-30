package portablefsd

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/steerlabs/portablefs/vcs/internal/content"
	"github.com/steerlabs/portablefs/vcs/internal/pfj3"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/daemonctl"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
)

type daemonTestBlobs struct{}

func (daemonTestBlobs) Blob(context.Context, string) ([]byte, error) {
	return nil, errors.New("no backed blobs in portablefsd tests")
}

func serveAuthority(t *testing.T) string {
	t.Helper()
	addr, _ := serveAuthorityServer(t)
	return addr
}

func serveAuthorityServer(t *testing.T) (string, *fsproto.Server) {
	t.Helper()
	fs := newManagedTestFS(t, daemonTestBlobs{}, filepath.Join(privateTestDir(t), "wal.log"))
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srv := fsproto.NewServer(fs, fs)
	go func() { _ = srv.Serve(ctx, ln) }()
	return ln.Addr().String(), srv
}

func startDaemon(t *testing.T, authority string) (Config, *http.Client, string, context.CancelFunc) {
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
	for _, p := range []string{cfg.ControlSocket, cfg.FrontendSocket} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("%s mode=%o, want 0600", p, got)
		}
	}
	hc := httpUDSClient(cfg.ControlSocket)
	ref := ensureAttach(t, hc, authority, "vol-test", "main", "/Volumes/Test")
	return cfg, hc, ref, cancel
}

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

func ensureAttach(t *testing.T, hc *http.Client, authority, volumeID, branch, mountPath string) string {
	return ensureAttachWithPolicy(t, hc, authority, volumeID, branch, mountPath, "writethrough")
}

func ensureAttachWithPolicy(t *testing.T, hc *http.Client, authority, volumeID, branch, mountPath, writePolicy string) string {
	t.Helper()
	out := ensureAttachOnceWithPolicy(t, hc, authority, volumeID, branch, mountPath, writePolicy, "", nil)
	out2 := ensureAttachOnceWithPolicy(t, hc, authority, volumeID, branch, mountPath, writePolicy, "renewed", nil)
	if out2.AttachRef != out.AttachRef {
		t.Fatalf("idempotent attach ref=%q want %q", out2.AttachRef, out.AttachRef)
	}
	return out.AttachRef
}

func ensureAttachWithPolicyOptions(t *testing.T, hc *http.Client, authority, volumeID, branch, mountPath, writePolicy string, options map[string]any) string {
	t.Helper()
	out := ensureAttachOnceWithPolicy(t, hc, authority, volumeID, branch, mountPath, writePolicy, "", options)
	out2 := ensureAttachOnceWithPolicy(t, hc, authority, volumeID, branch, mountPath, writePolicy, "renewed", options)
	if out2.AttachRef != out.AttachRef {
		t.Fatalf("idempotent attach ref=%q want %q", out2.AttachRef, out.AttachRef)
	}
	return out.AttachRef
}

func TestControlAttachHonorsRequestedStableIdentityIdempotently(t *testing.T) {
	authority := serveAuthority(t)
	_, hc, _, _ := startDaemon(t, authority)
	const attachRef = "att_RRRRRRRRRRRRRRRRRRRRRR"
	request := map[string]any{
		"attachRef":          attachRef,
		"volumeId":           "vol-requested-ref",
		"branch":             "main",
		"authorityUrl":       authority,
		"dataPlaneTransport": "plaintext",
		"mountPath":          "/Volumes/RequestedRef",
		"options":            map[string]any{"diskCacheMb": 1},
	}
	for attempt := 0; attempt < 2; attempt++ {
		var out struct {
			AttachRef string `json:"attachRef"`
		}
		controlJSON(t, hc, http.MethodPost, "/v1/attaches", request, http.StatusOK, &out)
		if out.AttachRef != attachRef {
			t.Fatalf("attempt %d attachRef = %q, want requested %q", attempt+1, out.AttachRef, attachRef)
		}
	}
}

func ensureAttachOnceWithPolicy(t *testing.T, hc *http.Client, authority, volumeID, branch, mountPath, writePolicy, authToken string, extraOptions map[string]any) struct {
	AttachRef  string `json:"attachRef"`
	VolumeName string `json:"volumeName"`
} {
	t.Helper()
	var out struct {
		AttachRef  string `json:"attachRef"`
		VolumeName string `json:"volumeName"`
	}
	options := map[string]any{"writePolicy": writePolicy, "negativeCache": true, "diskCacheMb": 1}
	for k, v := range extraOptions {
		options[k] = v
	}
	controlJSON(t, hc, http.MethodPost, "/v1/attaches", map[string]any{
		"volumeId": volumeID, "branch": branch, "authorityUrl": authority, "authToken": authToken, "mountPath": mountPath,
		"dataPlaneTransport": "plaintext",
		"options":            options,
	}, http.StatusOK, &out)
	if out.AttachRef == "" || out.VolumeName == "" {
		t.Fatalf("bad attach response: %+v", out)
	}
	return out
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

func seedAuthorityFiles(t *testing.T, authority string, n int) []string {
	t.Helper()
	cli, err := fsproto.Dial(authority, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	names := make([]string, 0, n)
	for i := 0; i < n; i++ {
		name := fmt.Sprintf("f%05d", i)
		if _, st, err := cli.Create(name, 0o644); err != nil || st != fsproto.OK {
			t.Fatalf("seed create %s: st=%d err=%v", name, st, err)
		}
		names = append(names, name)
	}
	return names
}

func seedAuthorityAppleDoubleFiles(t *testing.T, authority string, n int) []string {
	t.Helper()
	cli, err := fsproto.Dial(authority, 8)
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	names := make([]string, 0, 2*n+2)
	for i := 0; i < n; i++ {
		for _, name := range []string{fmt.Sprintf("file%04d.txt", i), fmt.Sprintf("._file%04d.txt", i)} {
			if _, st, err := cli.Create(name, 0o644); err != nil || st != fsproto.OK {
				t.Fatalf("seed create %s: st=%d err=%v", name, st, err)
			}
			names = append(names, name)
		}
	}
	for _, name := range []string{".localized", "README.md"} {
		if _, st, err := cli.Create(name, 0o644); err != nil || st != fsproto.OK {
			t.Fatalf("seed create %s: st=%d err=%v", name, st, err)
		}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func appendEnumeratePage(t *testing.T, c *pfsTestClient, root pfslocal.Item, cookie uint64, max uint32, names *[]string, seen map[string]bool) uint64 {
	t.Helper()
	return appendEnumeratePageMode(t, c, root, cookie, max, true, names, seen)
}

func appendEnumeratePageMode(t *testing.T, c *pfsTestClient, root pfslocal.Item, cookie uint64, max uint32, wantAttrs bool, names *[]string, seen map[string]bool) uint64 {
	t.Helper()
	page := c.call(&pfslocal.EnumerateRequest{Dir: root, Cookie: cookie, MaxEntries: max, WantAttrs: wantAttrs}).(*pfslocal.EnumerateReply)
	for _, e := range page.Entries {
		name := string(e.Name)
		if seen[name] {
			t.Fatalf("duplicate enumerate entry %q after cookie %d", name, cookie)
		}
		seen[name] = true
		*names = append(*names, name)
	}
	if page.NextCookie != 0 && page.NextCookie&enumerateCookieMarker == 0 {
		t.Fatalf("next cookie %#x is not in the high-bit portablefsd namespace", page.NextCookie)
	}
	if page.NextCookie != 0 && page.NextCookie&enumerateCookieReservedMask != 0 {
		t.Fatalf("next cookie %#x low bits are not reserved zero", page.NextCookie)
	}
	return page.NextCookie
}

func assertExactNames(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		n := len(got)
		if n > 10 {
			n = 10
		}
		t.Fatalf("names len=%d want=%d first got=%v", len(got), len(want), got[:n])
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("names[%d]=%q want %q", i, got[i], want[i])
		}
	}
}

func enumerateAllPFS(t *testing.T, c *pfsTestClient, root pfslocal.Item, max uint32) []string {
	t.Helper()
	return enumerateAllPFSMode(t, c, root, max, true)
}

func enumerateAllPFSMode(t *testing.T, c *pfsTestClient, root pfslocal.Item, max uint32, wantAttrs bool) []string {
	t.Helper()
	var names []string
	seen := map[string]bool{}
	var cookie uint64
	for {
		cookie = appendEnumeratePageMode(t, c, root, cookie, max, wantAttrs, &names, seen)
		if cookie == 0 {
			return names
		}
	}
}

func TestEnumerationCookieEncodingOpaqueHighBitOnly(t *testing.T) {
	cases := []struct {
		enumID uint64
		pos    int
	}{
		{1, 1},
		{42, 256},
		{enumerateCookieMaxID, int(enumerateCookieMaxPos)},
	}
	for _, tc := range cases {
		cookie, ok := encodeEnumerationCookie(tc.enumID, tc.pos)
		if !ok {
			t.Fatalf("encodeEnumerationCookie(%d, %d) failed", tc.enumID, tc.pos)
		}
		if cookie&enumerateCookieMarker == 0 {
			t.Fatalf("encoded cookie %#x is not high-bit-set", cookie)
		}
		if cookie&enumerateCookieReservedMask != 0 {
			t.Fatalf("encoded cookie %#x has nonzero reserved bits", cookie)
		}
		enumID, pos, ok := decodeEnumerationCookie(cookie)
		if !ok || enumID != tc.enumID || pos != tc.pos {
			t.Fatalf("decodeEnumerationCookie(%#x)=(%d,%d,%v), want (%d,%d,true)", cookie, enumID, pos, ok, tc.enumID, tc.pos)
		}
		for _, bad := range []uint64{cookie | 1, cookie | 2, cookie | 3} {
			if enumID, pos, ok := decodeEnumerationCookie(bad); ok {
				t.Fatalf("decodeEnumerationCookie(%#x)=(%d,%d,true), want stale", bad, enumID, pos)
			}
		}
	}
	for _, bad := range []uint64{1, 2, 3, ^uint64(0)} {
		if enumID, pos, ok := decodeEnumerationCookie(bad); ok {
			t.Fatalf("decodeEnumerationCookie(%#x)=(%d,%d,true), want stale", bad, enumID, pos)
		}
	}
	for _, tc := range []struct {
		enumID uint64
		pos    int
	}{
		{0, 1},
		{1, 0},
		{enumerateCookieMaxID + 1, 1},
		{1, int(enumerateCookieMaxPos) + 1},
	} {
		if cookie, ok := encodeEnumerationCookie(tc.enumID, tc.pos); ok {
			t.Fatalf("encodeEnumerationCookie(%d, %d)=(%#x,true), want false", tc.enumID, tc.pos, cookie)
		}
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

func TestDaemonControlAndFrontendEndToEnd(t *testing.T) {
	authority := serveAuthority(t)
	cfg, hc, ref, cancel := startDaemon(t, authority)
	defer cancel()

	req, _ := http.NewRequest(http.MethodGet, "http://portablefsd/healthz", nil)
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("healthz status=%d", resp.StatusCode)
	}
	req, _ = http.NewRequest(http.MethodGet, "http://portablefsd/v1/identity", nil)
	resp, err = hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var identity struct {
		SchemaVersion    int    `json:"schemaVersion"`
		ControlProtocol  int    `json:"controlProtocol"`
		DaemonVersion    string `json:"daemonVersion"`
		ExecutableSHA256 string `json:"executableSha256"`
		PFSLocalMajor    uint32 `json:"pfslocalMajor"`
		PFSLocalMinor    uint32 `json:"pfslocalMinor"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&identity); err != nil {
		_ = resp.Body.Close()
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK ||
		identity.SchemaVersion != 1 ||
		identity.ControlProtocol != 1 ||
		identity.DaemonVersion != "portablefsd-test" ||
		len(identity.ExecutableSHA256) != 64 ||
		identity.PFSLocalMajor != pfslocal.ProtocolMajor ||
		identity.PFSLocalMinor != pfslocal.ProtocolMinor {
		t.Fatalf("identity status=%d body=%+v", resp.StatusCode, identity)
	}
	req, _ = http.NewRequest(http.MethodGet, "http://portablefsd/v1/attaches", nil)
	resp, err = rawHTTPUDSClient(cfg.ControlSocket).Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUpgradeRequired {
		t.Fatalf("headerless control request status=%d, want 426", resp.StatusCode)
	}

	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	c.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "go-test"})
	res := c.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply)
	root := res.Root
	// Xattrs is a per-attach capability: this authority (workfs) advertises
	// native xattrs, so the resolve reply must reflect that support.
	if res.RootAttr.Kind != pfslocal.ItemKindDirectory || !res.Capabilities.Symlinks || !res.Capabilities.HardLinks || !res.Capabilities.Xattrs {
		t.Fatalf("resolve = %+v", res)
	}

	cr := c.call(&pfslocal.CreateRequest{Dir: root, Name: []byte("a.txt"), Mode: 0o644, Exclusive: true}).(*pfslocal.CreateReply)
	if cr.Handle == 0 {
		t.Fatalf("create handle is zero")
	}
	wr := c.call(&pfslocal.WriteRequest{Handle: cr.Handle, Data: []byte("hello world")}).(*pfslocal.WriteReply)
	if wr.Written != 11 {
		t.Fatalf("write=%d", wr.Written)
	}
	rr := c.call(&pfslocal.ReadRequest{Handle: cr.Handle, Length: 32}).(*pfslocal.ReadReply)
	if string(rr.Data) != "hello world" {
		t.Fatalf("read=%q", rr.Data)
	}
	c.call(&pfslocal.FsyncRequest{Handle: cr.Handle})
	c.call(&pfslocal.CloseRequest{Handle: cr.Handle})

	c.call(&pfslocal.MkdirRequest{Dir: root, Name: []byte("dir"), Mode: 0o755})
	c.call(&pfslocal.SymlinkRequest{Dir: root, Name: []byte("link"), Target: []byte("a.txt")})
	var names []string
	page := c.call(&pfslocal.EnumerateRequest{Dir: root, MaxEntries: 1, WantAttrs: true}).(*pfslocal.EnumerateReply)
	if len(page.Entries) != 1 || page.NextCookie == 0 {
		t.Fatalf("first enumerate page = %+v", page)
	}
	names = append(names, string(page.Entries[0].Name))
	for page.NextCookie != 0 {
		page = c.call(&pfslocal.EnumerateRequest{Dir: root, Cookie: page.NextCookie, MaxEntries: 1, WantAttrs: true}).(*pfslocal.EnumerateReply)
		if len(page.Entries) > 0 {
			names = append(names, string(page.Entries[0].Name))
		}
	}
	sort.Strings(names)
	if got := stringsJoin(names); got != "a.txt,dir,link" {
		t.Fatalf("enumerate names=%s", got)
	}

	c.call(&pfslocal.RenameRequest{FromDir: root, FromName: []byte("a.txt"), ToDir: root, ToName: []byte("b.txt")})
	b := c.call(&pfslocal.LookupRequest{Dir: root, Name: []byte("b.txt")}).(*pfslocal.LookupReply)
	target := c.call(&pfslocal.ReadlinkRequest{Item: c.call(&pfslocal.LookupRequest{Dir: root, Name: []byte("link")}).(*pfslocal.LookupReply).Attr.Item}).(*pfslocal.ReadlinkReply)
	if string(target.Target) != "a.txt" || b.Attr.Kind != pfslocal.ItemKindFile {
		t.Fatalf("rename/readlink target=%q b=%+v", target.Target, b)
	}
	c.call(&pfslocal.StatfsRequest{})
	hard := c.call(&pfslocal.HardLinkRequest{Item: b.Attr.Item, Dir: root, Name: []byte("hard")}).(*pfslocal.HardLinkReply)
	if hard.Attr.Item != b.Attr.Item || hard.Attr.Nlink != 2 {
		t.Fatalf("hardlink reply=%+v source=%+v", hard, b.Attr)
	}
	if linked := c.call(&pfslocal.LookupRequest{Dir: root, Name: []byte("hard")}).(*pfslocal.LookupReply); linked.Attr.Item != b.Attr.Item || linked.Attr.Nlink != 2 {
		t.Fatalf("hardlink lookup=%+v source=%+v", linked, b.Attr)
	}

	// Native xattrs through the pfslocal surface: set/get/list survive the
	// daemon round trip; FSKit's mustCreate/mustReplace policies enforce;
	// a removed or never-set name answers Darwin ENOATTR (93).
	if lr := c.call(&pfslocal.XattrListRequest{Item: b.Attr.Item}).(*pfslocal.XattrListReply); len(lr.Names) != 0 {
		t.Fatalf("fresh file lists xattrs: %v", lr.Names)
	}
	c.call(&pfslocal.XattrSetRequest{Item: b.Attr.Item, Name: "com.apple.quarantine", Value: []byte("0083;test")})
	c.call(&pfslocal.XattrSetRequest{Item: b.Attr.Item, Name: "user.tag", Value: []byte("v1")})
	if gr := c.call(&pfslocal.XattrGetRequest{Item: b.Attr.Item, Name: "com.apple.quarantine"}).(*pfslocal.XattrGetReply); string(gr.Value) != "0083;test" {
		t.Fatalf("xattr get=%q", gr.Value)
	}
	if lr := c.call(&pfslocal.XattrListRequest{Item: b.Attr.Item}).(*pfslocal.XattrListReply); stringsJoin(lr.Names) != "com.apple.quarantine,user.tag" {
		t.Fatalf("xattr list=%v", lr.Names)
	}
	if er := c.callErr(&pfslocal.XattrSetRequest{Item: b.Attr.Item, Name: "user.tag", Value: []byte("v2"), CreateOnly: true}); er.Errno != darwinEEXIST {
		t.Fatalf("mustCreate over existing errno=%d", er.Errno)
	}
	if er := c.callErr(&pfslocal.XattrSetRequest{Item: b.Attr.Item, Name: "user.absent", Value: []byte("v"), ReplaceOnly: true}); er.Errno != darwinENOATTR {
		t.Fatalf("mustReplace of missing errno=%d", er.Errno)
	}
	c.call(&pfslocal.XattrRemoveRequest{Item: b.Attr.Item, Name: "user.tag"})
	if er := c.callErr(&pfslocal.XattrGetRequest{Item: b.Attr.Item, Name: "user.tag"}); er.Errno != darwinENOATTR {
		t.Fatalf("removed xattr get errno=%d", er.Errno)
	}
	if er := c.callErr(&pfslocal.XattrRemoveRequest{Item: b.Attr.Item, Name: "user.tag"}); er.Errno != darwinENOATTR {
		t.Fatalf("double remove errno=%d", er.Errno)
	}

	tmp := c.call(&pfslocal.CreateRequest{Dir: root, Name: []byte("tmp"), Mode: 0o644, Exclusive: true}).(*pfslocal.CreateReply)
	c.call(&pfslocal.WriteRequest{Handle: tmp.Handle, Data: []byte("still-open")})
	c.call(&pfslocal.RemoveRequest{Dir: root, Name: []byte("tmp")})
	afterUnlink := c.call(&pfslocal.ReadRequest{Handle: tmp.Handle, Length: 32}).(*pfslocal.ReadReply)
	if string(afterUnlink.Data) != "still-open" {
		t.Fatalf("open-after-unlink read=%q", afterUnlink.Data)
	}
	c.call(&pfslocal.WriteRequest{
		Handle: tmp.Handle, Offset: uint64(len("still-open")), Data: []byte("-updated"),
	})
	c.call(&pfslocal.FsyncRequest{Handle: tmp.Handle})
	if er := c.callErr(&pfslocal.LookupRequest{Dir: root, Name: []byte("tmp")}); er.Errno != darwinENOENT {
		t.Fatalf("write through unlinked handle resurrected path: errno=%d", er.Errno)
	}
	afterUnlinkedWrite := c.call(&pfslocal.ReadRequest{
		Handle: tmp.Handle, Length: 32,
	}).(*pfslocal.ReadReply)
	if string(afterUnlinkedWrite.Data) != "still-open-updated" {
		t.Fatalf("open-after-unlink write/read=%q", afterUnlinkedWrite.Data)
	}
	c.call(&pfslocal.CloseRequest{Handle: tmp.Handle})

	events := dialPFS(t, cfg.FrontendSocket)
	defer events.close()
	events.call(&pfslocal.Hello{ProtocolMajor: 1})
	events.call(&pfslocal.ResolveRequest{AttachRef: ref})
	events.call(&pfslocal.SubscribeEventsRequest{})
	time.Sleep(200 * time.Millisecond)
	remote, err := clientcore.Dial(context.Background(), clientcore.Options{Addr: authority, Pool: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	if _, st := remote.Create(context.Background(), "remote", 0o644); st != fsproto.OK {
		t.Fatalf("remote create st=%d", st)
	}
	waitEvent(t, events.conn)

	controlJSON(t, hc, http.MethodPost, "/v1/attaches/"+ref+"/credential", map[string]string{"authToken": "new-token"}, http.StatusNoContent, nil)
	controlJSON(t, hc, http.MethodPost, "/v1/attaches/"+ref+"/flush", nil, http.StatusNoContent, nil)
	var stat struct {
		Attr pfslocalAttr `json:"attr"`
	}
	controlJSON(t, hc, http.MethodPost, "/v1/attaches/"+ref+"/fs/stat", map[string]string{"path": "b.txt"}, http.StatusOK, &stat)
	if stat.Attr.Size == 0 {
		t.Fatalf("control stat = %+v", stat)
	}
	var listOut struct {
		Attaches []attachStatus `json:"attaches"`
	}
	controlJSON(t, hc, http.MethodGet, "/v1/attaches", nil, http.StatusOK, &listOut)
	if len(listOut.Attaches) != 1 || listOut.Attaches[0].AttachRef != ref {
		t.Fatalf("control list = %+v", listOut)
	}
	var one attachStatus
	controlJSON(t, hc, http.MethodGet, "/v1/attaches/"+ref, nil, http.StatusOK, &one)
	if one.AttachRef != ref || one.State == "" {
		t.Fatalf("control get = %+v", one)
	}
	var fsList struct {
		Entries []struct {
			Name string `json:"name"`
		} `json:"entries"`
	}
	controlJSON(t, hc, http.MethodPost, "/v1/attaches/"+ref+"/fs/list", map[string]any{"path": "", "maxEntries": 100}, http.StatusOK, &fsList)
	if len(fsList.Entries) == 0 {
		t.Fatalf("control fs/list empty")
	}
	readReq, _ := http.NewRequest(http.MethodPost, "http://portablefsd/v1/attaches/"+ref+"/fs/read", bytes.NewReader([]byte(`{"path":"b.txt","offset":0,"length":5}`)))
	readReq.Header.Set("Content-Type", "application/json")
	readResp, err := hc.Do(readReq)
	if err != nil {
		t.Fatal(err)
	}
	readData, _ := io.ReadAll(readResp.Body)
	_ = readResp.Body.Close()
	if readResp.StatusCode != http.StatusOK || string(readData) != "hello" || readResp.Header.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("control fs/read status=%d content-type=%q body=%q", readResp.StatusCode, readResp.Header.Get("Content-Type"), readData)
	}
	var writeReq = map[string]string{"path": "control.txt", "dataBase64": base64.StdEncoding.EncodeToString([]byte("control"))}
	controlJSON(t, hc, http.MethodPost, "/v1/attaches/"+ref+"/fs/write", writeReq, http.StatusNoContent, nil)

	// Removing the registry's original path must not reap a multiply-linked
	// item. The surviving alias keeps the same FSKit item identity, content,
	// and an updated link count.
	openedHard := c.call(&pfslocal.OpenRequest{Item: hard.Attr.Item, Mode: pfslocal.OpenModeRead}).(*pfslocal.OpenReply)
	c.call(&pfslocal.RemoveRequest{Dir: root, Name: []byte("b.txt")})
	survivor := c.call(&pfslocal.LookupRequest{Dir: root, Name: []byte("hard")}).(*pfslocal.LookupReply)
	if survivor.Attr.Item != hard.Attr.Item || survivor.Attr.Nlink != 1 {
		t.Fatalf("hardlink survivor=%+v original=%+v", survivor, hard)
	}
	afterOriginalUnlink := c.call(&pfslocal.ReadRequest{Handle: openedHard.Handle, Length: 32}).(*pfslocal.ReadReply)
	if string(afterOriginalUnlink.Data) != "hello world" {
		t.Fatalf("hardlink open handle after original unlink=%q", afterOriginalUnlink.Data)
	}
	c.call(&pfslocal.CloseRequest{Handle: openedHard.Handle})

	controlJSON(t, hc, http.MethodPost, "/v1/attaches/"+ref+"/unmount", nil, http.StatusNoContent, nil)
	_ = c.conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	if err := pfslocal.WriteFrame(c.conn, &pfslocal.Envelope{RequestID: 999, Body: &pfslocal.StatfsRequest{}}); err == nil {
		if env, rerr := pfslocal.ReadFrame(c.conn); rerr == nil {
			if er, ok := env.Body.(*pfslocal.ErrorReply); !ok || er.Errno != darwinENXIO {
				t.Fatalf("post-detach reply=%#v err=%v", env.Body, rerr)
			}
		}
	}
}

func TestFrontendSignalsOnlyPublicationRepliesAndKeepsConnectionOpen(t *testing.T) {
	authority := serveAuthority(t)
	cfg, _, ref, cancel := startDaemon(t, authority)
	defer cancel()

	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	c.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "ack-contract-test"})
	resolve := c.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply)
	created := c.call(&pfslocal.CreateRequest{
		Dir:       resolve.Root,
		Name:      []byte("ack-contract"),
		Mode:      0o644,
		Exclusive: true,
	}).(*pfslocal.CreateReply)
	c.call(&pfslocal.CloseRequest{Handle: created.Handle})

	request := func(body any) *pfslocal.Envelope {
		t.Helper()
		c.next++
		operationID := testOperationID(body, c.next)
		if err := pfslocal.WriteFrame(c.conn, &pfslocal.Envelope{
			RequestID:   c.next,
			OperationID: operationID,
			Body:        body,
		}); err != nil {
			t.Fatal(err)
		}
		return readPFSReply(t, c.conn, c.next)
	}

	open := request(&pfslocal.OpenRequest{Item: created.Attr.Item, Mode: pfslocal.OpenModeRead})
	if open.PublicationAckRequired {
		t.Fatal("open reply unexpectedly requires publication acknowledgement")
	}
	handle := open.Body.(*pfslocal.OpenReply).Handle

	statfs := request(&pfslocal.StatfsRequest{})
	if statfs.PublicationAckRequired {
		t.Fatal("statfs reply unexpectedly requires publication acknowledgement")
	}

	getattr := request(&pfslocal.GetAttrRequest{Item: created.Attr.Item})
	if !getattr.PublicationAckRequired {
		t.Fatal("getattr reply did not require publication acknowledgement")
	}
	if err := pfslocal.WriteFrame(c.conn, &pfslocal.Envelope{
		Body: &pfslocal.PublicationAck{
			OperationID: getattr.RequestID,
		},
	}); err != nil {
		t.Fatal(err)
	}

	// A second non-publishing round trip proves that omitting acknowledgements
	// for Open and Statfs leaves the same production server connection usable.
	after := request(&pfslocal.StatfsRequest{})
	if _, ok := after.Body.(*pfslocal.StatfsReply); !ok {
		t.Fatalf("post-publication statfs reply = %T", after.Body)
	}
	c.call(&pfslocal.CloseRequest{Handle: handle})
}

func TestFrontendRejectsMalformedRequestAndPublicationSequences(t *testing.T) {
	cfg, _, ref, cancel := startDaemon(t, serveAuthority(t))
	defer cancel()

	t.Run("unknown publication acknowledgement", func(t *testing.T) {
		conn, err := net.Dial("unix", cfg.FrontendSocket)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := pfslocal.WriteFrame(conn, &pfslocal.Envelope{
			Body: &pfslocal.PublicationAck{OperationID: 1},
		}); err != nil {
			t.Fatal(err)
		}
		expectPFSConnectionClosed(t, conn)
	})

	t.Run("acknowledgement carries request id", func(t *testing.T) {
		conn, err := net.Dial("unix", cfg.FrontendSocket)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := pfslocal.WriteFrame(conn, &pfslocal.Envelope{
			RequestID: 1,
			Body:      &pfslocal.PublicationAck{OperationID: 1},
		}); err != nil {
			t.Fatal(err)
		}
		expectPFSConnectionClosed(t, conn)
	})

	t.Run("protocol minor 2", func(t *testing.T) {
		conn, err := net.Dial("unix", cfg.FrontendSocket)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		hello := &pfslocal.Envelope{
			RequestID: 1,
			Body: &pfslocal.Hello{
				ProtocolMajor: pfslocal.ProtocolMajor,
				ProtocolMinor: 2,
				ClientName:    "old-operation-contract-test",
			},
		}
		if err := pfslocal.WriteFrame(conn, hello); err != nil {
			t.Fatal(err)
		}
		reply := readPFSReply(t, conn, hello.RequestID)
		if protocolErr, ok := reply.Body.(*pfslocal.ErrorReply); !ok ||
			protocolErr.Errno != darwinEINVAL {
			t.Fatalf("minor-2 hello reply = %#v", reply.Body)
		}
		expectPFSConnectionClosed(t, conn)
	})

	t.Run("non-increasing request id", func(t *testing.T) {
		conn, err := net.Dial("unix", cfg.FrontendSocket)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		hello := &pfslocal.Envelope{
			RequestID: 2,
			Body: &pfslocal.Hello{
				ProtocolMajor: pfslocal.ProtocolMajor,
				ProtocolMinor: pfslocal.ProtocolMinor,
				ClientName:    "sequence-test",
			},
		}
		if err := pfslocal.WriteFrame(conn, hello); err != nil {
			t.Fatal(err)
		}
		_ = readPFSReply(t, conn, hello.RequestID)
		if err := pfslocal.WriteFrame(conn, hello); err != nil {
			t.Fatal(err)
		}
		expectPFSConnectionClosed(t, conn)
	})

	t.Run("resolve before hello", func(t *testing.T) {
		conn, err := net.Dial("unix", cfg.FrontendSocket)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := pfslocal.WriteFrame(conn, &pfslocal.Envelope{
			RequestID: 1,
			Body:      &pfslocal.ResolveRequest{AttachRef: "anything"},
		}); err != nil {
			t.Fatal(err)
		}
		expectPFSConnectionClosed(t, conn)
	})

	t.Run("attached request before resolve", func(t *testing.T) {
		conn, err := net.Dial("unix", cfg.FrontendSocket)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := pfslocal.WriteFrame(conn, &pfslocal.Envelope{
			RequestID: 1,
			Body: &pfslocal.Hello{
				ProtocolMajor: pfslocal.ProtocolMajor,
				ProtocolMinor: pfslocal.ProtocolMinor,
				ClientName:    "state-test",
			},
		}); err != nil {
			t.Fatal(err)
		}
		_ = readPFSReply(t, conn, 1)
		if err := pfslocal.WriteFrame(conn, &pfslocal.Envelope{
			RequestID: 2,
			Body:      &pfslocal.StatfsRequest{},
		}); err != nil {
			t.Fatal(err)
		}
		expectPFSConnectionClosed(t, conn)
	})

	t.Run("second resolve", func(t *testing.T) {
		conn, err := net.Dial("unix", cfg.FrontendSocket)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		if err := pfslocal.WriteFrame(conn, &pfslocal.Envelope{
			RequestID: 1,
			Body: &pfslocal.Hello{
				ProtocolMajor: pfslocal.ProtocolMajor,
				ProtocolMinor: pfslocal.ProtocolMinor,
				ClientName:    "state-test",
			},
		}); err != nil {
			t.Fatal(err)
		}
		_ = readPFSReply(t, conn, 1)
		resolve := &pfslocal.Envelope{
			RequestID: 2,
			Body:      &pfslocal.ResolveRequest{AttachRef: ref},
		}
		if err := pfslocal.WriteFrame(conn, resolve); err != nil {
			t.Fatal(err)
		}
		_ = readPFSReply(t, conn, 2)
		resolve.RequestID = 3
		if err := pfslocal.WriteFrame(conn, resolve); err != nil {
			t.Fatal(err)
		}
		expectPFSConnectionClosed(t, conn)
	})

	t.Run("fresh nonpublishing operation id", func(t *testing.T) {
		conn, err := net.Dial("unix", cfg.FrontendSocket)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		hello := &pfslocal.Envelope{
			RequestID: 1,
			Body: &pfslocal.Hello{
				ProtocolMajor: pfslocal.ProtocolMajor,
				ProtocolMinor: pfslocal.ProtocolMinor,
				ClientName:    "operation-sequence-test",
			},
		}
		if err := pfslocal.WriteFrame(conn, hello); err != nil {
			t.Fatal(err)
		}
		_ = readPFSReply(t, conn, hello.RequestID)
		resolve := &pfslocal.Envelope{
			RequestID: 2,
			Body:      &pfslocal.ResolveRequest{AttachRef: ref},
		}
		if err := pfslocal.WriteFrame(conn, resolve); err != nil {
			t.Fatal(err)
		}
		_ = readPFSReply(t, conn, resolve.RequestID)
		if err := pfslocal.WriteFrame(conn, &pfslocal.Envelope{
			RequestID:   3,
			OperationID: 1,
			Body:        &pfslocal.StatfsRequest{},
		}); err != nil {
			t.Fatal(err)
		}
		expectPFSConnectionClosed(t, conn)
	})

	t.Run("publishing request without operation id", func(t *testing.T) {
		conn, err := net.Dial("unix", cfg.FrontendSocket)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		hello := &pfslocal.Envelope{
			RequestID: 1,
			Body: &pfslocal.Hello{
				ProtocolMajor: pfslocal.ProtocolMajor,
				ProtocolMinor: pfslocal.ProtocolMinor,
				ClientName:    "missing-operation-id-test",
			},
		}
		if err := pfslocal.WriteFrame(conn, hello); err != nil {
			t.Fatal(err)
		}
		_ = readPFSReply(t, conn, hello.RequestID)
		resolve := &pfslocal.Envelope{
			RequestID: 2,
			Body:      &pfslocal.ResolveRequest{AttachRef: ref},
		}
		if err := pfslocal.WriteFrame(conn, resolve); err != nil {
			t.Fatal(err)
		}
		root := readPFSReply(t, conn, resolve.RequestID).Body.(*pfslocal.ResolveReply).Root
		if err := pfslocal.WriteFrame(conn, &pfslocal.Envelope{
			RequestID: 3,
			Body:      &pfslocal.GetAttrRequest{Item: root},
		}); err != nil {
			t.Fatal(err)
		}
		expectPFSConnectionClosed(t, conn)
	})
}

func TestStopIfIdleAtomicallyRefusesBusyDaemon(t *testing.T) {
	authority := serveAuthority(t)
	cfg, hc, _, cancel := startDaemon(t, authority)
	defer cancel()

	req, _ := http.NewRequest(http.MethodPost, "http://portablefsd/v1/lifecycle/stop-if-idle", nil)
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Fatalf("busy stop status=%d, want 409", resp.StatusCode)
	}
	if _, err := os.Stat(cfg.ControlSocket); err != nil {
		t.Fatalf("busy stop changed the live daemon: %v", err)
	}
}

func TestStopIfIdleExitsDaemonWithNoAttaches(t *testing.T) {
	cfg, hc, cancel := startDaemonNoAttach(t, "")
	defer cancel()

	req, _ := http.NewRequest(http.MethodPost, "http://portablefsd/v1/lifecycle/stop-if-idle", nil)
	resp, err := hc.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("idle stop status=%d, want 204", resp.StatusCode)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Lstat(cfg.ControlSocket); os.IsNotExist(err) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("idle daemon did not remove %s after accepting stop", cfg.ControlSocket)
}

func TestStopIfIdleAllowsOnlyDormantRestartMetadata(t *testing.T) {
	stateDir := privateTestDir(t)
	r := newRegistry(stateDir)
	req := ensureAttachRequest{
		VolumeID:           "vol-dormant",
		Branch:             "main",
		AuthorityURL:       "127.0.0.1:1",
		DataPlaneTransport: "plaintext",
		MountPath:          "/Volumes/Dormant",
	}
	key := attachKey(req.VolumeID, req.Branch, req.MountPath)
	a, err := newRevivedAttach("att_DDDDDDDDDDDDDDDDDDDDDD", key, req, stateDir, 1, false, false, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	a.persist = r.persist
	a.schedulePersist = r.schedulePersist
	a.journal = r.journal
	r.byRef[a.ref] = a
	r.byKey[a.key] = a

	idle, count, err := r.quiesceIfIdle()
	if err != nil {
		t.Fatal(err)
	}
	if !idle || count != 0 {
		t.Fatalf("quiesceIfIdle() = (%v, %d), want (true, 0) for metadata-only revived attach", idle, count)
	}
	if len(r.byRef) != 1 {
		t.Fatal("idle proof must preserve dormant restart metadata on disk")
	}
	if err := r.closeAll(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestDaemonFrontendLookupSeesControlWriteAfterNegative(t *testing.T) {
	authority := serveAuthority(t)
	cfg, hc, ref, cancel := startDaemon(t, authority)
	defer cancel()

	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	c.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "negative-control-write"})
	res := c.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply)
	if er := c.callErr(&pfslocal.LookupRequest{Dir: res.Root, Name: []byte("ext.txt")}); er.Errno != darwinENOENT {
		t.Fatalf("initial lookup errno=%d want ENOENT", er.Errno)
	}

	writeControlFile(t, hc, ref, "ext.txt", "created outside frontend")
	lr := c.call(&pfslocal.LookupRequest{Dir: res.Root, Name: []byte("ext.txt")}).(*pfslocal.LookupReply)
	if lr.Attr.Kind != pfslocal.ItemKindFile {
		t.Fatalf("post-control lookup attr=%+v, want file", lr.Attr)
	}
	op := c.call(&pfslocal.OpenRequest{Item: lr.Attr.Item, Mode: pfslocal.OpenModeRead}).(*pfslocal.OpenReply)
	got := c.call(&pfslocal.ReadRequest{Handle: op.Handle, Length: 64}).(*pfslocal.ReadReply)
	if string(got.Data) != "created outside frontend" {
		t.Fatalf("post-control read=%q", got.Data)
	}
}

func TestDaemonWritebackRenameOverServesNewContentImmediately(t *testing.T) {
	authority := serveAuthority(t)
	cfg, hc, _, cancel := startDaemon(t, authority)
	defer cancel()
	opts := map[string]any{"flushIntervalMs": int64(time.Hour / time.Millisecond)}
	ref := ensureAttachWithPolicyOptions(t, hc, authority, "vol-rename-over", "main", "/Volumes/RenameOver", "writeback", opts)

	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	c.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "rename-over-immediate"})
	res := c.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply)
	root := res.Root

	for i := 0; i < 100; i++ {
		configName := fmt.Sprintf("config-%03d", i)
		lockName := configName + ".lock"
		oldContent := []byte(fmt.Sprintf("[old]\n\tvalue = %03d\n", i))
		newContent := []byte(fmt.Sprintf("[core]\n\trepositoryformatversion = %03d\n", i))

		config := c.call(&pfslocal.CreateRequest{Dir: root, Name: []byte(configName), Mode: 0o644, Exclusive: true}).(*pfslocal.CreateReply)
		c.call(&pfslocal.WriteRequest{Handle: config.Handle, Data: oldContent})
		c.call(&pfslocal.CloseRequest{Handle: config.Handle})

		lock := c.call(&pfslocal.CreateRequest{Dir: root, Name: []byte(lockName), Mode: 0o644, Exclusive: true}).(*pfslocal.CreateReply)
		c.call(&pfslocal.WriteRequest{Handle: lock.Handle, Data: newContent})
		c.call(&pfslocal.RenameRequest{FromDir: root, FromName: []byte(lockName), ToDir: root, ToName: []byte(configName)})

		if er := c.callErr(&pfslocal.GetAttrRequest{Item: config.Attr.Item}); er.Errno != darwinENOENT {
			t.Fatalf("iter %d overwritten target getattr errno=%d want ENOENT", i, er.Errno)
		}

		gotOpenHandle := c.call(&pfslocal.ReadRequest{Handle: lock.Handle, Length: uint32(len(newContent) + 16)}).(*pfslocal.ReadReply)
		if !bytes.Equal(gotOpenHandle.Data, newContent) {
			t.Fatalf("iter %d source handle read after rename=%q want %q", i, gotOpenHandle.Data, newContent)
		}

		byItem := c.call(&pfslocal.OpenRequest{Item: lock.Attr.Item, Mode: pfslocal.OpenModeRead}).(*pfslocal.OpenReply)
		gotByItem := c.call(&pfslocal.ReadRequest{Handle: byItem.Handle, Length: uint32(len(newContent) + 16)}).(*pfslocal.ReadReply)
		c.call(&pfslocal.CloseRequest{Handle: byItem.Handle})
		if !bytes.Equal(gotByItem.Data, newContent) {
			t.Fatalf("iter %d renamed item read=%q want %q", i, gotByItem.Data, newContent)
		}

		lookup := c.call(&pfslocal.LookupRequest{Dir: root, Name: []byte(configName)}).(*pfslocal.LookupReply)
		if lookup.Attr.Item != lock.Attr.Item {
			t.Fatalf("iter %d lookup item=%+v want renamed item %+v", i, lookup.Attr.Item, lock.Attr.Item)
		}
		byPath := c.call(&pfslocal.OpenRequest{Item: lookup.Attr.Item, Mode: pfslocal.OpenModeRead}).(*pfslocal.OpenReply)
		gotByPath := c.call(&pfslocal.ReadRequest{Handle: byPath.Handle, Length: uint32(len(newContent) + 16)}).(*pfslocal.ReadReply)
		c.call(&pfslocal.CloseRequest{Handle: byPath.Handle})
		if !bytes.Equal(gotByPath.Data, newContent) {
			t.Fatalf("iter %d lookup config read=%q want %q", i, gotByPath.Data, newContent)
		}
		c.call(&pfslocal.CloseRequest{Handle: lock.Handle})
	}
	controlJSON(t, hc, http.MethodPost, "/v1/attaches/"+ref+"/unmount", nil, http.StatusNoContent, nil)
}

func TestWriteThroughRenameOverTargetHandlePreservesReplacementBinding(t *testing.T) {
	authority := serveAuthority(t)
	cfg, hc, _, cancel := startDaemon(t, authority)
	defer cancel()
	ref := ensureAttach(t, hc, authority, "vol-rename-over-open-target", "main", "/Volumes/RenameOverOpenTarget")

	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	c.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "rename-over-open-target"})
	root := c.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply).Root

	target := c.call(&pfslocal.CreateRequest{
		Dir: root, Name: []byte("target"), Mode: 0o644, Exclusive: true,
	}).(*pfslocal.CreateReply)
	c.call(&pfslocal.WriteRequest{Handle: target.Handle, Data: []byte("old-target")})

	replacement := c.call(&pfslocal.CreateRequest{
		Dir: root, Name: []byte("replacement"), Mode: 0o644, Exclusive: true,
	}).(*pfslocal.CreateReply)
	c.call(&pfslocal.WriteRequest{Handle: replacement.Handle, Data: []byte("new-target")})
	c.call(&pfslocal.CloseRequest{Handle: replacement.Handle})
	c.call(&pfslocal.RenameRequest{
		FromDir: root, FromName: []byte("replacement"),
		ToDir: root, ToName: []byte("target"),
	})

	// The old target is detached but its descriptor remains a valid inode
	// reference. Mutating it must never rebind its stale "target" pathname.
	detachedAttr := c.call(&pfslocal.GetAttrRequest{
		Item: target.Attr.Item, Handle: target.Handle,
	}).(*pfslocal.GetAttrReply)
	if detachedAttr.Attr.Nlink != 0 {
		t.Fatalf("last-link detached target nlink=%d want 0", detachedAttr.Attr.Nlink)
	}
	truncatedSize := uint64(3)
	truncated := c.call(&pfslocal.SetAttrRequest{
		Item: target.Attr.Item, Handle: target.Handle, Size: &truncatedSize,
	}).(*pfslocal.SetAttrReply)
	if truncated.Attr.Size != truncatedSize || truncated.Attr.Nlink != 0 {
		t.Fatalf("detached truncate attr=%+v want size=3 nlink=0", truncated.Attr)
	}
	c.call(&pfslocal.WriteRequest{
		Handle: target.Handle, Offset: 0, Data: []byte("old-updated"),
	})
	c.call(&pfslocal.FsyncRequest{Handle: target.Handle})
	gotDetached := c.call(&pfslocal.ReadRequest{
		Handle: target.Handle, Length: 32,
	}).(*pfslocal.ReadReply)
	if string(gotDetached.Data) != "old-updated" {
		t.Fatalf("detached target bytes=%q want old-updated", gotDetached.Data)
	}

	lookup := c.call(&pfslocal.LookupRequest{
		Dir: root, Name: []byte("target"),
	}).(*pfslocal.LookupReply)
	if lookup.Attr.Item != replacement.Attr.Item || lookup.Attr.Item == target.Attr.Item {
		t.Fatalf("replacement binding changed after detached write: old=%+v replacement=%+v got=%+v",
			target.Attr.Item, replacement.Attr.Item, lookup.Attr.Item)
	}
	opened := c.call(&pfslocal.OpenRequest{
		Item: lookup.Attr.Item, Mode: pfslocal.OpenModeRead,
	}).(*pfslocal.OpenReply)
	gotReplacement := c.call(&pfslocal.ReadRequest{
		Handle: opened.Handle, Length: 32,
	}).(*pfslocal.ReadReply)
	if string(gotReplacement.Data) != "new-target" {
		t.Fatalf("replacement bytes after detached write=%q want new-target", gotReplacement.Data)
	}
	c.call(&pfslocal.CloseRequest{Handle: opened.Handle})
	if er := c.callErr(&pfslocal.ReclaimRequest{Item: target.Attr.Item}); er.Errno != darwinEBUSY {
		t.Fatalf("reclaim of open detached item errno=%d want EBUSY", er.Errno)
	}
	c.call(&pfslocal.CloseRequest{Handle: target.Handle})
	if er := c.callErr(&pfslocal.GetAttrRequest{
		Item: target.Attr.Item, Handle: target.Handle,
	}); er.Errno != darwinENOENT {
		t.Fatalf("closed detached handle getattr errno=%d want ENOENT", er.Errno)
	}
	c.call(&pfslocal.ReclaimRequest{Item: target.Attr.Item})
}

func TestDetachedHandleWithUnseenHardlinkUsesExactInode(t *testing.T) {
	authority := serveAuthority(t)
	cfg, hc, _, cancel := startDaemon(t, authority)
	defer cancel()
	ref := ensureAttach(t, hc, authority, "vol-detached-unseen-hardlink", "main", "/Volumes/DetachedUnseenHardlink")

	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	c.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "detached-unseen-hardlink"})
	root := c.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply).Root

	target := c.call(&pfslocal.CreateRequest{
		Dir: root, Name: []byte("target"), Mode: 0o644, Exclusive: true,
	}).(*pfslocal.CreateReply)
	c.call(&pfslocal.WriteRequest{Handle: target.Handle, Data: []byte("old-target")})
	c.call(&pfslocal.SyncVolumeRequest{})
	readOnlyTarget := c.call(&pfslocal.OpenRequest{
		Item: target.Attr.Item, Mode: pfslocal.OpenModeRead,
	}).(*pfslocal.OpenReply)

	peer, err := fsproto.Dial(authority, 4)
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	linked, st, err := peer.Link("target", "unseen-alias")
	if err != nil || st != fsproto.OK || linked == nil || linked.Nlink != 2 {
		t.Fatalf("peer unseen hardlink: attr=%+v st=%d err=%v", linked, st, err)
	}

	replacement := c.call(&pfslocal.CreateRequest{
		Dir: root, Name: []byte("replacement"), Mode: 0o644, Exclusive: true,
	}).(*pfslocal.CreateReply)
	c.call(&pfslocal.WriteRequest{Handle: replacement.Handle, Data: []byte("new-target")})
	c.call(&pfslocal.CloseRequest{Handle: replacement.Handle})
	c.call(&pfslocal.RenameRequest{
		FromDir: root, FromName: []byte("replacement"),
		ToDir: root, ToName: []byte("target"),
	})
	readOnlySize := uint64(1)
	if er := c.callErr(&pfslocal.SetAttrRequest{
		Item: target.Attr.Item, Handle: readOnlyTarget.Handle, Size: &readOnlySize,
	}); er.Errno != darwinEBADF {
		t.Fatalf("detached truncate through read-only handle errno=%d want EBADF", er.Errno)
	}
	readOnlyMode := uint32(0o640)
	readOnlyMtime := int64(111_222)
	readOnlyAttrs := c.call(&pfslocal.SetAttrRequest{
		Item: target.Attr.Item, Handle: readOnlyTarget.Handle,
		Mode: &readOnlyMode, MtimeMs: &readOnlyMtime,
	}).(*pfslocal.SetAttrReply).Attr
	if readOnlyAttrs.Mode != readOnlyMode || readOnlyAttrs.MtimeMs != readOnlyMtime ||
		readOnlyAttrs.Size != uint64(len("old-target")) || readOnlyAttrs.Nlink != 1 {
		t.Fatalf("detached metadata setattr through read-only handle=%+v", readOnlyAttrs)
	}

	mode := uint32(0o600)
	size := uint64(3)
	mtime := int64(123_456)
	atime := int64(234_567)
	attrs := c.call(&pfslocal.SetAttrRequest{
		Item: target.Attr.Item, Handle: target.Handle,
		Mode: &mode, Size: &size, MtimeMs: &mtime, AtimeMs: &atime,
	}).(*pfslocal.SetAttrReply).Attr
	if attrs.Size != size || attrs.Mode != mode || attrs.Nlink != 1 ||
		attrs.MtimeMs != mtime || attrs.AtimeMs != atime {
		t.Fatalf("detached exact setattr=%+v", attrs)
	}

	c.call(&pfslocal.XattrSetRequest{
		Item: target.Attr.Item, Handle: target.Handle,
		Name: "user.detached", Value: []byte("old-inode"),
	})
	if got := c.call(&pfslocal.XattrGetRequest{
		Item: target.Attr.Item, Handle: target.Handle, Name: "user.detached",
	}).(*pfslocal.XattrGetReply); string(got.Value) != "old-inode" {
		t.Fatalf("detached xattr=%q want old-inode", got.Value)
	}
	if names := c.call(&pfslocal.XattrListRequest{
		Item: target.Attr.Item, Handle: target.Handle,
	}).(*pfslocal.XattrListReply).Names; stringsJoin(names) != "user.detached" {
		t.Fatalf("detached xattr names=%v", names)
	}

	c.call(&pfslocal.WriteRequest{
		Handle: target.Handle, Offset: 3, Data: []byte("-fd"),
	})
	gotOld := c.call(&pfslocal.ReadRequest{
		Handle: target.Handle, Length: 32,
	}).(*pfslocal.ReadReply)
	if string(gotOld.Data) != "old-fd" {
		t.Fatalf("detached handle bytes=%q want old-fd", gotOld.Data)
	}

	aliasBytes, st, err := peer.Read("unseen-alias", 0, 32)
	if err != nil || st != fsproto.OK || string(aliasBytes) != "old-fd" {
		t.Fatalf("unseen alias bytes=%q st=%d err=%v", aliasBytes, st, err)
	}
	aliasAttr, st, err := peer.Getattr("unseen-alias")
	if err != nil || st != fsproto.OK || aliasAttr == nil ||
		aliasAttr.Mode != mode || aliasAttr.Nlink != 1 || aliasAttr.Size != 6 {
		t.Fatalf("unseen alias attrs=%+v st=%d err=%v", aliasAttr, st, err)
	}
	aliasXattr, st, err := peer.Getxattr("unseen-alias", 0, "user.detached")
	if err != nil || st != fsproto.OK || string(aliasXattr) != "old-inode" {
		t.Fatalf("unseen alias xattr=%q st=%d err=%v", aliasXattr, st, err)
	}

	lookup := c.call(&pfslocal.LookupRequest{
		Dir: root, Name: []byte("target"),
	}).(*pfslocal.LookupReply)
	if lookup.Attr.Item != replacement.Attr.Item || lookup.Attr.Item == target.Attr.Item {
		t.Fatalf("replacement binding old=%+v replacement=%+v got=%+v",
			target.Attr.Item, replacement.Attr.Item, lookup.Attr.Item)
	}
	replacementHandle := c.call(&pfslocal.OpenRequest{
		Item: lookup.Attr.Item, Mode: pfslocal.OpenModeRead,
	}).(*pfslocal.OpenReply)
	if er := c.callErr(&pfslocal.WriteRequest{
		Handle: replacementHandle.Handle, Data: []byte("forbidden"),
	}); er.Errno != darwinEBADF {
		t.Fatalf("write through read-only handle errno=%d want EBADF", er.Errno)
	}
	replacementBytes := c.call(&pfslocal.ReadRequest{
		Handle: replacementHandle.Handle, Length: 32,
	}).(*pfslocal.ReadReply)
	c.call(&pfslocal.CloseRequest{Handle: replacementHandle.Handle})
	if string(replacementBytes.Data) != "new-target" || lookup.Attr.Mode != 0o644 {
		t.Fatalf("replacement changed: bytes=%q attr=%+v", replacementBytes.Data, lookup.Attr)
	}
	if _, st, err := peer.Getxattr("target", 0, "user.detached"); err != nil || st != fsproto.ENODATA {
		t.Fatalf("replacement inherited detached xattr: st=%d err=%v", st, err)
	}

	c.call(&pfslocal.XattrRemoveRequest{
		Item: target.Attr.Item, Handle: target.Handle, Name: "user.detached",
	})
	c.call(&pfslocal.CloseRequest{Handle: readOnlyTarget.Handle})
	c.call(&pfslocal.CloseRequest{Handle: target.Handle})
	if er := c.callErr(&pfslocal.GetAttrRequest{
		Item: target.Attr.Item, Handle: target.Handle,
	}); er.Errno != darwinENOENT {
		t.Fatalf("post-close detached getattr errno=%d want ENOENT", er.Errno)
	}
}

func TestDaemonWritebackDoubleLockRenameDoesNotRecycleMovedItem(t *testing.T) {
	authority := serveAuthority(t)
	cfg, hc, _, cancel := startDaemon(t, authority)
	defer cancel()
	opts := map[string]any{"flushIntervalMs": int64(time.Hour / time.Millisecond)}
	ref := ensureAttachWithPolicyOptions(t, hc, authority, "vol-rename-recycle", "main", "/Volumes/RenameRecycle", "writeback", opts)

	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	c.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "rename-recycle"})
	res := c.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply)
	root := res.Root

	for i := 0; i < 100; i++ {
		configName := fmt.Sprintf("double-config-%03d", i)
		lockName := configName + ".lock"
		firstContent := []byte(fmt.Sprintf("[core]\n\tfirst = %03d\n", i))
		secondContent := []byte(fmt.Sprintf("[core]\n\tsecond = %03d\n", i))

		first := c.call(&pfslocal.CreateRequest{Dir: root, Name: []byte(lockName), Mode: 0o644, Exclusive: true}).(*pfslocal.CreateReply)
		c.call(&pfslocal.WriteRequest{Handle: first.Handle, Data: firstContent})
		c.call(&pfslocal.RenameRequest{FromDir: root, FromName: []byte(lockName), ToDir: root, ToName: []byte(configName)})
		c.call(&pfslocal.CloseRequest{Handle: first.Handle})

		lr := c.call(&pfslocal.LookupRequest{Dir: root, Name: []byte(configName)}).(*pfslocal.LookupReply)
		if lr.Attr.Item != first.Attr.Item {
			t.Fatalf("iter %d first config item=%+v want %+v", i, lr.Attr.Item, first.Attr.Item)
		}
		if er := c.callErr(&pfslocal.LookupRequest{Dir: root, Name: []byte(lockName)}); er.Errno != darwinENOENT {
			t.Fatalf("iter %d lock after first rename errno=%d want ENOENT", i, er.Errno)
		}

		second := c.call(&pfslocal.CreateRequest{Dir: root, Name: []byte(lockName), Mode: 0o644, Exclusive: true}).(*pfslocal.CreateReply)
		if second.Attr.Item == first.Attr.Item {
			t.Fatalf("iter %d recycled moved item %+v for recreated lock path", i, second.Attr.Item)
		}
		c.call(&pfslocal.WriteRequest{Handle: second.Handle, Data: secondContent})
		c.call(&pfslocal.RenameRequest{FromDir: root, FromName: []byte(lockName), ToDir: root, ToName: []byte(configName)})

		if er := c.callErr(&pfslocal.GetAttrRequest{Item: first.Attr.Item}); er.Errno != darwinENOENT {
			t.Fatalf("iter %d overwritten first item errno=%d want ENOENT", i, er.Errno)
		}
		gotOpenHandle := c.call(&pfslocal.ReadRequest{Handle: second.Handle, Length: uint32(len(secondContent) + 16)}).(*pfslocal.ReadReply)
		if !bytes.Equal(gotOpenHandle.Data, secondContent) {
			t.Fatalf("iter %d second handle read=%q want %q", i, gotOpenHandle.Data, secondContent)
		}

		lr = c.call(&pfslocal.LookupRequest{Dir: root, Name: []byte(configName)}).(*pfslocal.LookupReply)
		if lr.Attr.Item != second.Attr.Item {
			t.Fatalf("iter %d final config item=%+v want second item %+v", i, lr.Attr.Item, second.Attr.Item)
		}
		byItem := c.call(&pfslocal.OpenRequest{Item: lr.Attr.Item, Mode: pfslocal.OpenModeRead}).(*pfslocal.OpenReply)
		gotByItem := c.call(&pfslocal.ReadRequest{Handle: byItem.Handle, Length: uint32(len(secondContent) + 16)}).(*pfslocal.ReadReply)
		c.call(&pfslocal.CloseRequest{Handle: byItem.Handle})
		if !bytes.Equal(gotByItem.Data, secondContent) {
			t.Fatalf("iter %d final config read=%q want %q", i, gotByItem.Data, secondContent)
		}
		c.call(&pfslocal.CloseRequest{Handle: second.Handle})
		if er := c.callErr(&pfslocal.LookupRequest{Dir: root, Name: []byte(lockName)}); er.Errno != darwinENOENT {
			t.Fatalf("iter %d lock after second rename errno=%d want ENOENT", i, er.Errno)
		}
	}
	controlJSON(t, hc, http.MethodPost, "/v1/attaches/"+ref+"/unmount", nil, http.StatusNoContent, nil)
}

func TestDaemonRemoveTypeMismatchDoesNotDeleteDotGit(t *testing.T) {
	authority := serveAuthority(t)
	cfg, hc, _, cancel := startDaemon(t, authority)
	defer cancel()
	opts := map[string]any{"flushIntervalMs": int64(time.Hour / time.Millisecond)}
	ref := ensureAttachWithPolicyOptions(t, hc, authority, "vol-remove-type", "main", "/Volumes/RemoveType", "writeback", opts)

	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	c.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "remove-type"})
	res := c.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply)
	root := res.Root
	git := c.call(&pfslocal.MkdirRequest{Dir: root, Name: []byte(".git"), Mode: 0o755}).(*pfslocal.MkdirReply)
	head := c.call(&pfslocal.CreateRequest{Dir: git.Attr.Item, Name: []byte("HEAD"), Mode: 0o644, Exclusive: true}).(*pfslocal.CreateReply)
	c.call(&pfslocal.WriteRequest{Handle: head.Handle, Data: []byte("ref: refs/heads/main\n")})
	c.call(&pfslocal.CloseRequest{Handle: head.Handle})
	ad := c.call(&pfslocal.CreateRequest{Dir: root, Name: []byte("._.git"), Mode: 0o644, Exclusive: true}).(*pfslocal.CreateReply)
	c.call(&pfslocal.WriteRequest{Handle: ad.Handle, Data: []byte("appledouble")})
	c.call(&pfslocal.CloseRequest{Handle: ad.Handle})

	if er := c.callErr(&pfslocal.RemoveRequest{Dir: root, Name: []byte(".git"), Directory: false}); er.Errno != darwinEISDIR {
		t.Fatalf("unlink-style remove of .git errno=%d want EISDIR", er.Errno)
	}
	if lr := c.call(&pfslocal.LookupRequest{Dir: root, Name: []byte(".git")}).(*pfslocal.LookupReply); lr.Attr.Kind != pfslocal.ItemKindDirectory {
		t.Fatalf(".git after unlink-style remove = %+v, want directory", lr.Attr)
	}
	if lr := c.call(&pfslocal.LookupRequest{Dir: root, Name: []byte("._.git")}).(*pfslocal.LookupReply); lr.Attr.Kind != pfslocal.ItemKindFile {
		t.Fatalf("._.git after .git remove attempt = %+v, want file", lr.Attr)
	}
	if er := c.callErr(&pfslocal.RemoveRequest{Dir: root, Name: []byte(".git"), Directory: true}); er.Errno != darwinENOTEMPTY {
		t.Fatalf("rmdir .git errno=%d want ENOTEMPTY", er.Errno)
	}
	if lr := c.call(&pfslocal.LookupRequest{Dir: root, Name: []byte(".git")}).(*pfslocal.LookupReply); lr.Attr.Kind != pfslocal.ItemKindDirectory {
		t.Fatalf(".git after non-empty rmdir = %+v, want directory", lr.Attr)
	}

	controlJSON(t, hc, http.MethodPost, "/v1/attaches/"+ref+"/flush", nil, http.StatusNoContent, nil)
	var stat struct {
		Attr pfslocalAttr `json:"attr"`
	}
	controlJSON(t, hc, http.MethodPost, "/v1/attaches/"+ref+"/fs/stat", map[string]string{"path": ".git"}, http.StatusOK, &stat)
	if stat.Attr.Kind != "directory" {
		t.Fatalf("control stat .git = %+v, want directory", stat.Attr)
	}
	var fsList struct {
		Entries []struct {
			Name string `json:"name"`
		} `json:"entries"`
	}
	controlJSON(t, hc, http.MethodPost, "/v1/attaches/"+ref+"/fs/list", map[string]any{"path": "", "maxEntries": 100}, http.StatusOK, &fsList)
	names := map[string]bool{}
	for _, e := range fsList.Entries {
		names[e.Name] = true
	}
	if !names[".git"] || !names["._.git"] {
		t.Fatalf("root listing after failed removes = %+v, want .git and ._.git", fsList.Entries)
	}
	controlJSON(t, hc, http.MethodPost, "/v1/attaches/"+ref+"/unmount", nil, http.StatusNoContent, nil)
}

func TestDaemonWritebackGitStashLikeChurnKeepsDotGit(t *testing.T) {
	authority := serveAuthority(t)
	cfg, hc, _, cancel := startDaemon(t, authority)
	defer cancel()
	opts := map[string]any{"flushIntervalMs": int64((25 * time.Millisecond) / time.Millisecond)}
	ref := ensureAttachWithPolicyOptions(t, hc, authority, "vol-git-stash-churn", "main", "/Volumes/GitStashChurn", "writeback", opts)

	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	c.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "git-stash-churn"})
	res := c.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply)
	root := res.Root
	git := c.call(&pfslocal.MkdirRequest{Dir: root, Name: []byte(".git"), Mode: 0o755}).(*pfslocal.MkdirReply)
	refs := c.call(&pfslocal.MkdirRequest{Dir: git.Attr.Item, Name: []byte("refs"), Mode: 0o755}).(*pfslocal.MkdirReply)
	c.call(&pfslocal.MkdirRequest{Dir: refs.Attr.Item, Name: []byte("heads"), Mode: 0o755})
	head := c.call(&pfslocal.CreateRequest{Dir: git.Attr.Item, Name: []byte("HEAD"), Mode: 0o644, Exclusive: true}).(*pfslocal.CreateReply)
	c.call(&pfslocal.WriteRequest{Handle: head.Handle, Data: []byte("ref: refs/heads/main\n")})
	index := c.call(&pfslocal.CreateRequest{Dir: git.Attr.Item, Name: []byte("index"), Mode: 0o644, Exclusive: true}).(*pfslocal.CreateReply)
	c.call(&pfslocal.WriteRequest{Handle: index.Handle, Data: []byte("index-base")})
	c.call(&pfslocal.CloseRequest{Handle: index.Handle})
	stash := c.call(&pfslocal.CreateRequest{Dir: refs.Attr.Item, Name: []byte("stash"), Mode: 0o644, Exclusive: true}).(*pfslocal.CreateReply)
	c.call(&pfslocal.WriteRequest{Handle: stash.Handle, Data: []byte("stash-base")})
	c.call(&pfslocal.CloseRequest{Handle: stash.Handle})

	for i := 0; i < 100; i++ {
		idxLock := c.call(&pfslocal.CreateRequest{Dir: git.Attr.Item, Name: []byte("index.lock"), Mode: 0o644, Exclusive: true}).(*pfslocal.CreateReply)
		indexContent := []byte(fmt.Sprintf("index-%03d", i))
		c.call(&pfslocal.WriteRequest{Handle: idxLock.Handle, Data: indexContent})
		c.call(&pfslocal.RenameRequest{FromDir: git.Attr.Item, FromName: []byte("index.lock"), ToDir: git.Attr.Item, ToName: []byte("index")})
		gotIndex := c.call(&pfslocal.ReadRequest{Handle: idxLock.Handle, Length: uint32(len(indexContent) + 16)}).(*pfslocal.ReadReply)
		if !bytes.Equal(gotIndex.Data, indexContent) {
			t.Fatalf("iter %d index handle read=%q want %q", i, gotIndex.Data, indexContent)
		}
		c.call(&pfslocal.CloseRequest{Handle: idxLock.Handle})

		stashLock := c.call(&pfslocal.CreateRequest{Dir: refs.Attr.Item, Name: []byte("stash.lock"), Mode: 0o644, Exclusive: true}).(*pfslocal.CreateReply)
		stashContent := []byte(fmt.Sprintf("stash-%03d", i))
		c.call(&pfslocal.WriteRequest{Handle: stashLock.Handle, Data: stashContent})
		c.call(&pfslocal.RenameRequest{FromDir: refs.Attr.Item, FromName: []byte("stash.lock"), ToDir: refs.Attr.Item, ToName: []byte("stash")})
		c.call(&pfslocal.CloseRequest{Handle: stashLock.Handle})

		tmpName := fmt.Sprintf("tmp-%03d", i)
		tmp := c.call(&pfslocal.CreateRequest{Dir: git.Attr.Item, Name: []byte(tmpName), Mode: 0o644, Exclusive: true}).(*pfslocal.CreateReply)
		c.call(&pfslocal.CloseRequest{Handle: tmp.Handle})
		c.call(&pfslocal.RemoveRequest{Dir: git.Attr.Item, Name: []byte(tmpName), Directory: false})

		ad := c.call(&pfslocal.CreateRequest{Dir: root, Name: []byte("._.git"), Mode: 0o644, Exclusive: true}).(*pfslocal.CreateReply)
		c.call(&pfslocal.WriteRequest{Handle: ad.Handle, Data: []byte("appledouble")})
		c.call(&pfslocal.CloseRequest{Handle: ad.Handle})
		c.call(&pfslocal.RemoveRequest{Dir: root, Name: []byte("._.git"), Directory: false})

		if lr := c.call(&pfslocal.LookupRequest{Dir: root, Name: []byte(".git")}).(*pfslocal.LookupReply); lr.Attr.Kind != pfslocal.ItemKindDirectory {
			t.Fatalf("iter %d .git lookup = %+v, want directory", i, lr.Attr)
		}
		if er := c.callErr(&pfslocal.LookupRequest{Dir: root, Name: []byte("._.git")}); er.Errno != darwinENOENT {
			t.Fatalf("iter %d ._.git errno=%d want ENOENT after unlink", i, er.Errno)
		}
		time.Sleep(5 * time.Millisecond)
	}
	c.call(&pfslocal.CloseRequest{Handle: head.Handle})

	controlJSON(t, hc, http.MethodPost, "/v1/attaches/"+ref+"/flush", nil, http.StatusNoContent, nil)
	var stat struct {
		Attr pfslocalAttr `json:"attr"`
	}
	controlJSON(t, hc, http.MethodPost, "/v1/attaches/"+ref+"/fs/stat", map[string]string{"path": ".git"}, http.StatusOK, &stat)
	if stat.Attr.Kind != "directory" {
		t.Fatalf("control stat .git after churn = %+v, want directory", stat.Attr)
	}
	controlJSON(t, hc, http.MethodPost, "/v1/attaches/"+ref+"/unmount", nil, http.StatusNoContent, nil)
}

func TestDaemonRenameWaitsForInFlightLookupBeforeReply(t *testing.T) {
	authority := serveAuthority(t)
	dir, err := os.MkdirTemp("", "pfsd-rename-order-")
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
	defer cancel()
	srv := NewServer(cfg)
	runDone := make(chan error, 1)
	go func() {
		runDone <- srv.Run(ctx)
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
	hc := httpUDSClient(cfg.ControlSocket)
	opts := map[string]any{"flushIntervalMs": int64(time.Hour / time.Millisecond)}
	ref := ensureAttachWithPolicyOptions(t, hc, authority, "vol-rename-order", "main", "/Volumes/RenameOrder", "writeback", opts)
	a := srv.registry.get(ref)
	if a == nil {
		t.Fatal("attach missing after ensure")
	}

	setup := dialPFS(t, cfg.FrontendSocket)
	defer setup.close()
	setup.call(&pfslocal.Hello{ProtocolMajor: 1})
	res := setup.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply)
	// The rename must ride one write-back session's overlay (buffered, then
	// flushed): use a subdirectory so both names share the parent-dir session
	// (top-level names hold file-grain roots and rename write-through).
	cfgDir := setup.call(&pfslocal.MkdirRequest{Dir: res.Root, Name: []byte("cfg"), Mode: 0o755}).(*pfslocal.MkdirReply)
	root := cfgDir.Attr.Item
	lock := setup.call(&pfslocal.CreateRequest{Dir: root, Name: []byte("config.lock"), Mode: 0o644, Exclusive: true}).(*pfslocal.CreateReply)
	setup.call(&pfslocal.WriteRequest{Handle: lock.Handle, Data: []byte("[core]\n")})
	setup.call(&pfslocal.CloseRequest{Handle: lock.Handle})

	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	a.testLookupAfterVolume = func(p string) {
		if p != "cfg/config.lock" {
			return
		}
		once.Do(func() {
			close(entered)
			<-release
		})
	}
	defer func() { a.testLookupAfterVolume = nil }()

	lookupDone := make(chan pfslocal.Item, 1)
	go func() {
		c := dialPFS(t, cfg.FrontendSocket)
		defer c.close()
		c.call(&pfslocal.Hello{ProtocolMajor: 1})
		c.call(&pfslocal.ResolveRequest{AttachRef: ref})
		lr := c.call(&pfslocal.LookupRequest{Dir: root, Name: []byte("config.lock")}).(*pfslocal.LookupReply)
		lookupDone <- lr.Attr.Item
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("stale lookup did not enter hook")
	}

	renameDone := make(chan struct{})
	go func() {
		c := dialPFS(t, cfg.FrontendSocket)
		defer c.close()
		c.call(&pfslocal.Hello{ProtocolMajor: 1})
		c.call(&pfslocal.ResolveRequest{AttachRef: ref})
		c.call(&pfslocal.RenameRequest{FromDir: root, FromName: []byte("config.lock"), ToDir: root, ToName: []byte("config")})
		close(renameDone)
	}()
	select {
	case <-renameDone:
		t.Fatal("rename completed while an older name lookup was still in flight")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	select {
	case got := <-lookupDone:
		if got != lock.Attr.Item {
			t.Fatalf("stale lookup item=%+v want %+v", got, lock.Attr.Item)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("stale lookup did not complete after release")
	}
	select {
	case <-renameDone:
	case <-time.After(5 * time.Second):
		t.Fatal("rename did not complete after stale lookup drained")
	}

	if er := setup.callErr(&pfslocal.LookupRequest{Dir: root, Name: []byte("config.lock")}); er.Errno != darwinENOENT {
		t.Fatalf("post-rename config.lock errno=%d want ENOENT", er.Errno)
	}
	lr := setup.call(&pfslocal.LookupRequest{Dir: root, Name: []byte("config")}).(*pfslocal.LookupReply)
	if lr.Attr.Item != lock.Attr.Item {
		t.Fatalf("post-rename config item=%+v want %+v", lr.Attr.Item, lock.Attr.Item)
	}
	controlJSON(t, hc, http.MethodPost, "/v1/attaches/"+ref+"/unmount", nil, http.StatusNoContent, nil)
}

func TestDaemonWritebackRenameLookupsMonotonicDuringActiveFlush(t *testing.T) {
	authority, authSrv := serveAuthorityServer(t)
	var flushes atomic.Int64
	authSrv.SetBeforeFlushBatch(func() {
		flushes.Add(1)
		time.Sleep(25 * time.Millisecond)
	})

	cfg, hc, _, cancel := startDaemon(t, authority)
	defer cancel()
	opts := map[string]any{"flushIntervalMs": int64((100 * time.Millisecond) / time.Millisecond)}
	ref := ensureAttachWithPolicyOptions(t, hc, authority, "vol-rename-flush", "main", "/Volumes/RenameFlush", "writeback", opts)

	setup := dialPFS(t, cfg.FrontendSocket)
	defer setup.close()
	setup.call(&pfslocal.Hello{ProtocolMajor: 1})
	res := setup.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply)
	// The rename must ride one write-back session's overlay (buffered, then
	// flushed): use a subdirectory so both names share the parent-dir session
	// (top-level names hold file-grain roots and rename write-through).
	cfgDir := setup.call(&pfslocal.MkdirRequest{Dir: res.Root, Name: []byte("cfg"), Mode: 0o755}).(*pfslocal.MkdirReply)
	root := cfgDir.Attr.Item
	lock := setup.call(&pfslocal.CreateRequest{Dir: root, Name: []byte("config.lock"), Mode: 0o644, Exclusive: true}).(*pfslocal.CreateReply)
	setup.call(&pfslocal.WriteRequest{Handle: lock.Handle, Data: []byte("[core]\n")})

	ctx, stop := context.WithCancel(context.Background())
	defer stop()
	errCh := make(chan string, 1)
	report := func(format string, args ...any) {
		select {
		case errCh <- fmt.Sprintf(format, args...):
			stop()
		default:
		}
	}
	var anyConfigSeenOK atomic.Bool
	var anyLockSeenENOENT atomic.Bool
	var wg sync.WaitGroup
	lookupLoop := func(worker int) {
		defer wg.Done()
		c := dialPFS(t, cfg.FrontendSocket)
		defer c.close()
		c.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: fmt.Sprintf("rename-flush-%d", worker)})
		c.call(&pfslocal.ResolveRequest{AttachRef: ref})
		configSeenOK := false
		lockSeenENOENT := false
		for ctx.Err() == nil {
			body, er := c.callMaybe(&pfslocal.LookupRequest{Dir: root, Name: []byte("config")})
			if er != nil {
				if er.Errno != darwinENOENT {
					report("config lookup errno=%d want ENOENT or OK", er.Errno)
					return
				}
				if configSeenOK {
					report("config flapped OK -> ENOENT")
					return
				}
			} else {
				lr := body.(*pfslocal.LookupReply)
				if lr.Attr.Item != lock.Attr.Item {
					report("config item=%+v want renamed item %+v", lr.Attr.Item, lock.Attr.Item)
					return
				}
				configSeenOK = true
				anyConfigSeenOK.Store(true)
			}

			body, er = c.callMaybe(&pfslocal.LookupRequest{Dir: root, Name: []byte("config.lock")})
			if er != nil {
				if er.Errno != darwinENOENT {
					report("config.lock lookup errno=%d want ENOENT or OK", er.Errno)
					return
				}
				lockSeenENOENT = true
				anyLockSeenENOENT.Store(true)
			} else {
				lr := body.(*pfslocal.LookupReply)
				if lockSeenENOENT {
					report("config.lock flapped ENOENT -> OK")
					return
				}
				if lr.Attr.Item != lock.Attr.Item {
					report("config.lock item=%+v want lock item %+v", lr.Attr.Item, lock.Attr.Item)
					return
				}
			}
		}
	}
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go lookupLoop(i)
	}
	time.Sleep(100 * time.Millisecond)
	beforeFlushes := flushes.Load()
	setup.call(&pfslocal.RenameRequest{FromDir: root, FromName: []byte("config.lock"), ToDir: root, ToName: []byte("config")})
	deadline := time.After(3 * time.Second)
	select {
	case err := <-errCh:
		t.Fatal(err)
	case <-deadline:
	}
	stop()
	wg.Wait()
	select {
	case err := <-errCh:
		t.Fatal(err)
	default:
	}
	if !anyConfigSeenOK.Load() {
		t.Fatal("config never transitioned to OK")
	}
	if !anyLockSeenENOENT.Load() {
		t.Fatal("config.lock never transitioned to ENOENT")
	}
	if flushes.Load() <= beforeFlushes {
		t.Fatalf("no active flush observed after rename: before=%d after=%d", beforeFlushes, flushes.Load())
	}
	setup.call(&pfslocal.CloseRequest{Handle: lock.Handle})
	controlJSON(t, hc, http.MethodPost, "/v1/attaches/"+ref+"/unmount", nil, http.StatusNoContent, nil)
}

func TestDaemonPublishesInvalidationsForControlAndRemoteMutations(t *testing.T) {
	authority := serveAuthority(t)
	cfg, hc, ref, cancel := startDaemon(t, authority)
	defer cancel()

	ops := dialPFS(t, cfg.FrontendSocket)
	defer ops.close()
	ops.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "ops"})
	res := ops.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply)
	root := res.Root

	events := dialPFS(t, cfg.FrontendSocket)
	defer events.close()
	events.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "events"})
	events.call(&pfslocal.ResolveRequest{AttachRef: ref})
	events.call(&pfslocal.SubscribeEventsRequest{})

	frontendCreate := ops.call(&pfslocal.CreateRequest{Dir: root, Name: []byte("frontend-event.txt"), Mode: 0o644, Exclusive: true}).(*pfslocal.CreateReply)
	ops.call(&pfslocal.CloseRequest{Handle: frontendCreate.Handle})
	inv := waitInvalidation(t, events.conn, func(inv *pfslocal.Invalidation) bool {
		return inv.NamespaceChanged && inv.Item == root
	})
	if !inv.NamespaceChanged {
		t.Fatalf("frontend create invalidation = %+v", inv)
	}

	writeControlFile(t, hc, ref, "external-event.txt", "created")
	inv = waitInvalidation(t, events.conn, func(inv *pfslocal.Invalidation) bool {
		return inv.NamespaceChanged && inv.Item == root
	})
	if !inv.NamespaceChanged {
		t.Fatalf("control create invalidation = %+v", inv)
	}

	file := ops.call(&pfslocal.LookupRequest{Dir: root, Name: []byte("external-event.txt")}).(*pfslocal.LookupReply).Attr.Item
	writeControlFile(t, hc, ref, "external-event.txt", "updated-content")
	inv = waitInvalidation(t, events.conn, func(inv *pfslocal.Invalidation) bool {
		return inv.ContentChanged && inv.AttrsChanged && inv.Item == file
	})
	if !inv.ContentChanged || inv.Item != file {
		t.Fatalf("control update invalidation = %+v want item %+v", inv, file)
	}

	remote, err := clientcore.Dial(context.Background(), clientcore.Options{Addr: authority, Pool: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer remote.Close()
	if _, st := remote.Create(context.Background(), "remote-event.txt", 0o644); st != fsproto.OK {
		t.Fatalf("remote create st=%d", st)
	}
	inv = waitInvalidation(t, events.conn, func(inv *pfslocal.Invalidation) bool {
		return inv.NamespaceChanged && inv.Item == root
	})
	if !inv.NamespaceChanged {
		t.Fatalf("remote create invalidation = %+v", inv)
	}
}

func TestDaemonWritebackEnumerateReflectsOverlayBeforeFlush(t *testing.T) {
	authority, srv := serveAuthorityServer(t)
	blockFlush := make(chan struct{})
	srv.SetBeforeFlushBatch(func() { <-blockFlush })

	seed, err := clientcore.Dial(context.Background(), clientcore.Options{Addr: authority, Pool: 2})
	if err != nil {
		t.Fatal(err)
	}
	if _, st := seed.Create(context.Background(), "ghost.txt", 0o644); st != fsproto.OK {
		t.Fatalf("seed ghost: %d", st)
	}
	_ = seed.Close()

	cfg, hc, _, cancel := startDaemon(t, authority)
	defer cancel()
	defer close(blockFlush)
	// Keep the background flusher quiet: every file-grain session would
	// otherwise park a flush RPC on the blocked hook and starve the pool.
	opts := map[string]any{"flushIntervalMs": int64(time.Hour / time.Millisecond)}
	ref := ensureAttachWithPolicyOptions(t, hc, authority, "vol-wb-enum", "main", "/Volumes/WBEnum", "writeback", opts)
	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	c.call(&pfslocal.Hello{ProtocolMajor: 1})
	res := c.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply)
	root := res.Root

	for _, name := range []string{"wb-00", "wb-01", "wb-02", "wb-03", "wb-04", "wb-05"} {
		create := c.call(&pfslocal.CreateRequest{Dir: root, Name: []byte(name), Mode: 0o644, Exclusive: true}).(*pfslocal.CreateReply)
		c.call(&pfslocal.CloseRequest{Handle: create.Handle})
	}
	ghost := c.call(&pfslocal.LookupRequest{Dir: root, Name: []byte("ghost.txt")}).(*pfslocal.LookupReply)
	c.call(&pfslocal.RemoveRequest{Dir: root, Name: []byte("ghost.txt")})
	if er := c.callErr(&pfslocal.LookupRequest{Dir: root, Name: []byte("ghost.txt")}); er.Errno != darwinENOENT {
		t.Fatalf("ghost lookup after delete errno=%d want ENOENT", er.Errno)
	}
	if ghost.Attr.Item.ItemID == 0 {
		t.Fatalf("bad ghost lookup before delete: %+v", ghost)
	}

	seen := map[string]bool{}
	expected := map[string]bool{"wb-00": true, "wb-01": true, "wb-02": true, "wb-03": true, "wb-04": true, "wb-05": true}
	var cookie uint64
	insertedMidWalk := false
	for {
		page := c.call(&pfslocal.EnumerateRequest{Dir: root, Cookie: cookie, MaxEntries: 2, WantAttrs: true}).(*pfslocal.EnumerateReply)
		for _, e := range page.Entries {
			name := string(e.Name)
			if name == "ghost.txt" {
				t.Fatalf("deleted authority child appeared in enumerate page: %+v", page)
			}
			if seen[name] {
				t.Fatalf("duplicate enumerate entry %q after cookie %d", name, cookie)
			}
			seen[name] = true
		}
		if !insertedMidWalk {
			create := c.call(&pfslocal.CreateRequest{Dir: root, Name: []byte("aa-midwalk"), Mode: 0o644, Exclusive: true}).(*pfslocal.CreateReply)
			c.call(&pfslocal.CloseRequest{Handle: create.Handle})
			insertedMidWalk = true
		}
		if page.NextCookie == 0 {
			break
		}
		cookie = page.NextCookie
	}
	for name := range expected {
		if !seen[name] {
			t.Fatalf("enumerate missed pre-existing overlay child %q; seen=%v", name, seen)
		}
	}
}

func TestDaemonEnumerateSnapshotsSurviveInterleavedCookieChurn(t *testing.T) {
	authority := serveAuthority(t)
	want := seedAuthorityFiles(t, authority, 4110)

	cfg, _, ref, cancel := startDaemon(t, authority)
	defer cancel()
	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	c.call(&pfslocal.Hello{ProtocolMajor: 1})
	res := c.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply)
	root := res.Root

	var namesA, namesB []string
	seenA, seenB := map[string]bool{}, map[string]bool{}
	cookieA := appendEnumeratePage(t, c, root, 0, 1, &namesA, seenA)
	cookieB := appendEnumeratePage(t, c, root, 0, 1, &namesB, seenB)
	if cookieA == 0 || cookieB == 0 {
		t.Fatal("large enumeration unexpectedly completed on the first page")
	}

	// Keep B live while A advances beyond the old 4096-cookie wholesale-reset threshold.
	// With the former unknown-cookie-as-index fallback, B's early token could be evicted
	// and then misread as an index, silently skipping entries.
	for i := 0; i < 4097 && cookieA != 0; i++ {
		cookieA = appendEnumeratePage(t, c, root, cookieA, 1, &namesA, seenA)
	}
	if cookieB == 0 {
		t.Fatal("B unexpectedly finished before the churn point")
	}
	cookieB = appendEnumeratePage(t, c, root, cookieB, 1, &namesB, seenB)

	for cookieA != 0 || cookieB != 0 {
		if cookieA != 0 {
			cookieA = appendEnumeratePage(t, c, root, cookieA, 128, &namesA, seenA)
		}
		if cookieB != 0 {
			cookieB = appendEnumeratePage(t, c, root, cookieB, 128, &namesB, seenB)
		}
	}
	assertExactNames(t, namesA, want)
	assertExactNames(t, namesB, want)
}

func TestDaemonEnumerateWantAttrsModesReturnCompleteLargeDir(t *testing.T) {
	authority := serveAuthority(t)
	want := seedAuthorityAppleDoubleFiles(t, authority, 1200)

	cfg, _, ref, cancel := startDaemon(t, authority)
	defer cancel()
	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	c.call(&pfslocal.Hello{ProtocolMajor: 1})
	res := c.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply)

	withAttrs := enumerateAllPFSMode(t, c, res.Root, 37, true)
	withoutAttrs := enumerateAllPFSMode(t, c, res.Root, 37, false)
	assertExactNames(t, withAttrs, want)
	assertExactNames(t, withoutAttrs, want)
}

func TestDaemonEnumerateOffsetCookieFailsSafe(t *testing.T) {
	authority := serveAuthority(t)
	seedAuthorityFiles(t, authority, 3)

	cfg, _, ref, cancel := startDaemon(t, authority)
	defer cancel()
	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	c.call(&pfslocal.Hello{ProtocolMajor: 1})
	res := c.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply)

	page := c.call(&pfslocal.EnumerateRequest{Dir: res.Root, MaxEntries: 1, WantAttrs: false}).(*pfslocal.EnumerateReply)
	if page.NextCookie == 0 || page.NextCookie&enumerateCookieMarker == 0 || page.NextCookie&enumerateCookieReservedMask != 0 {
		t.Fatalf("next cookie=%#x, want high-bit reserved-zero continuation", page.NextCookie)
	}
	if er := c.callErr(&pfslocal.EnumerateRequest{Dir: res.Root, Cookie: page.NextCookie + 2, MaxEntries: 1, WantAttrs: false}); er.Errno != darwinESTALE {
		t.Fatalf("offset cookie errno=%d want ESTALE", er.Errno)
	}
}

func TestDaemonEnumerateConcurrentSameDirSnapshotsAreIsolated(t *testing.T) {
	authority := serveAuthority(t)
	want := seedAuthorityAppleDoubleFiles(t, authority, 1200)

	dir, err := os.MkdirTemp("", "pfsd-enum-concurrent-")
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
	defer cancel()
	srv := NewServer(cfg)
	runDone := make(chan error, 1)
	go func() {
		runDone <- srv.Run(ctx)
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
	hc := httpUDSClient(cfg.ControlSocket)
	ref := ensureAttach(t, hc, authority, "vol-enum-concurrent", "main", "/Volumes/EnumConcurrent")
	a := srv.registry.get(ref)
	if a == nil {
		t.Fatal("attach missing after ensure")
	}

	const workers = 5
	ready := make(chan struct{}, workers)
	release := make(chan struct{})
	results := make([][]string, workers)
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c := dialPFS(t, cfg.FrontendSocket)
			defer c.close()
			c.call(&pfslocal.Hello{ProtocolMajor: 1})
			res := c.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply)
			var names []string
			seen := map[string]bool{}
			cookie := appendEnumeratePageMode(t, c, res.Root, 0, 17, false, &names, seen)
			ready <- struct{}{}
			<-release
			for cookie != 0 {
				cookie = appendEnumeratePageMode(t, c, res.Root, cookie, 17, false, &names, seen)
			}
			results[i] = names
		}(i)
	}
	for i := 0; i < workers; i++ {
		select {
		case <-ready:
		case <-time.After(10 * time.Second):
			close(release)
			wg.Wait()
			t.Fatalf("timed out waiting for enumeration %d first page", i)
		}
	}
	a.mu.RLock()
	live := len(a.enumRecords)
	a.mu.RUnlock()
	if live != workers {
		close(release)
		wg.Wait()
		t.Fatalf("live enumeration records=%d want %d", live, workers)
	}
	close(release)
	wg.Wait()
	for i := 0; i < workers; i++ {
		assertExactNames(t, results[i], want)
	}
}

func TestDaemonEnumerateStaleCookieAfterRestartFailsSafe(t *testing.T) {
	authority := serveAuthority(t)
	want := seedAuthorityFiles(t, authority, 4)
	bin := buildPortablefsdTestBinary(t)
	stateDir, err := os.MkdirTemp("", "pfsd-enum-restart-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stateDir) })

	p1 := startPortablefsdProcess(t, bin, stateDir, "pfsd-enum-restart1")
	ref1 := ensureAttachWithPolicy(t, p1.hc, authority, "vol-enum-restart", "main", "/Volumes/EnumRestart", "writethrough")
	c1 := dialPFS(t, p1.cfg.FrontendSocket)
	c1.call(&pfslocal.Hello{ProtocolMajor: 1})
	res1 := c1.call(&pfslocal.ResolveRequest{AttachRef: ref1}).(*pfslocal.ResolveReply)
	page1 := c1.call(&pfslocal.EnumerateRequest{Dir: res1.Root, MaxEntries: 1, WantAttrs: true}).(*pfslocal.EnumerateReply)
	if page1.NextCookie == 0 || page1.NextCookie&enumerateCookieMarker == 0 {
		t.Fatalf("first page next cookie=%#x, want high-bit continuation", page1.NextCookie)
	}
	staleCookie := page1.NextCookie
	p1.stop()
	c1.close()

	p2 := startPortablefsdProcess(t, bin, stateDir, "pfsd-enum-restart2")
	ref2 := ensureAttachWithPolicy(t, p2.hc, authority, "vol-enum-restart", "main", "/Volumes/EnumRestart", "writethrough")
	if ref2 != ref1 {
		t.Fatalf("restart ref=%q want %q", ref2, ref1)
	}
	c2 := dialPFS(t, p2.cfg.FrontendSocket)
	defer c2.close()
	c2.call(&pfslocal.Hello{ProtocolMajor: 1})
	res2 := c2.call(&pfslocal.ResolveRequest{AttachRef: ref2}).(*pfslocal.ResolveReply)
	if er := c2.callErr(&pfslocal.EnumerateRequest{Dir: res2.Root, Cookie: staleCookie, MaxEntries: 1, WantAttrs: true}); er.Errno != darwinESTALE {
		t.Fatalf("stale restart cookie errno=%d want ESTALE", er.Errno)
	}
	assertExactNames(t, enumerateAllPFS(t, c2, res2.Root, 2), want)
}

func TestDaemonEnumerateLRUEvictionFailsSafe(t *testing.T) {
	authority := serveAuthority(t)
	seedAuthorityFiles(t, authority, 3)
	cfg, _, ref, cancel := startDaemon(t, authority)
	defer cancel()
	c := dialPFS(t, cfg.FrontendSocket)
	defer c.close()
	c.call(&pfslocal.Hello{ProtocolMajor: 1})
	res := c.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply)

	var firstCookie uint64
	for i := 0; i < maxLiveEnumerations+1; i++ {
		page := c.call(&pfslocal.EnumerateRequest{Dir: res.Root, MaxEntries: 1, WantAttrs: true}).(*pfslocal.EnumerateReply)
		if page.NextCookie == 0 || page.NextCookie&enumerateCookieMarker == 0 {
			t.Fatalf("enumeration %d next cookie=%#x, want high-bit continuation", i, page.NextCookie)
		}
		if i == 0 {
			firstCookie = page.NextCookie
		}
	}
	if er := c.callErr(&pfslocal.EnumerateRequest{Dir: res.Root, Cookie: firstCookie, MaxEntries: 1, WantAttrs: true}); er.Errno != darwinESTALE {
		t.Fatalf("LRU-evicted cookie errno=%d want ESTALE", er.Errno)
	}
}

func writeControlFile(t *testing.T, hc *http.Client, ref, p, data string) {
	t.Helper()
	controlJSON(t, hc, http.MethodPost, "/v1/attaches/"+ref+"/fs/write", map[string]string{
		"path": p, "dataBase64": base64.StdEncoding.EncodeToString([]byte(data)),
	}, http.StatusNoContent, nil)
}

var (
	testBinOnce sync.Once
	testBinPath string
	testBinErr  error
)

// buildPortablefsdTestBinary builds the daemon ONCE per test process. A fresh
// binary's first exec goes through macOS binary assessment, which serializes
// on syspolicyd and can take tens of seconds when the machine is under
// concurrent build/test load; building (and warming) one binary keeps that
// cost out of every subprocess test's socket-readiness window.
func buildPortablefsdTestBinary(t *testing.T) string {
	t.Helper()
	testBinOnce.Do(func() {
		dir, err := os.MkdirTemp("", "portablefsd-testbin-")
		if err != nil {
			testBinErr = err
			return
		}
		bin := filepath.Join(dir, "portablefsd-test")
		build := exec.Command("go", "build", "-o", bin, "./cmd/portablefsd")
		build.Dir = filepath.Join("..", "..")
		if out, err := build.CombinedOutput(); err != nil {
			testBinErr = fmt.Errorf("%v\n%s", err, out)
			return
		}
		// Pre-pay the first-exec assessment here rather than under a test's
		// startup deadline; the bogus flag makes the daemon exit immediately.
		_ = exec.Command(bin, "--portablefsd-test-warmup").Run()
		testBinPath = bin
	})
	if testBinErr != nil {
		t.Fatalf("build portablefsd: %v", testBinErr)
	}
	return testBinPath
}

type portablefsdProcess struct {
	cmd     *exec.Cmd
	cfg     Config
	hc      *http.Client
	stderr  *bytes.Buffer
	stopped atomic.Bool
}

func startPortablefsdProcess(t *testing.T, bin, stateDir, name string) *portablefsdProcess {
	t.Helper()
	runDir, err := os.MkdirTemp("", name+"-")
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{
		FrontendSocket: filepath.Join(runDir, "frontend.sock"),
		ControlSocket:  filepath.Join(runDir, "control.sock"),
		StateDir:       stateDir,
	}
	cmd := exec.Command(bin, "--frontend-socket", cfg.FrontendSocket, "--control-socket", cfg.ControlSocket, "--state-dir", cfg.StateDir)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &portablefsdProcess{cmd: cmd, cfg: cfg, hc: httpUDSClient(cfg.ControlSocket), stderr: &stderr}
	t.Cleanup(func() {
		if t.Failed() {
			alive := cmd.Process != nil && cmd.Process.Signal(syscall.Signal(0)) == nil
			t.Logf("%s: pid=%d alive=%v stderr(%d bytes):\n%s", name, cmd.Process.Pid, alive, stderr.Len(), stderr.String())
		}
		p.stop()
		_ = os.RemoveAll(runDir)
	})
	waitUnix(t, cfg.ControlSocket)
	waitUnix(t, cfg.FrontendSocket)
	return p
}

func (p *portablefsdProcess) stop() {
	if p == nil || p.cmd == nil || p.cmd.Process == nil || p.stopped.Swap(true) {
		return
	}
	_ = p.cmd.Process.Kill()
	_ = p.cmd.Wait()
}

func TestDaemonRevivesAttachRefAfterRestart(t *testing.T) {
	authority := serveAuthority(t)
	bin := buildPortablefsdTestBinary(t)
	stateDir, err := os.MkdirTemp("", "pfsd-wal-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stateDir) })

	p1 := startPortablefsdProcess(t, bin, stateDir, "pfsd-revive1")
	ref := ensureAttachWithPolicy(t, p1.hc, authority, "vol-revive", "main", "/Volumes/Revive", "writethrough")
	credentialRef := ensureAttachWithPolicy(t, p1.hc, authority, "vol-revive-credential", "main", "/Volumes/ReviveCredential", "writethrough")
	c1 := dialPFS(t, p1.cfg.FrontendSocket)
	c1.call(&pfslocal.Hello{ProtocolMajor: 1})
	res1 := c1.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply)
	cr := c1.call(&pfslocal.CreateRequest{Dir: res1.Root, Name: []byte("alive.txt"), Mode: 0o644, Exclusive: true}).(*pfslocal.CreateReply)
	c1.call(&pfslocal.WriteRequest{Handle: cr.Handle, Data: []byte("alive")})
	c1.call(&pfslocal.CloseRequest{Handle: cr.Handle})
	c1.close()
	cCred1 := dialPFS(t, p1.cfg.FrontendSocket)
	cCred1.call(&pfslocal.Hello{ProtocolMajor: 1})
	credRes1 := cCred1.call(&pfslocal.ResolveRequest{AttachRef: credentialRef}).(*pfslocal.ResolveReply)
	credCreate := cCred1.call(&pfslocal.CreateRequest{Dir: credRes1.Root, Name: []byte("credential.txt"), Mode: 0o644, Exclusive: true}).(*pfslocal.CreateReply)
	cCred1.call(&pfslocal.WriteRequest{Handle: credCreate.Handle, Data: []byte("credential")})
	cCred1.call(&pfslocal.CloseRequest{Handle: credCreate.Handle})
	cCred1.close()
	p1.stop()

	p2 := startPortablefsdProcess(t, bin, stateDir, "pfsd-revive2")
	c2 := dialPFS(t, p2.cfg.FrontendSocket)
	defer c2.close()
	c2.call(&pfslocal.Hello{ProtocolMajor: 1})
	res2 := c2.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply)
	if res2.Root.ItemID == 0 || res2.RootAttr.Kind != pfslocal.ItemKindDirectory {
		t.Fatalf("revived resolve = %+v", res2)
	}
	if er := c2.callErr(&pfslocal.LookupRequest{Dir: res2.Root, Name: []byte("alive.txt")}); er.Errno != darwinEIO {
		t.Fatalf("pending lookup errno=%d want EIO", er.Errno)
	}
	events := dialPFS(t, p2.cfg.FrontendSocket)
	defer events.close()
	events.call(&pfslocal.Hello{ProtocolMajor: 1})
	events.call(&pfslocal.ResolveRequest{AttachRef: ref})
	if st := events.subscribeAndWaitAttachState(pfslocal.AttachStateDegraded); st.Detail == "" {
		t.Fatalf("degraded event missing detail: %+v", st)
	}
	var pending attachStatus
	controlJSON(t, p2.hc, http.MethodGet, "/v1/attaches/"+ref, nil, http.StatusOK, &pending)
	if pending.State != "degraded" || pending.LastError == "" {
		t.Fatalf("pending status = %+v", pending)
	}

	cCred2 := dialPFS(t, p2.cfg.FrontendSocket)
	defer cCred2.close()
	cCred2.call(&pfslocal.Hello{ProtocolMajor: 1})
	credRes2 := cCred2.call(&pfslocal.ResolveRequest{AttachRef: credentialRef}).(*pfslocal.ResolveReply)
	if er := cCred2.callErr(&pfslocal.LookupRequest{Dir: credRes2.Root, Name: []byte("credential.txt")}); er.Errno != darwinEIO {
		t.Fatalf("credential-pending lookup errno=%d want EIO", er.Errno)
	}
	controlJSON(t, p2.hc, http.MethodPost, "/v1/attaches/"+credentialRef+"/credential", map[string]string{"authToken": ""}, http.StatusNoContent, nil)
	credLookup := cCred2.call(&pfslocal.LookupRequest{Dir: credRes2.Root, Name: []byte("credential.txt")}).(*pfslocal.LookupReply)
	if credLookup.Attr.Kind != pfslocal.ItemKindFile {
		t.Fatalf("post-credential endpoint lookup = %+v", credLookup)
	}

	ref2 := ensureAttachWithPolicy(t, p2.hc, authority, "vol-revive", "main", "/Volumes/Revive", "writethrough")
	if ref2 != ref {
		t.Fatalf("reattach ref=%q want old ref %q", ref2, ref)
	}
	lr := c2.call(&pfslocal.LookupRequest{Dir: res2.Root, Name: []byte("alive.txt")}).(*pfslocal.LookupReply)
	if lr.Attr.Kind != pfslocal.ItemKindFile {
		t.Fatalf("post-credential lookup = %+v", lr)
	}
	var attached attachStatus
	controlJSON(t, p2.hc, http.MethodGet, "/v1/attaches/"+ref, nil, http.StatusOK, &attached)
	if attached.State != "attached" || attached.LastError != "" {
		t.Fatalf("attached status = %+v", attached)
	}
}

func TestDaemonStableItemIdentityAfterRestart(t *testing.T) {
	authority := serveAuthority(t)
	bin := buildPortablefsdTestBinary(t)
	stateDir, err := os.MkdirTemp("", "pfsd-identity-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stateDir) })

	p1 := startPortablefsdProcess(t, bin, stateDir, "pfsd-identity1")
	ref1 := ensureAttachWithPolicy(t, p1.hc, authority, "vol-identity", "main", "/Volumes/Identity", "writethrough")
	c1 := dialPFS(t, p1.cfg.FrontendSocket)
	c1.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "identity-before"})
	res1 := c1.call(&pfslocal.ResolveRequest{AttachRef: ref1}).(*pfslocal.ResolveReply)
	root1 := res1.Root
	mkdir := c1.call(&pfslocal.MkdirRequest{Dir: root1, Name: []byte("bigdir"), Mode: 0o755}).(*pfslocal.MkdirReply)
	dirItem := mkdir.Attr.Item
	create := c1.call(&pfslocal.CreateRequest{Dir: dirItem, Name: []byte("kept.txt"), Mode: 0o644, Exclusive: true}).(*pfslocal.CreateReply)
	fileItem := create.Attr.Item
	c1.call(&pfslocal.WriteRequest{Handle: create.Handle, Data: []byte("identity survives")})
	c1.call(&pfslocal.CloseRequest{Handle: create.Handle})
	lookupBefore := c1.call(&pfslocal.LookupRequest{Dir: dirItem, Name: []byte("kept.txt")}).(*pfslocal.LookupReply)
	if lookupBefore.Attr.Item != fileItem {
		t.Fatalf("pre-restart lookup item=%+v want create item %+v", lookupBefore.Attr.Item, fileItem)
	}
	p1.stop()
	c1.close()

	p2 := startPortablefsdProcess(t, bin, stateDir, "pfsd-identity2")
	pending := dialPFS(t, p2.cfg.FrontendSocket)
	pending.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "identity-pending"})
	pendingRes := pending.call(&pfslocal.ResolveRequest{AttachRef: ref1}).(*pfslocal.ResolveReply)
	if pendingRes.Root != root1 {
		t.Fatalf("credential-pending root item=%+v want pre-crash %+v", pendingRes.Root, root1)
	}
	if pendingRes.RootAttr.Kind != pfslocal.ItemKindDirectory {
		t.Fatalf("credential-pending root attr=%+v, want directory", pendingRes.RootAttr)
	}
	pending.close()

	ref2 := ensureAttachWithPolicy(t, p2.hc, authority, "vol-identity", "main", "/Volumes/Identity", "writethrough")
	if ref2 != ref1 {
		t.Fatalf("restart ref=%q want %q", ref2, ref1)
	}
	c2 := dialPFS(t, p2.cfg.FrontendSocket)
	defer c2.close()
	c2.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "identity-after"})
	res2 := c2.call(&pfslocal.ResolveRequest{AttachRef: ref2}).(*pfslocal.ResolveReply)
	if res2.Root != root1 {
		t.Fatalf("post-restart root item=%+v want pre-crash %+v", res2.Root, root1)
	}
	if got := c2.call(&pfslocal.GetAttrRequest{Item: root1}).(*pfslocal.GetAttrReply); got.Attr.Kind != pfslocal.ItemKindDirectory {
		t.Fatalf("old root getattr=%+v", got.Attr)
	}
	if got := c2.call(&pfslocal.GetAttrRequest{Item: dirItem}).(*pfslocal.GetAttrReply); got.Attr.Kind != pfslocal.ItemKindDirectory {
		t.Fatalf("old dir getattr=%+v", got.Attr)
	}
	if got := c2.call(&pfslocal.GetAttrRequest{Item: fileItem}).(*pfslocal.GetAttrReply); got.Attr.Kind != pfslocal.ItemKindFile {
		t.Fatalf("old file getattr=%+v", got.Attr)
	}
	dirLookup := c2.call(&pfslocal.LookupRequest{Dir: root1, Name: []byte("bigdir")}).(*pfslocal.LookupReply)
	if dirLookup.Attr.Item != dirItem || dirLookup.Attr.Kind != pfslocal.ItemKindDirectory {
		t.Fatalf("lookup old root/bigdir=%+v want item %+v", dirLookup.Attr, dirItem)
	}
	fileLookup := c2.call(&pfslocal.LookupRequest{Dir: dirItem, Name: []byte("kept.txt")}).(*pfslocal.LookupReply)
	if fileLookup.Attr.Item != fileItem || fileLookup.Attr.Kind != pfslocal.ItemKindFile {
		t.Fatalf("lookup old dir/kept.txt=%+v want item %+v", fileLookup.Attr, fileItem)
	}
	op := c2.call(&pfslocal.OpenRequest{Item: fileItem, Mode: pfslocal.OpenModeRead}).(*pfslocal.OpenReply)
	read := c2.call(&pfslocal.ReadRequest{Handle: op.Handle, Length: 64}).(*pfslocal.ReadReply)
	if string(read.Data) != "identity survives" {
		t.Fatalf("read via old file item=%q", read.Data)
	}
	names := enumerateAllPFS(t, c2, root1, 2)
	assertExactNames(t, names, []string{"bigdir"})
}

func TestDaemonWritebackHardLinkSharesOpenItemAcrossRestart(t *testing.T) {
	authority := serveAuthority(t)
	bin := buildPortablefsdTestBinary(t)
	stateDir, err := os.MkdirTemp("", "pfsd-hardlink-identity-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stateDir) })

	opts := map[string]any{"flushIntervalMs": int64(time.Hour / time.Millisecond)}
	p1 := startPortablefsdProcess(t, bin, stateDir, "pfsd-hardlink1")
	ref1 := ensureAttachWithPolicyOptions(t, p1.hc, authority, "vol-hardlink", "main", "/Volumes/Hardlink", "writeback", opts)
	c1 := dialPFS(t, p1.cfg.FrontendSocket)
	c1.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "hardlink-before"})
	res1 := c1.call(&pfslocal.ResolveRequest{AttachRef: ref1}).(*pfslocal.ResolveReply)
	dir := c1.call(&pfslocal.MkdirRequest{Dir: res1.Root, Name: []byte("delegated"), Mode: 0o755}).(*pfslocal.MkdirReply)

	// The create remains open while Link drains its delegation, establishes
	// the authority identity/open pin, and publishes the alias. Both names
	// must continue to be one pfslocal Item, not two objects with coincident
	// link counts.
	source := c1.call(&pfslocal.CreateRequest{Dir: dir.Attr.Item, Name: []byte("source"), Mode: 0o644, Exclusive: true}).(*pfslocal.CreateReply)
	c1.call(&pfslocal.WriteRequest{Handle: source.Handle, Data: []byte("abcdefgh")})
	alias := c1.call(&pfslocal.HardLinkRequest{Item: source.Attr.Item, Dir: dir.Attr.Item, Name: []byte("alias")}).(*pfslocal.HardLinkReply)
	if alias.Attr.Item != source.Attr.Item || alias.Attr.Nlink != 2 {
		t.Fatalf("open-source hardlink split item: source=%+v alias=%+v", source.Attr, alias.Attr)
	}
	aliasLookup := c1.call(&pfslocal.LookupRequest{Dir: dir.Attr.Item, Name: []byte("alias")}).(*pfslocal.LookupReply)
	if aliasLookup.Attr.Item != source.Attr.Item || aliasLookup.Attr.Nlink != 2 {
		t.Fatalf("alias lookup split item: source=%+v alias=%+v", source.Attr, aliasLookup.Attr)
	}

	aliasOpen := c1.call(&pfslocal.OpenRequest{Item: alias.Attr.Item, Mode: pfslocal.OpenModeReadWrite}).(*pfslocal.OpenReply)
	c1.call(&pfslocal.WriteRequest{Handle: source.Handle, Offset: 0, Data: []byte("SOURCE!!")})
	if got := c1.call(&pfslocal.ReadRequest{Handle: aliasOpen.Handle, Length: 16}).(*pfslocal.ReadReply); string(got.Data) != "SOURCE!!" {
		t.Fatalf("source write not visible through alias: %q", got.Data)
	}
	size := uint64(4)
	c1.call(&pfslocal.SetAttrRequest{Item: alias.Attr.Item, Size: &size})
	if got := c1.call(&pfslocal.ReadRequest{Handle: source.Handle, Length: 16}).(*pfslocal.ReadReply); string(got.Data) != "SOUR" {
		t.Fatalf("alias truncate not visible through open source: %q", got.Data)
	}
	c1.call(&pfslocal.WriteRequest{Handle: aliasOpen.Handle, Offset: 0, Data: []byte("alias-data")})
	if got := c1.call(&pfslocal.ReadRequest{Handle: source.Handle, Length: 16}).(*pfslocal.ReadReply); string(got.Data) != "alias-data" {
		t.Fatalf("alias write not visible through open source: %q", got.Data)
	}
	c1.call(&pfslocal.FsyncRequest{Handle: source.Handle})
	c1.call(&pfslocal.CloseRequest{Handle: aliasOpen.Handle})
	c1.call(&pfslocal.CloseRequest{Handle: source.Handle})

	// A process restart restores the frontend item and its distinct authority
	// inode from the durable binding journal. With all old handles closed,
	// opening either name still reaches the same authority inode.
	p1.stop()
	c1.close()
	p2 := startPortablefsdProcess(t, bin, stateDir, "pfsd-hardlink2")
	ref2 := ensureAttachWithPolicyOptions(t, p2.hc, authority, "vol-hardlink", "main", "/Volumes/Hardlink", "writeback", opts)
	if ref2 != ref1 {
		t.Fatalf("restart ref=%q want %q", ref2, ref1)
	}
	c2 := dialPFS(t, p2.cfg.FrontendSocket)
	defer c2.close()
	c2.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "hardlink-after"})
	res2 := c2.call(&pfslocal.ResolveRequest{AttachRef: ref2}).(*pfslocal.ResolveReply)
	dir2 := c2.call(&pfslocal.LookupRequest{Dir: res2.Root, Name: []byte("delegated")}).(*pfslocal.LookupReply)
	source2 := c2.call(&pfslocal.LookupRequest{Dir: dir2.Attr.Item, Name: []byte("source")}).(*pfslocal.LookupReply)
	alias2 := c2.call(&pfslocal.LookupRequest{Dir: dir2.Attr.Item, Name: []byte("alias")}).(*pfslocal.LookupReply)
	if source2.Attr.Item != source.Attr.Item || alias2.Attr.Item != source.Attr.Item ||
		source2.Attr.Nlink != 2 || alias2.Attr.Nlink != 2 {
		t.Fatalf("restart hardlink identity: before=%+v source=%+v alias=%+v", source.Attr, source2.Attr, alias2.Attr)
	}
	closedSource := c2.call(&pfslocal.OpenRequest{Item: source2.Attr.Item, Mode: pfslocal.OpenModeReadWrite}).(*pfslocal.OpenReply)
	closedAlias := c2.call(&pfslocal.OpenRequest{Item: alias2.Attr.Item, Mode: pfslocal.OpenModeReadWrite}).(*pfslocal.OpenReply)
	c2.call(&pfslocal.WriteRequest{Handle: closedAlias.Handle, Offset: 0, Data: []byte("restart")})
	if got := c2.call(&pfslocal.ReadRequest{Handle: closedSource.Handle, Length: 16}).(*pfslocal.ReadReply); string(got.Data) != "restartata" {
		t.Fatalf("post-restart alias write not visible through source: %q", got.Data)
	}
	c2.call(&pfslocal.FsyncRequest{Handle: closedAlias.Handle})
	c2.call(&pfslocal.CloseRequest{Handle: closedAlias.Handle})
	c2.call(&pfslocal.CloseRequest{Handle: closedSource.Handle})
}

func TestDaemonPeerHardLinkDiscoveryReusesDelegatedCreateIdentity(t *testing.T) {
	authority := serveAuthority(t)
	cfg, hc, _ := startDaemonNoAttach(t, authority)
	opts := map[string]any{"flushIntervalMs": int64(time.Hour / time.Millisecond)}
	ref := ensureAttachWithPolicyOptions(
		t, hc, authority, "vol-peer-hardlink", "main",
		"/Volumes/PeerHardlink", "writeback", opts,
	)

	local := dialPFS(t, cfg.FrontendSocket)
	defer local.close()
	local.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "peer-hardlink-local"})
	root := local.call(&pfslocal.ResolveRequest{AttachRef: ref}).(*pfslocal.ResolveReply).Root
	dir := local.call(&pfslocal.MkdirRequest{
		Dir: root, Name: []byte("delegated"), Mode: 0o755,
	}).(*pfslocal.MkdirReply)
	source := local.call(&pfslocal.CreateRequest{
		Dir: dir.Attr.Item, Name: []byte("source"), Mode: 0o644, Exclusive: true,
	}).(*pfslocal.CreateReply)
	if source.Attr.Item.ItemID&localItemIDMarker == 0 {
		t.Fatalf("delegated create item=%+v, want daemon-local identity", source.Attr.Item)
	}
	local.call(&pfslocal.WriteRequest{Handle: source.Handle, Data: []byte("before")})

	// Synchronize makes the data authority-durable while the adaptive
	// delegation remains held. The peer link below recalls that delegation;
	// its release pin assigns an authority inode to source's still-open
	// NodeState while the frontend gate is closed. portablefsd must index
	// that inode before the peer can publish a new name for it.
	local.call(&pfslocal.SyncVolumeRequest{})

	peer, err := clientcore.Dial(context.Background(), clientcore.Options{
		Addr: authority, Pool: 2, Owner: "peer-hardlink-writer",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	peerSource, st := peer.Lookup(context.Background(), "delegated/source")
	if st != fsproto.OK || peerSource.Ino == 0 {
		t.Fatalf("peer source lookup: attr=%+v st=%d", peerSource, st)
	}
	peerState := clientcore.NewNodeState(peerSource.Ino, true)
	for _, alias := range []string{"lookup-alias", "enum-alias"} {
		if linked, st := peer.Link(
			context.Background(),
			"delegated/source",
			"delegated/"+alias,
			peerState,
		); st != fsproto.OK || linked.Ino != peerSource.Ino {
			t.Fatalf("peer link %s: attr=%+v st=%d", alias, linked, st)
		}
	}
	local.call(&pfslocal.CloseRequest{Handle: source.Handle})

	lookupAlias := local.call(&pfslocal.LookupRequest{
		Dir: dir.Attr.Item, Name: []byte("lookup-alias"),
	}).(*pfslocal.LookupReply)
	if lookupAlias.Attr.Item != source.Attr.Item {
		t.Fatalf("peer alias lookup split frontend identity: source=%+v alias=%+v",
			source.Attr.Item, lookupAlias.Attr.Item)
	}

	page := local.call(&pfslocal.EnumerateRequest{
		Dir: dir.Attr.Item, MaxEntries: 32, WantAttrs: true,
	}).(*pfslocal.EnumerateReply)
	var enumAlias *pfslocal.DirEntry
	for i := range page.Entries {
		if string(page.Entries[i].Name) == "enum-alias" {
			enumAlias = &page.Entries[i]
			break
		}
	}
	if enumAlias == nil {
		t.Fatalf("peer enum alias absent from listing: %+v", page.Entries)
	}
	if enumAlias.Attr.Item != source.Attr.Item {
		t.Fatalf("peer alias readdir split frontend identity: source=%+v alias=%+v",
			source.Attr.Item, enumAlias.Attr.Item)
	}

	// Removing the original name must move the canonical path to an alias
	// without changing Item ID, generation, or NodeState. An already-open
	// handle and a newly-opened survivor then share writes.
	beforeUnlink := local.call(&pfslocal.OpenRequest{
		Item: source.Attr.Item, Mode: pfslocal.OpenModeReadWrite,
	}).(*pfslocal.OpenReply)
	local.call(&pfslocal.RemoveRequest{
		Dir: dir.Attr.Item, Name: []byte("source"),
	})
	survivor := local.call(&pfslocal.LookupRequest{
		Dir: dir.Attr.Item, Name: []byte("enum-alias"),
	}).(*pfslocal.LookupReply)
	if survivor.Attr.Item != source.Attr.Item {
		t.Fatalf("surviving alias changed frontend identity: source=%+v survivor=%+v",
			source.Attr.Item, survivor.Attr.Item)
	}
	afterUnlink := local.call(&pfslocal.OpenRequest{
		Item: survivor.Attr.Item, Mode: pfslocal.OpenModeReadWrite,
	}).(*pfslocal.OpenReply)
	local.call(&pfslocal.WriteRequest{
		Handle: afterUnlink.Handle, Offset: 0, Data: []byte("shared"),
	})
	if got := local.call(&pfslocal.ReadRequest{
		Handle: beforeUnlink.Handle, Length: 16,
	}).(*pfslocal.ReadReply); string(got.Data) != "shared" {
		t.Fatalf("surviving alias write not visible through pre-unlink open: %q", got.Data)
	}
	local.call(&pfslocal.CloseRequest{Handle: afterUnlink.Handle})
	local.call(&pfslocal.CloseRequest{Handle: beforeUnlink.Handle})
}

func TestDaemonWritebackFrontendItemSurvivesImmediateCrash(t *testing.T) {
	// The SIGKILLed daemon's mount session must expire quickly: its journaled
	// file-grain grants block the restarted daemon's WAL recovery (bounded
	// retry) until the lease resolves.
	prevTTL := workfs.SessionLeaseTTL()
	workfs.SetSessionLeaseTTL(time.Second)
	t.Cleanup(func() { workfs.SetSessionLeaseTTL(prevTTL) })
	authority := serveAuthority(t)
	bin := buildPortablefsdTestBinary(t)
	stateDir, err := os.MkdirTemp("", "pfsd-item-crash-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stateDir) })

	opts := map[string]any{"flushIntervalMs": int64(time.Hour / time.Millisecond)}
	p1 := startPortablefsdProcess(t, bin, stateDir, "pfsd-item-crash1")
	ref1 := ensureAttachWithPolicyOptions(t, p1.hc, authority, "vol-item-crash", "main", "/Volumes/ItemCrash", "writeback", opts)
	c1 := dialPFS(t, p1.cfg.FrontendSocket)
	c1.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "item-crash-before"})
	res1 := c1.call(&pfslocal.ResolveRequest{AttachRef: ref1}).(*pfslocal.ResolveReply)
	create := c1.call(&pfslocal.CreateRequest{Dir: res1.Root, Name: []byte("just-created.txt"), Mode: 0o644, Exclusive: true}).(*pfslocal.CreateReply)
	fileItem := create.Attr.Item
	c1.call(&pfslocal.WriteRequest{Handle: create.Handle, Data: []byte("survived immediate crash")})
	if got := c1.call(&pfslocal.ReadRequest{Handle: create.Handle, Length: 64}).(*pfslocal.ReadReply); string(got.Data) != "survived immediate crash" {
		t.Fatalf("pre-crash readback=%q", got.Data)
	}
	p1.stop()
	c1.close()

	p2 := startPortablefsdProcess(t, bin, stateDir, "pfsd-item-crash2")
	ref2 := ensureAttachWithPolicyOptions(t, p2.hc, authority, "vol-item-crash", "main", "/Volumes/ItemCrash", "writeback", opts)
	if ref2 != ref1 {
		t.Fatalf("restart ref=%q want %q", ref2, ref1)
	}
	c2 := dialPFS(t, p2.cfg.FrontendSocket)
	defer c2.close()
	c2.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "item-crash-after"})
	res2 := c2.call(&pfslocal.ResolveRequest{AttachRef: ref2}).(*pfslocal.ResolveReply)

	var oldAttr *pfslocal.GetAttrReply
	itemDeadline := time.Now().Add(20 * time.Second)
	for {
		body, er := c2.callMaybe(&pfslocal.GetAttrRequest{Item: fileItem})
		if er == nil {
			oldAttr = body.(*pfslocal.GetAttrReply)
			break
		}
		if time.Now().After(itemDeadline) {
			t.Fatalf("old item never recovered: errno=%d", er.Errno)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if oldAttr.Attr.Kind != pfslocal.ItemKindFile || oldAttr.Attr.Item != fileItem {
		t.Fatalf("old item getattr=%+v want file item %+v", oldAttr.Attr, fileItem)
	}
	oldOpen := c2.call(&pfslocal.OpenRequest{Item: fileItem, Mode: pfslocal.OpenModeRead}).(*pfslocal.OpenReply)
	oldRead := c2.call(&pfslocal.ReadRequest{Handle: oldOpen.Handle, Length: 64}).(*pfslocal.ReadReply)
	if string(oldRead.Data) != "survived immediate crash" {
		t.Fatalf("old item read=%q", oldRead.Data)
	}
	fresh := c2.call(&pfslocal.LookupRequest{Dir: res2.Root, Name: []byte("just-created.txt")}).(*pfslocal.LookupReply)
	if fresh.Attr.Kind != pfslocal.ItemKindFile || fresh.Attr.Item != fileItem {
		t.Fatalf("fresh lookup=%+v want same item %+v", fresh.Attr, fileItem)
	}
}

func TestDaemonWritebackWALReplayAfterCrash(t *testing.T) {
	// The SIGKILLed daemon's mount session must expire quickly: its journaled
	// file-grain grants block the restarted daemon's WAL recovery (bounded
	// retry) until the lease resolves.
	prevTTL := workfs.SessionLeaseTTL()
	workfs.SetSessionLeaseTTL(time.Second)
	t.Cleanup(func() { workfs.SetSessionLeaseTTL(prevTTL) })
	authority := serveAuthority(t)

	bin := buildPortablefsdTestBinary(t)
	stateDir, err := os.MkdirTemp("", "pfsd-wal-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stateDir) })

	writebackNoAutoFlush := map[string]any{"flushIntervalMs": int64(time.Hour / time.Millisecond)}
	p1 := startPortablefsdProcess(t, bin, stateDir, "pfsd1")
	ref1 := ensureAttachWithPolicyOptions(t, p1.hc, authority, "vol-crash", "main", "/Volumes/Crash", "writeback", writebackNoAutoFlush)
	c1 := dialPFS(t, p1.cfg.FrontendSocket)
	c1.call(&pfslocal.Hello{ProtocolMajor: 1})
	res1 := c1.call(&pfslocal.ResolveRequest{AttachRef: ref1}).(*pfslocal.ResolveReply)
	cr := c1.call(&pfslocal.CreateRequest{Dir: res1.Root, Name: []byte("crash.txt"), Mode: 0o644, Exclusive: true}).(*pfslocal.CreateReply)
	wr := c1.call(&pfslocal.WriteRequest{Handle: cr.Handle, Data: []byte("replayed")}).(*pfslocal.WriteReply)
	if wr.Written != uint32(len("replayed")) {
		t.Fatalf("write before crash = %d, want %d", wr.Written, len("replayed"))
	}
	rr := c1.call(&pfslocal.ReadRequest{Handle: cr.Handle, Length: 64}).(*pfslocal.ReadReply)
	if string(rr.Data) != "replayed" {
		t.Fatalf("pre-crash readback = %q, want replayed", rr.Data)
	}
	// No Fsync and no CloseRequest: SIGKILL immediately after the write ack must still
	// leave a replayable session WAL in state-dir.
	p1.stop()
	c1.close()

	p2 := startPortablefsdProcess(t, bin, stateDir, "pfsd2")
	ref2 := ensureAttachWithPolicyOptions(t, p2.hc, authority, "vol-crash", "main", "/Volumes/Crash", "writeback", writebackNoAutoFlush)
	if ref2 != ref1 {
		t.Fatalf("writeback restart ref=%q want %q", ref2, ref1)
	}
	c2 := dialPFS(t, p2.cfg.FrontendSocket)
	defer c2.close()
	c2.call(&pfslocal.Hello{ProtocolMajor: 1})
	res2 := c2.call(&pfslocal.ResolveRequest{AttachRef: ref2}).(*pfslocal.ResolveReply)
	var lr *pfslocal.LookupReply
	lookupDeadline := time.Now().Add(20 * time.Second)
	for {
		body, er := c2.callMaybe(&pfslocal.LookupRequest{Dir: res2.Root, Name: []byte("crash.txt")})
		if er == nil {
			lr = body.(*pfslocal.LookupReply)
			break
		}
		if time.Now().After(lookupDeadline) {
			t.Fatalf("crash.txt never recovered: errno=%d", er.Errno)
		}
		time.Sleep(100 * time.Millisecond)
	}
	if lr.Attr.Kind != pfslocal.ItemKindFile {
		t.Fatalf("post-restart lookup attr = %+v, want file", lr.Attr)
	}
	op := c2.call(&pfslocal.OpenRequest{Item: lr.Attr.Item, Mode: pfslocal.OpenModeRead}).(*pfslocal.OpenReply)
	got := c2.call(&pfslocal.ReadRequest{Handle: op.Handle, Length: 64}).(*pfslocal.ReadReply)
	if string(got.Data) != "replayed" {
		t.Fatalf("post-restart read = %q, want replayed", got.Data)
	}
}

func TestDaemonWritebackWALReplayAfterCrashWithPriorSessionHistory(t *testing.T) {
	// The SIGKILLed daemon's mount session must expire quickly: its journaled
	// file-grain grants block the restarted daemon's WAL recovery (bounded
	// retry) until the lease resolves.
	prevTTL := workfs.SessionLeaseTTL()
	workfs.SetSessionLeaseTTL(time.Second)
	t.Cleanup(func() { workfs.SetSessionLeaseTTL(prevTTL) })
	authority := serveAuthority(t)

	bin := buildPortablefsdTestBinary(t)
	stateDir, err := os.MkdirTemp("", "pfsd-wal-history-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stateDir) })

	opts := map[string]any{
		"flushIntervalMs": int64(time.Hour / time.Millisecond),
		"fsyncPolicy":     "authority",
	}
	p1 := startPortablefsdProcess(t, bin, stateDir, "pfsd-history1")
	ref1 := ensureAttachWithPolicyOptions(t, p1.hc, authority, "vol-history", "main", "/Volumes/History", "writeback", opts)
	c1 := dialPFS(t, p1.cfg.FrontendSocket)
	c1.call(&pfslocal.Hello{ProtocolMajor: 1})
	res1 := c1.call(&pfslocal.ResolveRequest{AttachRef: ref1}).(*pfslocal.ResolveReply)

	hist := c1.call(&pfslocal.CreateRequest{Dir: res1.Root, Name: []byte("history.txt"), Mode: 0o644, Exclusive: true}).(*pfslocal.CreateReply)
	c1.call(&pfslocal.WriteRequest{Handle: hist.Handle, Data: []byte("flushed")})
	c1.call(&pfslocal.FsyncRequest{Handle: hist.Handle}) // advances the authority watermark, then compacts the local WAL.
	c1.call(&pfslocal.CloseRequest{Handle: hist.Handle})

	live := c1.call(&pfslocal.CreateRequest{Dir: res1.Root, Name: []byte("durability.txt"), Mode: 0o644, Exclusive: true}).(*pfslocal.CreateReply)
	c1.call(&pfslocal.WriteRequest{Handle: live.Handle, Data: []byte("survives")})
	if got := c1.call(&pfslocal.ReadRequest{Handle: live.Handle, Length: 64}).(*pfslocal.ReadReply); string(got.Data) != "survives" {
		t.Fatalf("pre-crash readback=%q want survives", got.Data)
	}
	p1.stop()
	c1.close()

	p2 := startPortablefsdProcess(t, bin, stateDir, "pfsd-history2")
	var revived attachStatus
	controlJSON(t, p2.hc, http.MethodGet, "/v1/attaches/"+ref1, nil, http.StatusOK, &revived)
	if revived.State != "degraded" {
		t.Fatalf("revived status=%+v, want degraded credential-pending before re-attach", revived)
	}
	ref2 := ensureAttachWithPolicyOptions(t, p2.hc, authority, "vol-history", "main", "/Volumes/History", "writeback", opts)
	if ref2 != ref1 {
		t.Fatalf("restart ref=%q want %q", ref2, ref1)
	}
	c2 := dialPFS(t, p2.cfg.FrontendSocket)
	defer c2.close()
	c2.call(&pfslocal.Hello{ProtocolMajor: 1})
	res2 := c2.call(&pfslocal.ResolveRequest{AttachRef: ref2}).(*pfslocal.ResolveReply)
	var lr *pfslocal.LookupReply
	lookupDeadline := time.Now().Add(20 * time.Second)
	for {
		body, er := c2.callMaybe(&pfslocal.LookupRequest{Dir: res2.Root, Name: []byte("durability.txt")})
		if er == nil {
			lr = body.(*pfslocal.LookupReply)
			break
		}
		if time.Now().After(lookupDeadline) {
			t.Fatalf("durability.txt never recovered: errno=%d", er.Errno)
		}
		time.Sleep(100 * time.Millisecond)
	}
	op := c2.call(&pfslocal.OpenRequest{Item: lr.Attr.Item, Mode: pfslocal.OpenModeRead}).(*pfslocal.OpenReply)
	got := c2.call(&pfslocal.ReadRequest{Handle: op.Handle, Length: 64}).(*pfslocal.ReadReply)
	if string(got.Data) != "survives" {
		t.Fatalf("post-restart read=%q want survives", got.Data)
	}
}

func TestDaemonDeletePurgesAttachPersistence(t *testing.T) {
	authority := serveAuthority(t)
	bin := buildPortablefsdTestBinary(t)
	stateDir, err := os.MkdirTemp("", "pfsd-delete-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stateDir) })

	p1 := startPortablefsdProcess(t, bin, stateDir, "pfsd-delete1")
	ref := ensureAttachWithPolicy(t, p1.hc, authority, "vol-delete", "main", "/Volumes/Delete", "writethrough")
	data, err := os.ReadFile(attachRegistryPath(stateDir))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(ref)) {
		t.Fatalf("registry does not contain ref %q: %s", ref, data)
	}
	if bytes.Contains(data, []byte("authToken")) || bytes.Contains(data, []byte("renewed")) {
		t.Fatalf("registry persisted credentials: %s", data)
	}
	controlJSON(t, p1.hc, http.MethodPost, "/v1/attaches/"+ref+"/unmount", nil, http.StatusNoContent, nil)
	data, err = os.ReadFile(attachRegistryPath(stateDir))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(ref)) {
		t.Fatalf("registry still contains deleted ref %q: %s", ref, data)
	}
	p1.stop()

	p2 := startPortablefsdProcess(t, bin, stateDir, "pfsd-delete2")
	c := dialPFS(t, p2.cfg.FrontendSocket)
	defer c.close()
	c.call(&pfslocal.Hello{ProtocolMajor: 1})
	if er := c.callErr(&pfslocal.ResolveRequest{AttachRef: ref}); er.Errno != darwinENOENT {
		t.Fatalf("deleted resolve errno=%d want ENOENT", er.Errno)
	}
}

func TestDaemonCorruptAttachRegistryFailsClosed(t *testing.T) {
	for name, body := range map[string]string{
		"malformed": `{"version":2,"attaches":[`,
		"mixed valid and invalid": `{"version":2,"attaches":[
			{"ref":"att_AAAAAAAAAAAAAAAAAAAAAA","volumeId":"vol-good","branch":"main","mountPath":"/Volumes/Good","authorityUrl":"127.0.0.1:1","dataPlaneTransport":"plaintext","options":{},"identityEpoch":1},
			{"ref":"att_bad","volumeId":"vol-bad","branch":"main","mountPath":"/Volumes/Bad","authorityUrl":"127.0.0.1:1","dataPlaneTransport":"plaintext","options":{},"identityEpoch":1}
		]}`,
	} {
		t.Run(name, func(t *testing.T) {
			stateDir := privateTestDir(t)
			if err := os.WriteFile(attachRegistryPath(stateDir), []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			socketDir := privateTestDir(t)
			server := NewServer(Config{
				FrontendSocket: filepath.Join(socketDir, "frontend.sock"),
				ControlSocket:  filepath.Join(socketDir, "control.sock"),
				StateDir:       stateDir,
			})
			err := server.Run(context.Background())
			if err == nil || !strings.Contains(err.Error(), "strict persisted attach inventory") {
				t.Fatalf("Run error = %v, want strict persisted attach inventory refusal", err)
			}
			if server.registry == nil {
				t.Fatal("strict inventory was not initialized after singleton ownership")
			}
			if _, statErr := os.Lstat(filepath.Join(socketDir, "control.sock")); !os.IsNotExist(statErr) {
				t.Fatalf("daemon published control socket despite corrupt registry: %v", statErr)
			}
		})
	}
}

func waitEvent(t *testing.T, conn net.Conn) {
	t.Helper()
	waitInvalidation(t, conn, func(inv *pfslocal.Invalidation) bool { return inv.NamespaceChanged })
}

func waitInvalidation(t *testing.T, conn net.Conn, want func(*pfslocal.Invalidation) bool) *pfslocal.Invalidation {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	for {
		env, err := pfslocal.ReadFrame(conn)
		if err != nil {
			t.Fatalf("no matching invalidation event: %v", err)
		}
		if env.RequestID != 0 {
			continue
		}
		if ev, ok := env.Body.(*pfslocal.Event); ok {
			if inv, ok := ev.Kind.(*pfslocal.Invalidation); ok && want(inv) {
				return inv
			}
		}
	}
}

func stringsJoin(v []string) string {
	if len(v) == 0 {
		return ""
	}
	out := v[0]
	for _, s := range v[1:] {
		out += "," + s
	}
	return out
}

// newManagedTestFS opens the file-backed PFJ3 entry log at walPath and builds
// the MANAGED workfs over it — the only generation a v5 server serves.
func newManagedTestFS(t testing.TB, blobs content.BlobReader, walPath string) *workfs.FS {
	t.Helper()
	w, err := wal.Open(walPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close() })
	flog, err := pfj3.NewFileEntryLog(w)
	if err != nil {
		t.Fatal(err)
	}
	fs, err := workfs.NewManaged(nil, blobs, flog)
	if err != nil {
		t.Fatal(err)
	}
	return fs
}
