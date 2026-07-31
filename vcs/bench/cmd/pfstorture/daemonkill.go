package main

// The daemon-kill campaign: the REAL portablefsd process — the daemon that
// owns the write-back engine behind the FSKit/pfslocal boundary — is
// SIGKILLed mid-storm while the authority stays healthy. A restarted daemon
// re-attaches the same (volume, branch) store; the attach-readiness gate
// must drain the parked stream BEFORE the attach reports ready, after which
// every step the dead daemon acknowledged over the pfslocal wire must be
// present on the authority byte-exactly, nothing duplicated.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/bench/internal/tortureplan"
	"github.com/steerlabs/portablefs/vcs/internal/daemonctl"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// pfsWire is a minimal pfslocal frontend client with error returns (the
// storm must survive the daemon dying mid-call).
type pfsWire struct {
	conn net.Conn
	next uint64
}

func dialPFSWire(sock string) (*pfsWire, error) {
	conn, err := net.Dial("unix", sock)
	if err != nil {
		return nil, err
	}
	return &pfsWire{conn: conn}, nil
}

func (c *pfsWire) close() { _ = c.conn.Close() }

func pfsWireOperationID(body any, requestID uint64) uint64 {
	switch body.(type) {
	case *pfslocal.MkdirRequest,
		*pfslocal.CreateRequest,
		*pfslocal.WriteRequest:
		return requestID
	default:
		return 0
	}
}

func (c *pfsWire) call(body any) (any, error) {
	c.next++
	id := c.next
	operationID := pfsWireOperationID(body, id)
	if err := pfslocal.WriteFrame(c.conn, &pfslocal.Envelope{
		RequestID:   id,
		OperationID: operationID,
		Body:        body,
	}); err != nil {
		return nil, err
	}
	for {
		env, err := pfslocal.ReadFrame(c.conn)
		if err != nil {
			return nil, err
		}
		if env.RequestID != id {
			continue // events/broadcasts
		}
		if env.PublicationAckRequired {
			if operationID == 0 {
				return nil, fmt.Errorf("reply for request %d requires publication acknowledgement without an operation id", id)
			}
			if err := pfslocal.WriteFrame(c.conn, &pfslocal.Envelope{
				RequestID: 0,
				Body: &pfslocal.PublicationAck{
					OperationID: operationID,
				},
			}); err != nil {
				return nil, fmt.Errorf("acknowledge operation %d publication: %w", id, err)
			}
		}
		if er, ok := env.Body.(*pfslocal.ErrorReply); ok {
			return nil, fmt.Errorf("pfslocal errno %d", er.Errno)
		}
		return env.Body, nil
	}
}

// fsdProc is one portablefsd OS process on fixed sockets + state dir.
type fsdProc struct {
	bin, frontend, control, state string
	cmd                           *exec.Cmd
	waitCh                        chan error
	hc                            *http.Client
}

func startFsd(bin, dir string) (*fsdProc, error) {
	p := &fsdProc{
		bin:      bin,
		frontend: filepath.Join(dir, "run", "pfs.sock"),
		control:  filepath.Join(dir, "run", "control.sock"),
		state:    filepath.Join(dir, "state"),
	}
	if err := os.MkdirAll(filepath.Join(dir, "run"), 0o700); err != nil {
		return nil, err
	}
	p.hc = &http.Client{
		Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", p.control)
		}},
		Timeout: 90 * time.Second,
	}
	return p, p.start()
}

func (p *fsdProc) start() error {
	if p.cmd != nil {
		return fmt.Errorf("portablefsd process is already started")
	}
	p.cmd = exec.Command(p.bin,
		"-frontend-socket", p.frontend,
		"-control-socket", p.control,
		"-state-dir", p.state)
	p.cmd.Stderr = os.Stderr
	if err := p.cmd.Start(); err != nil {
		p.cmd = nil
		return err
	}
	p.waitCh = make(chan error, 1)
	go func(cmd *exec.Cmd, waitCh chan<- error) {
		waitCh <- cmd.Wait()
	}(p.cmd, p.waitCh)
	deadline := time.Now().Add(15 * time.Second)
	for {
		select {
		case waitErr := <-p.waitCh:
			p.cmd = nil
			p.waitCh = nil
			if waitErr == nil {
				return fmt.Errorf("portablefsd exited without publishing both sockets")
			}
			return fmt.Errorf("portablefsd exited before publishing both sockets: %w", waitErr)
		default:
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			p.kill()
			return fmt.Errorf("portablefsd sockets never came up")
		}
		dialTimeout := min(250*time.Millisecond, remaining)
		if conn, err := net.DialTimeout("unix", p.control, dialTimeout); err == nil {
			_ = conn.Close()
			remaining = time.Until(deadline)
			if remaining <= 0 {
				p.kill()
				return fmt.Errorf("portablefsd sockets never came up")
			}
			if conn2, err2 := net.DialTimeout("unix", p.frontend, min(250*time.Millisecond, remaining)); err2 == nil {
				_ = conn2.Close()
				return nil
			}
		}
		time.Sleep(min(50*time.Millisecond, max(time.Duration(0), time.Until(deadline))))
	}
}

func (p *fsdProc) kill() {
	if p.cmd == nil || p.cmd.Process == nil || p.waitCh == nil {
		return
	}
	_ = p.cmd.Process.Signal(syscall.SIGKILL)
	<-p.waitCh
	p.cmd = nil
	p.waitCh = nil
}

func (p *fsdProc) stop() {
	if p.cmd == nil || p.cmd.Process == nil || p.waitCh == nil {
		return
	}
	_ = p.cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-p.waitCh:
	case <-time.After(60 * time.Second):
		_ = p.cmd.Process.Signal(syscall.SIGKILL)
		<-p.waitCh
	}
	p.cmd = nil
	p.waitCh = nil
}

func (p *fsdProc) controlJSON(method, path string, body any, out any) error {
	var r io.Reader
	if body != nil {
		buf := new(bytes.Buffer)
		if err := json.NewEncoder(buf).Encode(body); err != nil {
			return err
		}
		r = buf
	}
	req, err := http.NewRequest(method, "http://portablefsd"+path, r)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set(daemonctl.ControlProtocolHeader, fmt.Sprint(daemonctl.ControlProtocolVersion))
	resp, err := p.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		data, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("%s %s: status %d: %s", method, path, resp.StatusCode, data)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (p *fsdProc) ensureAttach(authority string) (string, error) {
	var out struct {
		AttachRef string `json:"attachRef"`
	}
	err := p.controlJSON(http.MethodPost, "/v1/attaches", map[string]any{
		"volumeId": "vol-torture", "branch": "main",
		"authorityUrl": authority, "dataPlaneTransport": "plaintext",
		"mountPath": "/Volumes/Torture",
		"options":   map[string]any{"diskCacheMb": 64},
	}, &out)
	if err != nil {
		return "", err
	}
	if out.AttachRef == "" {
		return "", fmt.Errorf("attach reply carried no ref")
	}
	return out.AttachRef, nil
}

// waitRecovered polls the attach status until no parked WAL and no pending
// write-back remains (the restarted daemon's attach gate drained it).
func (p *fsdProc) waitRecovered(ref string, deadline time.Time) error {
	for {
		var out struct {
			State     string `json:"state"`
			WriteBack *struct {
				PendingRecords int `json:"pendingRecords"`
				ParkedWALs     []struct {
					Records int `json:"records"`
				} `json:"parkedWals"`
			} `json:"writeBack"`
		}
		err := p.controlJSON(http.MethodGet, "/v1/attaches/"+ref, nil, &out)
		if err == nil {
			parked := 0
			pending := 0
			if out.WriteBack != nil {
				pending = out.WriteBack.PendingRecords
				for _, w := range out.WriteBack.ParkedWALs {
					parked += w.Records
				}
			}
			if out.State != "degraded" && parked == 0 && pending == 0 {
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("recovery did not drain (err=%v)", err)
		}
		time.Sleep(100 * time.Millisecond)
	}
}

func driveDaemonKillStorm(frontend, ref string, seed int64, note func(string)) error {
	pfs, err := dialPFSWire(frontend)
	if err != nil {
		return fmt.Errorf("dial frontend: %w", err)
	}
	defer pfs.close()
	if _, err := pfs.call(&pfslocal.Hello{
		ProtocolMajor: pfslocal.ProtocolMajor,
		ProtocolMinor: pfslocal.ProtocolMinor,
		ClientName:    "pfstorture-dk",
		ClientVersion: "test",
	}); err != nil {
		return fmt.Errorf("hello: %w", err)
	}
	res, err := pfs.call(&pfslocal.ResolveRequest{AttachRef: ref})
	if err != nil {
		return fmt.Errorf("resolve attach: %w", err)
	}
	resolve, ok := res.(*pfslocal.ResolveReply)
	if !ok {
		return fmt.Errorf("resolve returned %T", res)
	}
	root := resolve.Root
	plan := tortureplan.New(seed)
	mkdir := func(parent pfslocal.Item, name string) (pfslocal.Item, error) {
		reply, err := pfs.call(&pfslocal.MkdirRequest{Dir: parent, Name: []byte(name), Mode: 0o755})
		if err != nil {
			return pfslocal.Item{}, err
		}
		out, ok := reply.(*pfslocal.MkdirReply)
		if !ok {
			return pfslocal.Item{}, fmt.Errorf("mkdir returned %T", reply)
		}
		return out.Attr.Item, nil
	}
	tortureRoot, err := mkdir(root, "torture")
	if err != nil {
		return fmt.Errorf("mkdir torture root: %w", err)
	}
	dirItems := map[string]pfslocal.Item{}
	for _, dir := range plan.Dirs {
		item, err := mkdir(tortureRoot, strings.TrimPrefix(dir, "torture/"))
		if err != nil {
			return fmt.Errorf("mkdir %s: %w", dir, err)
		}
		dirItems[dir] = item
		note("ACK dir " + dir)
	}
	reply, err := pfs.call(&pfslocal.CreateRequest{Dir: tortureRoot, Name: []byte("append.log"), Mode: 0o644})
	if err != nil {
		return fmt.Errorf("create append log: %w", err)
	}
	created, ok := reply.(*pfslocal.CreateReply)
	if !ok {
		return fmt.Errorf("create append log returned %T", reply)
	}
	logHandle := created.Handle
	note("ACK logcreate")
	appends := 0
	for fi, file := range plan.Files {
		dir := filepath.Dir(file.Path)
		name := filepath.Base(file.Path)
		reply, err := pfs.call(&pfslocal.CreateRequest{Dir: dirItems[dir], Name: []byte(name), Mode: 0o644})
		if err != nil {
			return fmt.Errorf("create %s: %w", file.Path, err)
		}
		created, ok := reply.(*pfslocal.CreateReply)
		if !ok {
			return fmt.Errorf("create %s returned %T", file.Path, reply)
		}
		note(fmt.Sprintf("ACK create %d", fi))
		if _, err := pfs.call(&pfslocal.WriteRequest{Handle: created.Handle, Offset: 0, Data: file.Content}); err != nil {
			return fmt.Errorf("write %s: %w", file.Path, err)
		}
		note(fmt.Sprintf("ACK write %d", fi))
		if _, err := pfs.call(&pfslocal.CloseRequest{Handle: created.Handle}); err != nil {
			return fmt.Errorf("close %s: %w", file.Path, err)
		}
		if fi%plan.AppendEvery == plan.AppendEvery-1 {
			offset := uint64(appends) * uint64(len(plan.AppendChunk))
			if _, err := pfs.call(&pfslocal.WriteRequest{Handle: logHandle, Offset: offset, Data: plan.AppendChunk}); err != nil {
				return fmt.Errorf("append chunk %d: %w", appends, err)
			}
			appends++
			note(fmt.Sprintf("ACK append %d", appends))
		}
	}
	note("DONE")
	return nil
}

func runDaemonKillIteration(i int, seed int64, serveBin, daemonBin string) (ir iterationReport) {
	ir = iterationReport{Iteration: i, Seed: seed}
	rng := rand.New(rand.NewSource(seed ^ 0xdae11))
	dir, err := os.MkdirTemp("", fmt.Sprintf("pfstorture-dk-%d-", i))
	if err != nil {
		ir.Failure = err.Error()
		return ir
	}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		ir.Failure = "canonicalize work directory: " + err.Error()
		return ir
	}
	defer os.RemoveAll(dir)

	addr, err := freeAddr()
	if err != nil {
		ir.Failure = err.Error()
		return ir
	}
	auth := &authority{bin: serveBin, addr: addr, wal: filepath.Join(dir, "authority.wal")}
	if err := auth.start(); err != nil {
		ir.Failure = "authority start: " + err.Error()
		return ir
	}
	defer auth.stop()

	fsd, err := startFsd(daemonBin, dir)
	if err != nil {
		ir.Failure = "portablefsd start: " + err.Error()
		return ir
	}
	defer fsd.stop()
	ref, err := fsd.ensureAttach(addr)
	if err != nil {
		ir.Failure = "attach: " + err.Error()
		return ir
	}

	// The killer arms either a wall-clock timer or an ack-count trigger, the
	// same mid-ack-phase strategy as the client-kill campaign.
	killOnAcks := 0
	killAfter := time.Duration(30+rng.Intn(700)) * time.Millisecond
	if i%2 == 1 {
		killOnAcks = 1 + rng.Intn(250)
		killAfter = 10 * time.Second
	}
	ir.KillAfterMs = killAfter.Milliseconds()
	ir.KillOnAcks = killOnAcks

	acked := &ackState{creates: map[int]bool{}, writes: map[int]bool{}}
	var ackedN int
	var mu sync.Mutex
	killNow := make(chan struct{})
	var killOnce sync.Once
	note := func(line string) {
		mu.Lock()
		acked.apply(line)
		ackedN++
		n := ackedN
		mu.Unlock()
		if killOnAcks > 0 && n >= killOnAcks {
			killOnce.Do(func() { close(killNow) })
		}
	}

	stormDone := make(chan error, 1)
	go func() {
		stormDone <- driveDaemonKillStorm(fsd.frontend, ref, seed, note)
	}()

	timer := time.NewTimer(killAfter)
	stormFinished := false
	var stormErr error
	select {
	case <-timer.C:
	case <-killNow:
		timer.Stop()
	case stormErr = <-stormDone:
		stormFinished = true
		timer.Stop()
	}
	fsd.kill()
	if !stormFinished {
		stormErr = <-stormDone
	}
	if stormFinished && stormErr != nil {
		ir.Failure = "storm stopped before kill: " + stormErr.Error()
		return ir
	}

	mu.Lock()
	ir.StormDone = acked.done
	ir.AckedCreates = len(acked.creates)
	ir.AckedWrites = len(acked.writes)
	ir.AppendAcked = acked.appends
	mu.Unlock()

	// Restart the daemon on the SAME state dir: the attach-readiness gate
	// must drain the parked stream before the attach serves.
	if err := fsd.start(); err != nil {
		ir.Failure = "portablefsd restart: " + err.Error()
		return ir
	}
	ref2, err := fsd.ensureAttach(addr)
	if err != nil {
		ir.Failure = "re-attach: " + err.Error()
		return ir
	}
	if err := fsd.waitRecovered(ref2, time.Now().Add(90*time.Second)); err != nil {
		ir.Failure = "recovery: " + err.Error()
		return ir
	}

	verifyStart := time.Now()
	if fail := verifyClientKill(addr, seed, acked, &ir); fail != "" {
		ir.Failure = fail
		return ir
	}
	ir.VerifySec = time.Since(verifyStart).Seconds()
	ir.OK = true
	return ir
}
