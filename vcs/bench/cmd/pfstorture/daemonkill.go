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

func (c *pfsWire) call(body any) (any, error) {
	c.next++
	id := c.next
	if err := pfslocal.WriteFrame(c.conn, &pfslocal.Envelope{RequestID: id, Body: body}); err != nil {
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
	// A SIGKILLed daemon leaves stale socket files; a fresh bind needs them gone.
	_ = os.Remove(p.frontend)
	_ = os.Remove(p.control)
	p.cmd = exec.Command(p.bin,
		"-frontend-socket", p.frontend,
		"-control-socket", p.control,
		"-state-dir", p.state)
	p.cmd.Stderr = os.Stderr
	if err := p.cmd.Start(); err != nil {
		return err
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		if conn, err := net.Dial("unix", p.control); err == nil {
			_ = conn.Close()
			if conn2, err2 := net.Dial("unix", p.frontend); err2 == nil {
				_ = conn2.Close()
				return nil
			}
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("portablefsd sockets never came up")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (p *fsdProc) kill() {
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Signal(syscall.SIGKILL)
		_, _ = p.cmd.Process.Wait()
	}
}

func (p *fsdProc) stop() {
	if p.cmd != nil && p.cmd.Process != nil {
		_ = p.cmd.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _, _ = p.cmd.Process.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(60 * time.Second):
			_ = p.cmd.Process.Signal(syscall.SIGKILL)
		}
	}
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
		"authorityUrl": authority, "mountPath": "/Volumes/Torture",
		"options": map[string]any{"writePolicy": "writeback", "diskCacheMb": 1},
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

func runDaemonKillIteration(i int, seed int64, serveBin, daemonBin string) (ir iterationReport) {
	ir = iterationReport{Iteration: i, Seed: seed}
	rng := rand.New(rand.NewSource(seed ^ 0xdae11))
	dir, err := os.MkdirTemp("", fmt.Sprintf("pfstorture-dk-%d-", i))
	if err != nil {
		ir.Failure = err.Error()
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

	stormDone := make(chan struct{})
	go func() {
		defer close(stormDone)
		pfs, err := dialPFSWire(fsd.frontend)
		if err != nil {
			return
		}
		defer pfs.close()
		if _, err := pfs.call(&pfslocal.Hello{ProtocolMajor: 1, ClientName: "pfstorture-dk"}); err != nil {
			return
		}
		res, err := pfs.call(&pfslocal.ResolveRequest{AttachRef: ref})
		if err != nil {
			return
		}
		root := res.(*pfslocal.ResolveReply).Root
		plan := tortureplan.New(seed)
		mkdir := func(parent pfslocal.Item, name string) (pfslocal.Item, bool) {
			r, err := pfs.call(&pfslocal.MkdirRequest{Dir: parent, Name: []byte(name), Mode: 0o755})
			if err != nil {
				return pfslocal.Item{}, false
			}
			return r.(*pfslocal.MkdirReply).Attr.Item, true
		}
		tortureRoot, ok := mkdir(root, "torture")
		if !ok {
			return
		}
		dirItems := map[string]pfslocal.Item{}
		for _, d := range plan.Dirs {
			item, ok := mkdir(tortureRoot, strings.TrimPrefix(d, "torture/"))
			if !ok {
				return
			}
			dirItems[d] = item
			note("ACK dir " + d)
		}
		// The append log (offset writes at the pfslocal boundary, like FSKit).
		lr, err := pfs.call(&pfslocal.CreateRequest{Dir: tortureRoot, Name: []byte("append.log"), Mode: 0o644})
		if err != nil {
			return
		}
		logHandle := lr.(*pfslocal.CreateReply).Handle
		note("ACK logcreate")
		appends := 0
		for fi, f := range plan.Files {
			d := filepath.Dir(f.Path)
			name := filepath.Base(f.Path)
			cr, err := pfs.call(&pfslocal.CreateRequest{Dir: dirItems[d], Name: []byte(name), Mode: 0o644})
			if err != nil {
				return
			}
			note(fmt.Sprintf("ACK create %d", fi))
			h := cr.(*pfslocal.CreateReply).Handle
			if _, err := pfs.call(&pfslocal.WriteRequest{Handle: h, Offset: 0, Data: f.Content}); err != nil {
				return
			}
			note(fmt.Sprintf("ACK write %d", fi))
			if _, err := pfs.call(&pfslocal.CloseRequest{Handle: h}); err != nil {
				return
			}
			if fi%plan.AppendEvery == plan.AppendEvery-1 {
				off := uint64(appends) * uint64(len(plan.AppendChunk))
				if _, err := pfs.call(&pfslocal.WriteRequest{Handle: logHandle, Offset: off, Data: plan.AppendChunk}); err != nil {
					return
				}
				appends++
				note(fmt.Sprintf("ACK append %d", appends))
			}
		}
		note("DONE")
	}()

	timer := time.NewTimer(killAfter)
	select {
	case <-timer.C:
	case <-killNow:
		timer.Stop()
	case <-stormDone:
		timer.Stop()
	}
	fsd.kill()
	<-stormDone

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
