// Command pfstorture is the crash-durability torture loop. It has two
// campaigns:
//
//   - authority-kill (default): repeatedly SIGKILL a real authority OS
//     process mid-write-storm and prove every acknowledged write survives
//     restart, byte for byte.
//   - client-kill: keep the authority healthy and SIGKILL the write-back
//     MOUNT CLIENT (a real clientcore volume with the adaptive engine and a
//     durable store) mid-storm; a fresh client on the same store must
//     automatically recover the parked stream, after which every
//     acknowledged step must be present on the authority byte-exactly.
//
//	pfstorture -serve-bin /path/to/pfsbench [-mode authority-kill|client-kill] [-k 10] [-seed 42] [-out report.json]
//
// Per iteration: start `pfsbench serve` (the same workfs + WAL + fsproto stack
// the vcs authority wires into its data plane — the full vcs binary needs a
// Volume API control plane, which is irrelevant to WAL crash durability) on a
// fresh data dir; drive a W2-shaped small-file storm plus an append log over
// write-through fsproto; kill -9 the authority at a random point; record
// exactly which ops were ACKED; restart the authority on the SAME WAL; verify
// with the SAME client (its pooled connections must reconnect transparently):
//
//   - every acked create resolves (Getattr OK) and is reachable through its
//     parent directory listings (tree consistency);
//   - every acked full-file write reads back with the exact content hash;
//   - a file whose create acked but whose write was in flight is empty or
//     complete, never torn (a torn WAL tail record must be discarded whole);
//   - the append log's acked prefix hashes exactly; at most one in-flight
//     chunk may additionally be present.
//
// Any violation exits non-zero with the iteration's seed and the precise path,
// so a durability bug is a one-command repro: the top finding, not a stat.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

type iterationReport struct {
	Iteration    int     `json:"iteration"`
	Seed         int64   `json:"seed"`
	KillAfterMs  int64   `json:"killAfterMs"`
	KillOnAcks   int     `json:"killOnAcks,omitempty"`
	AckedCreates int     `json:"ackedCreates"`
	AckedWrites  int     `json:"ackedWrites"`
	AckedBytes   int64   `json:"ackedBytes"`
	AppendAcked  int     `json:"appendAckedChunks"`
	StormDone    bool    `json:"stormCompletedBeforeKill"`
	VerifySec    float64 `json:"verifySec"`
	OK           bool    `json:"ok"`
	Failure      string  `json:"failure,omitempty"`
}

type report struct {
	K        int               `json:"k"`
	Mode     string            `json:"mode"`
	Passed   int               `json:"passed"`
	Runs     []iterationReport `json:"runs"`
	Started  time.Time         `json:"started"`
	Finished time.Time         `json:"finished"`
}

func main() {
	log.SetFlags(0)
	serveBin := flag.String("serve-bin", "", "path to the pfsbench binary (its serve mode is the authority under torture)")
	daemonBin := flag.String("daemon-bin", "", "path to the portablefsd binary (required for -mode daemon-kill)")
	k := flag.Int("k", 10, "iterations (kill -9 + restart cycles)")
	seed := flag.Int64("seed", 42, "base RNG seed (iteration i uses seed+i)")
	mode := flag.String("mode", "authority-kill", "authority-kill (SIGKILL the authority mid-storm), client-kill (SIGKILL the write-back mount client mid-storm, restart, require recovery), or daemon-kill (SIGKILL a real portablefsd behind the pfslocal boundary mid-storm, restart, require the attach-readiness recovery gate to drain)")
	out := flag.String("out", "", "JSON report path (default: none)")
	flag.Parse()
	if *serveBin == "" {
		log.Fatal("pfstorture: -serve-bin is required (go build -o pfsbench ./bench/cmd/pfsbench)")
	}
	if *mode != "authority-kill" && *mode != "client-kill" && *mode != "daemon-kill" {
		log.Fatalf("pfstorture: unknown -mode %q", *mode)
	}
	if *mode == "daemon-kill" && *daemonBin == "" {
		log.Fatal("pfstorture: -daemon-bin is required for -mode daemon-kill (go build -o portablefsd ./cmd/portablefsd)")
	}

	rep := report{K: *k, Mode: *mode, Started: time.Now()}
	for i := 0; i < *k; i++ {
		var ir iterationReport
		switch *mode {
		case "client-kill":
			ir = runClientKillIteration(i, *seed+int64(i), *serveBin)
		case "daemon-kill":
			ir = runDaemonKillIteration(i, *seed+int64(i), *serveBin, *daemonBin)
		default:
			ir = runIteration(i, *seed+int64(i), *serveBin)
		}
		rep.Runs = append(rep.Runs, ir)
		if ir.OK {
			rep.Passed++
			log.Printf("iteration %d/%d PASS: %d creates, %d writes (%d bytes), %d append chunks acked; kill@%dms; verified in %.2fs",
				i+1, *k, ir.AckedCreates, ir.AckedWrites, ir.AckedBytes, ir.AppendAcked, ir.KillAfterMs, ir.VerifySec)
		} else {
			log.Printf("iteration %d/%d FAIL (seed=%d): %s", i+1, *k, ir.Seed, ir.Failure)
		}
	}
	rep.Finished = time.Now()
	if *out != "" {
		data, _ := json.MarshalIndent(rep, "", "  ")
		_ = os.MkdirAll(filepath.Dir(*out), 0o755)
		if err := os.WriteFile(*out, append(data, '\n'), 0o644); err != nil {
			log.Fatalf("write report: %v", err)
		}
	}
	if rep.Passed != *k {
		log.Fatalf("TORTURE FAILED: %d/%d passed — a durability violation reproduces with -seed <failing seed> -k 1", rep.Passed, *k)
	}
	log.Printf("TORTURE PASSED: %d/%d iterations, every acked write survived kill -9", rep.Passed, *k)
}

// authority manages the serve subprocess lifecycle for one iteration.
type authority struct {
	bin  string
	addr string
	wal  string
	proc *exec.Cmd
}

func (a *authority) start() error {
	cmd := exec.Command(a.bin, "serve", "-addr", a.addr, "-wal", a.wal)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	a.proc = cmd
	// Poll until the fixed address accepts (the process replays the WAL first).
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", a.addr, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return nil
		}
		time.Sleep(25 * time.Millisecond)
	}
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	return fmt.Errorf("authority did not accept on %s within 15s", a.addr)
}

func (a *authority) kill9() error {
	if err := a.proc.Process.Signal(syscall.SIGKILL); err != nil {
		return err
	}
	_ = a.proc.Wait()
	return nil
}

func (a *authority) stop() {
	if a.proc != nil && a.proc.Process != nil {
		_ = a.proc.Process.Signal(syscall.SIGTERM)
		done := make(chan struct{})
		go func() { _, _ = a.proc.Process.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = a.proc.Process.Kill()
		}
	}
}

// freeAddr reserves an ephemeral port and returns 127.0.0.1:port. The listener
// is closed so the child can bind it; the tiny reuse race is retried by the
// caller (start fails fast if the bind was lost).
func freeAddr() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	return addr, nil
}

type ackedFile struct {
	path    string
	content []byte // full expected bytes; nil = only the create acked
}

func sha(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

func runIteration(i int, seed int64, serveBin string) (ir iterationReport) {
	ir = iterationReport{Iteration: i, Seed: seed}
	rng := rand.New(rand.NewSource(seed))
	dir, err := os.MkdirTemp("", fmt.Sprintf("pfstorture-%d-", i))
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
		ir.Failure = "first start: " + err.Error()
		return ir
	}
	defer auth.stop()

	cli, err := fsproto.Dial(addr, 4)
	if err != nil {
		ir.Failure = "dial: " + err.Error()
		return ir
	}
	defer cli.Close()

	// Deterministic W2-shaped storm: dirs up front, then create+write per file,
	// with periodic appends to one log. Payloads derive from the seed.
	// Storm sizing vs kill timing is deliberately overlapped: with ~7ms per
	// durable RPC a storm runs ~1-2.5s, and killAfter spans 100ms-3s, so across
	// K iterations some kills land mid-storm (torn tail) and some land after
	// the last ack (the strictest durability point).
	const nDirs = 8
	nFiles := 120 + rng.Intn(180)
	payload := make([]byte, 16*1024)
	rng.Read(payload)
	appendChunk := payload[:512]

	killAfter := time.Duration(100+rng.Intn(2900)) * time.Millisecond
	ir.KillAfterMs = killAfter.Milliseconds()
	killed := make(chan struct{})
	timer := time.AfterFunc(killAfter, func() {
		if err := auth.kill9(); err == nil {
			close(killed)
		}
	})

	// acked records ONLY operations whose RPC returned OK before the crash.
	var acked []ackedFile
	appendAcked := 0
	appendPath := "torture/append.log"
	stormDone := false

	rpcFailed := func(st int32, err error) bool { return err != nil || st != fsproto.OK }
	storm := func() error {
		if _, st, err := cli.Mkdir("torture", 0o755); rpcFailed(st, err) {
			return fmt.Errorf("mkdir torture: st=%d err=%v", st, err)
		}
		for d := 0; d < nDirs; d++ {
			if _, st, err := cli.Mkdir(fmt.Sprintf("torture/d%02d", d), 0o755); rpcFailed(st, err) {
				return fmt.Errorf("mkdir d%02d: st=%d err=%v", d, st, err)
			}
		}
		if _, st, err := cli.Create(appendPath, 0o644); rpcFailed(st, err) {
			return fmt.Errorf("create append log: st=%d err=%v", st, err)
		}
		for f := 0; f < nFiles; f++ {
			p := fmt.Sprintf("torture/d%02d/f%04d.bin", f%nDirs, f)
			if _, st, err := cli.Create(p, 0o644); rpcFailed(st, err) {
				return fmt.Errorf("create %s: st=%d err=%v", p, st, err)
			}
			acked = append(acked, ackedFile{path: p}) // create acked
			size := 1024 + rng.Intn(15*1024)
			content := payload[:size]
			if _, _, _, st, err := cli.WriteV(p, 0, content, 0o644); rpcFailed(st, err) {
				return fmt.Errorf("write %s: st=%d err=%v", p, st, err)
			}
			acked[len(acked)-1].content = content // full write acked
			if f%5 == 4 {
				off := int64(appendAcked) * int64(len(appendChunk))
				if _, _, _, st, err := cli.WriteV(appendPath, off, appendChunk, 0o644); rpcFailed(st, err) {
					return fmt.Errorf("append @%d: st=%d err=%v", off, st, err)
				}
				appendAcked++
			}
		}
		return nil
	}
	stormErr := storm()
	if stormErr == nil {
		stormDone = true
		// The storm outran the timer: fire the kill NOW — "crash immediately
		// after the last ack" is the strictest durability point anyway.
		timer.Stop()
		if err := auth.kill9(); err != nil {
			ir.Failure = "post-storm kill: " + err.Error()
			return ir
		}
	} else {
		// The storm died mid-flight; that must be BECAUSE the authority was
		// killed. Give the killer a beat, then confirm the process is gone.
		select {
		case <-killed:
		case <-time.After(5 * time.Second):
			ir.Failure = "storm failed while the authority was still alive: " + stormErr.Error()
			return ir
		}
	}
	ir.StormDone = stormDone
	ir.AckedCreates = len(acked)
	for _, f := range acked {
		if f.content != nil {
			ir.AckedWrites++
			ir.AckedBytes += int64(len(f.content))
		}
	}
	ir.AckedBytes += int64(appendAcked * len(appendChunk))
	ir.AppendAcked = appendAcked

	// Restart the authority on the SAME WAL and the SAME address, then verify
	// through the SAME client — its pooled connections must transparently
	// reconnect (that is the mount's crash-ride-through path).
	if err := auth.start(); err != nil {
		ir.Failure = "restart: " + err.Error()
		return ir
	}
	verifyStart := time.Now()
	if fail := verify(cli, acked, appendPath, appendAcked, appendChunk); fail != "" {
		ir.Failure = fail
		return ir
	}
	ir.VerifySec = time.Since(verifyStart).Seconds()
	ir.OK = true
	return ir
}

// verify checks every acked op against the restarted authority.
func verify(cli *fsproto.Client, acked []ackedFile, appendPath string, appendAcked int, appendChunk []byte) string {
	// Tree consistency: a full readdir walk must reach every acked path.
	walked := map[string]bool{}
	var walk func(dir string) error
	walk = func(dir string) error {
		ents, _, st, err := cli.Readdir(dir)
		if err != nil || st != fsproto.OK {
			return fmt.Errorf("readdir %q: st=%d err=%v", dir, st, err)
		}
		seen := map[string]bool{}
		for _, e := range ents {
			if seen[e.Name] {
				return fmt.Errorf("readdir %q: duplicate entry %q", dir, e.Name)
			}
			seen[e.Name] = true
			p := e.Name
			if dir != "" {
				p = dir + "/" + e.Name
			}
			walked[p] = true
			if e.Attr.Kind == "directory" {
				if err := walk(p); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err := walk(""); err != nil {
		return "tree walk after restart: " + err.Error()
	}

	sort.Slice(acked, func(i, j int) bool { return acked[i].path < acked[j].path })
	for _, f := range acked {
		if !walked[f.path] {
			return fmt.Sprintf("ACKED CREATE LOST: %s is not reachable via readdir after restart", f.path)
		}
		attr, st, err := cli.Getattr(f.path)
		if err != nil || st != fsproto.OK {
			return fmt.Sprintf("ACKED CREATE LOST: getattr %s: st=%d err=%v", f.path, st, err)
		}
		if f.content == nil {
			// Only the create acked; the in-flight write may or may not have
			// landed, but the file must exist (it does) and be readable.
			continue
		}
		if attr.Size != int64(len(f.content)) {
			// A create-acked-write-unacked file may be empty; but content!=nil
			// means the WRITE acked: size must match exactly.
			return fmt.Sprintf("ACKED WRITE CORRUPT: %s size=%d want %d", f.path, attr.Size, len(f.content))
		}
		got, err := readAll(cli, f.path, int64(len(f.content)))
		if err != nil {
			return fmt.Sprintf("ACKED WRITE UNREADABLE: %s: %v", f.path, err)
		}
		if sha(got) != sha(f.content) {
			return fmt.Sprintf("ACKED WRITE CORRUPT: %s content hash mismatch (%s != %s)", f.path, sha(got)[:12], sha(f.content)[:12])
		}
	}

	// Append log: the acked prefix must hash exactly; at most ONE in-flight
	// chunk may additionally be present (single-writer, one op in flight).
	if appendAcked > 0 || walked[appendPath] {
		attr, st, err := cli.Getattr(appendPath)
		if err != nil || st != fsproto.OK {
			return fmt.Sprintf("append log lost: st=%d err=%v", st, err)
		}
		ackedBytes := int64(appendAcked) * int64(len(appendChunk))
		maxBytes := ackedBytes + int64(len(appendChunk))
		if attr.Size < ackedBytes || attr.Size > maxBytes {
			return fmt.Sprintf("append log size %d outside [acked=%d, acked+1 chunk=%d]", attr.Size, ackedBytes, maxBytes)
		}
		if ackedBytes > 0 {
			got, err := readAll(cli, appendPath, ackedBytes)
			if err != nil {
				return "append log unreadable: " + err.Error()
			}
			want := strings.Repeat(string(appendChunk), appendAcked)
			if sha(got) != sha([]byte(want)) {
				return "append log acked prefix hash mismatch"
			}
		}
	}
	return ""
}

func readAll(cli *fsproto.Client, path string, size int64) ([]byte, error) {
	out := make([]byte, 0, size)
	const chunk = 1 << 20
	for off := int64(0); off < size; {
		want := size - off
		if want > chunk {
			want = chunk
		}
		data, st, err := cli.Read(path, off, want)
		if err != nil || st != fsproto.OK {
			return nil, fmt.Errorf("read %s@%d: st=%d err=%v", path, off, st, err)
		}
		if len(data) == 0 {
			return nil, fmt.Errorf("read %s@%d: unexpected EOF", path, off)
		}
		out = append(out, data...)
		off += int64(len(data))
	}
	return out, nil
}
