package main

// The client-kill campaign: the authority stays healthy while the write-back
// MOUNT CLIENT (pfsbench wbstorm — a real clientcore volume with the adaptive
// engine and a durable store) is SIGKILLed mid-storm. A fresh client on the
// same store (pfsbench wbrecover) must automatically discover the parked
// stream, rebind it, and drain — after which every step the dead client
// acknowledged (its ACK lines) must be present on the authority byte-exactly,
// with nothing duplicated.

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/bench/internal/tortureplan"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// ackState collects the child's acknowledged plan steps (guarded: the scanner
// goroutine appends while the killer decides timing).
type ackState struct {
	mu       sync.Mutex
	dirs     int
	creates  map[int]bool
	writes   map[int]bool
	appends  int
	logMade  bool
	done     bool
}

func (a *ackState) apply(line string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	fields := strings.Fields(line)
	switch {
	case line == "DONE":
		a.done = true
	case len(fields) >= 2 && fields[0] == "ACK" && fields[1] == "logcreate":
		a.logMade = true
	case len(fields) >= 2 && fields[0] == "ACK" && fields[1] == "dir":
		a.dirs++
	case len(fields) >= 3 && fields[0] == "ACK":
		n, err := strconv.Atoi(fields[2])
		if err != nil {
			return
		}
		switch fields[1] {
		case "create":
			a.creates[n] = true
		case "write":
			a.writes[n] = true
		case "append":
			a.appends = n
		}
	}
}

func runClientKillIteration(i int, seed int64, serveBin string) (ir iterationReport) {
	ir = iterationReport{Iteration: i, Seed: seed}
	rng := rand.New(rand.NewSource(seed ^ 0x5eed))
	dir, err := os.MkdirTemp("", fmt.Sprintf("pfstorture-ck-%d-", i))
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

	walDir := filepath.Join(dir, "wbstore")
	storm := exec.Command(serveBin, "wbstorm", "-addr", addr, "-wal", walDir, "-seed", strconv.FormatInt(seed, 10))
	storm.Stderr = os.Stderr
	stdout, err := storm.StdoutPipe()
	if err != nil {
		ir.Failure = err.Error()
		return ir
	}
	if err := storm.Start(); err != nil {
		ir.Failure = "storm start: " + err.Error()
		return ir
	}

	acked := &ackState{creates: map[int]bool{}, writes: map[int]bool{}}
	ackSeen := make(chan struct{}, 1)
	scanDone := make(chan struct{})
	go func() {
		defer close(scanDone)
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			acked.apply(sc.Text())
			select {
			case ackSeen <- struct{}{}:
			default:
			}
		}
	}()

	// Kill the CLIENT at a random point. Delegated acks are local (the whole
	// storm acknowledges in well under a second), so a wall-clock timer alone
	// mostly lands before the first ack or after the last. Odd iterations
	// therefore kill when a RANDOM NUMBER OF ACKS has been observed — squarely
	// mid-ack-phase, with unshipped acknowledged state guaranteed — while
	// even iterations keep the timer (covering the setup phase and the
	// immediately-after-last-ack point).
	killOnAcks := 0
	killAfter := time.Duration(3+rng.Intn(300)) * time.Millisecond
	if i%2 == 1 {
		killOnAcks = 1 + rng.Intn(300)
		killAfter = 10 * time.Second // fallback only
	}
	ir.KillAfterMs = killAfter.Milliseconds()
	ir.KillOnAcks = killOnAcks
	timer := time.NewTimer(killAfter)
wait:
	for {
		select {
		case <-timer.C:
			break wait
		case <-ackSeen:
			acked.mu.Lock()
			done, n := acked.done, len(acked.creates)+len(acked.writes)+acked.appends+acked.dirs
			acked.mu.Unlock()
			if done || (killOnAcks > 0 && n >= killOnAcks) {
				timer.Stop()
				break wait
			}
		}
	}
	if err := storm.Process.Signal(syscall.SIGKILL); err != nil {
		ir.Failure = "client kill: " + err.Error()
		return ir
	}
	_ = storm.Wait()
	<-scanDone

	acked.mu.Lock()
	ir.StormDone = acked.done
	ir.AckedCreates = len(acked.creates)
	ir.AckedWrites = len(acked.writes)
	ir.AppendAcked = acked.appends
	acked.mu.Unlock()

	// The restarted client must discover the parked stream and drain it.
	recover := exec.Command(serveBin, "wbrecover", "-addr", addr, "-wal", walDir)
	recover.Stdout = os.Stderr
	recover.Stderr = os.Stderr
	if err := recover.Run(); err != nil {
		ir.Failure = "recovery client: " + err.Error()
		return ir
	}

	// Verify every acknowledged step against the authority, write-through.
	verifyStart := time.Now()
	if fail := verifyClientKill(addr, seed, acked, &ir); fail != "" {
		ir.Failure = fail
		return ir
	}
	ir.VerifySec = time.Since(verifyStart).Seconds()
	ir.OK = true
	return ir
}

func verifyClientKill(addr string, seed int64, acked *ackState, ir *iterationReport) string {
	plan := tortureplan.New(seed)
	cli, err := fsproto.Dial(addr, 4)
	if err != nil {
		return "verify dial: " + err.Error()
	}
	defer cli.Close()

	acked.mu.Lock()
	defer acked.mu.Unlock()

	var files []ackedFile
	for i := range plan.Files {
		if !acked.creates[i] {
			continue
		}
		f := ackedFile{path: plan.Files[i].Path}
		if acked.writes[i] {
			f.content = plan.Files[i].Content
			ir.AckedBytes += int64(len(f.content))
		}
		files = append(files, f)
	}
	ir.AckedBytes += int64(acked.appends * len(plan.AppendChunk))
	appendAcked := 0
	if acked.logMade {
		appendAcked = acked.appends
	}
	return verify(cli, files, plan.AppendPath, appendAcked, plan.AppendChunk)
}
