package main

import (
	"os/exec"
	"testing"
	"time"
)

func TestStartFsdReportsAndReapsEarlyExit(t *testing.T) {
	bin, err := exec.LookPath("true")
	if err != nil {
		t.Skip("true executable is unavailable")
	}
	started := time.Now()
	p, err := startFsd(bin, t.TempDir())
	if err == nil {
		p.stop()
		t.Fatal("early-exit daemon unexpectedly became ready")
	}
	if elapsed := time.Since(started); elapsed > 2*time.Second {
		t.Fatalf("early-exit daemon took %v to report", elapsed)
	}
	if p.cmd != nil || p.waitCh != nil {
		t.Fatal("early-exit daemon retained an unreaped process")
	}
}
