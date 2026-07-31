package clientcore

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// appendRecordLen mirrors the shape of the live cross-machine evidence:
// fixed-length, newline-terminated records, so a lost record shows up as a
// short file and a spliced one shows up as a wrong line length.
const appendRecordLen = 48

// appendKey is the unique identifying prefix of a record. It is a fixed
// width so a record can be keyed straight out of the durable bytes.
func appendKey(machine string, seq int) string {
	return fmt.Sprintf("%s-%06d-", machine, seq)
}

const appendKeyLen = 10

func appendRecord(t *testing.T, machine string, seq int) []byte {
	t.Helper()
	body := appendKey(machine, seq)
	if len(body) != appendKeyLen {
		t.Fatalf("record key %q is %d bytes, want %d", body, len(body), appendKeyLen)
	}
	rec := []byte(body + strings.Repeat("x", appendRecordLen-len(body)-1) + "\n")
	if len(rec) != appendRecordLen {
		t.Fatalf("record builder produced %d bytes, want %d", len(rec), appendRecordLen)
	}
	return rec
}

// verifyAppendLog asserts the durable file is exactly the wantTotal records
// that were written: no record lost, none duplicated, none torn or spliced.
func verifyAppendLog(t *testing.T, data []byte, machines []string, perMachine int) {
	t.Helper()
	wantTotal := len(machines) * perMachine
	if len(data) != wantTotal*appendRecordLen {
		t.Fatalf("durable size = %d bytes (%d records), want %d bytes (%d records): records were lost or overwritten",
			len(data), len(data)/appendRecordLen, wantTotal*appendRecordLen, wantTotal)
	}
	seen := make(map[string]bool, wantTotal)
	for off := 0; off < len(data); off += appendRecordLen {
		rec := data[off : off+appendRecordLen]
		if rec[appendRecordLen-1] != '\n' {
			t.Fatalf("record at offset %d is torn (no trailing newline): %q", off, rec)
		}
		if strings.Count(string(rec), "\n") != 1 {
			t.Fatalf("record at offset %d is spliced (%d newlines): %q", off, strings.Count(string(rec), "\n"), rec)
		}
		key := string(rec[:appendKeyLen])
		if seen[key] {
			t.Fatalf("record %q appears twice; offsets collided", key)
		}
		seen[key] = true
	}
	for _, m := range machines {
		for seq := 0; seq < perMachine; seq++ {
			key := appendKey(m, seq)
			if !seen[key] {
				t.Fatalf("record %q is missing from the durable log", key)
			}
		}
	}
}

// TestCrossMachineAppendsNeverCollide is the regression test for the live
// two-Mac evidence: two machines each appended 1500 fixed-length records to
// one file and the durable result held roughly half of them, with spliced
// lines at the collision boundaries. Both mounts here are write-through (no
// delegation over a volume-root child), so every append must reach the
// authority as an append operation whose offset the AUTHORITY assigns under
// its write serialization. Any frontend-computed absolute offset re-creates
// the collision and this test fails on record count.
func TestCrossMachineAppendsNeverCollide(t *testing.T) {
	addr := serveCore(t)
	ctx := context.Background()
	const (
		perMachine = 200
		path       = "shared-append.log"
	)
	machines := []string{"AA", "BB"}

	left := dialCore(t, addr, Options{Owner: "machine-left"})
	right := dialCore(t, addr, Options{Owner: "machine-right"})

	attr, st := left.Create(ctx, path, 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	leftState := NewNodeState(attr.Ino, attr.Ino != 0)
	rattr, st := right.Lookup(ctx, path)
	if st != fsproto.OK {
		t.Fatalf("peer lookup: %d", st)
	}
	rightState := NewNodeState(rattr.Ino, rattr.Ino != 0)

	writers := []struct {
		machine string
		vol     *Volume
		state   *NodeState
	}{
		{machines[0], left, leftState},
		{machines[1], right, rightState},
	}
	var wg sync.WaitGroup
	errCh := make(chan error, len(writers))
	for _, w := range writers {
		w := w
		wg.Add(1)
		go func() {
			defer wg.Done()
			for seq := 0; seq < perMachine; seq++ {
				rec := appendRecord(t, w.machine, seq)
				n, st := w.vol.WriteAppendOpenHandle(ctx, path, w.state, rec)
				if st != fsproto.OK || n != len(rec) {
					errCh <- fmt.Errorf("machine %s append %d: n=%d st=%d", w.machine, seq, n, st)
					return
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Fatal(err)
	}

	reader := dialCore(t, addr, Options{Owner: "verifier"})
	data, st := reader.Read(ctx, path, nil, 0, len(machines)*perMachine*appendRecordLen*2)
	if st != fsproto.OK {
		t.Fatalf("verify read: %d", st)
	}
	verifyAppendLog(t, data, machines, perMachine)
}

// TestFrontendComputedAppendOffsetsCollideAcrossMachines pins the MECHANISM
// of the production corruption with no timing dependence: two mounts each
// resolve "EOF" from their own view and then write at that absolute offset,
// which is exactly what a frontend does when the append intent never reaches
// the daemon. The second write lands on the first one's bytes and a record is
// destroyed. This is the behavior TestCrossMachineAppendsNeverCollide proves
// the authority-assigned-offset path does not have.
func TestFrontendComputedAppendOffsetsCollideAcrossMachines(t *testing.T) {
	addr := serveCore(t)
	ctx := context.Background()
	const path = "frontend-offset.log"

	left := dialCore(t, addr, Options{Owner: "machine-left"})
	right := dialCore(t, addr, Options{Owner: "machine-right"})

	attr, st := left.Create(ctx, path, 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	leftState := NewNodeState(attr.Ino, attr.Ino != 0)
	rattr, st := right.Lookup(ctx, path)
	if st != fsproto.OK {
		t.Fatalf("peer lookup: %d", st)
	}
	rightState := NewNodeState(rattr.Ino, rattr.Ino != 0)

	// Both machines sample size BEFORE either writes: the file is empty, so
	// both compute append offset 0. A kernel that resolved O_APPEND against
	// its own cached vnode size does precisely this.
	leftAttr, st := left.Getattr(ctx, path, leftState)
	if st != fsproto.OK {
		t.Fatalf("left getattr: %d", st)
	}
	rightAttr, st := right.Getattr(ctx, path, rightState)
	if st != fsproto.OK {
		t.Fatalf("right getattr: %d", st)
	}
	if leftAttr.Size != 0 || rightAttr.Size != 0 {
		t.Fatalf("fixture not empty: left=%d right=%d", leftAttr.Size, rightAttr.Size)
	}

	leftRec := appendRecord(t, "AA", 0)
	if n, st := left.Write(ctx, path, leftState, int64(leftAttr.Size), leftRec); st != fsproto.OK || n != len(leftRec) {
		t.Fatalf("left write: n=%d st=%d", n, st)
	}
	rightRec := appendRecord(t, "BB", 0)
	if n, st := right.Write(ctx, path, rightState, int64(rightAttr.Size), rightRec); st != fsproto.OK || n != len(rightRec) {
		t.Fatalf("right write: n=%d st=%d", n, st)
	}

	reader := dialCore(t, addr, Options{Owner: "verifier"})
	data, st := reader.Read(ctx, path, nil, 0, 4*appendRecordLen)
	if st != fsproto.OK {
		t.Fatalf("verify read: %d", st)
	}
	if len(data) != appendRecordLen {
		t.Fatalf("frontend-computed offsets produced %d bytes; the collision this test pins "+
			"requires both writes to land at offset 0 (one record survives)", len(data))
	}
	if string(data) != string(rightRec) {
		t.Fatalf("expected last-writer-wins at offset 0, got %q", data)
	}
	// One of two records is gone. That is the production failure, reproduced
	// with only frontend-computed offsets.
}
