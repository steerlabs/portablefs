package powerloss

import (
	"bytes"
	"strings"
	"testing"
)

// markedLog builds a log whose marks match the sample ledger, plus a
// controllable number of barriers between them.
func markedLog(t *testing.T, barriers int) *Log {
	t.Helper()
	entries := []synthEntry{{sector: 0, sectors: 4, flags: FlagDiscard}}
	for range barriers {
		entries = append(entries, synthEntry{sector: 1, sectors: 1, flags: FlagFlush, payload: []byte("b")})
	}
	entries = append(entries, synthEntry{flags: FlagMark, mark: "ckpt-0"})
	for range barriers {
		entries = append(entries, synthEntry{sector: 2, sectors: 1, flags: FlagFUA, payload: []byte("b")})
	}
	entries = append(entries, synthEntry{flags: FlagMark, mark: "ckpt-1"})
	entries = append(entries, synthEntry{sector: 3, sectors: 1, payload: []byte("tail")})
	image := buildSynthLog(t, 512, entries)
	log, err := ParseLog(bytes.NewReader(image), int64(len(image)))
	if err != nil {
		t.Fatalf("ParseLog: %v", err)
	}
	return log
}

func TestSelectPointsAlwaysKeepsEveryCheckpointMark(t *testing.T) {
	log := markedLog(t, 20)
	ledger := sampleLedger(t)
	// A barrier budget far smaller than the number of barriers must not cost a
	// single checkpoint cut: those are the points the contract lives at.
	points, err := SelectPoints(log, ledger, 3)
	if err != nil {
		t.Fatalf("SelectPoints: %v", err)
	}
	seen := make(map[string]bool)
	previous := -1
	for _, point := range points {
		if point.EndEntry <= previous {
			t.Fatalf("points are not strictly increasing: %+v after entry %d", point, previous)
		}
		previous = point.EndEntry
		if point.Kind == PointCheckpoint {
			seen[point.Mark] = true
		}
		if point.Reason == "" {
			t.Fatalf("point %+v carries no reason", point)
		}
	}
	for _, mark := range ledger.Marks() {
		if !seen[mark] {
			t.Fatalf("SelectPoints dropped checkpoint mark %q under a tight barrier budget", mark)
		}
	}
	if points[len(points)-1].EndEntry != log.Entries[len(log.Entries)-1].Index {
		t.Fatalf("last point = %+v, want a cut at the final entry", points[len(points)-1])
	}
}

func TestSelectPointsBoundsTheBarrierSweep(t *testing.T) {
	log := markedLog(t, 40)
	ledger := sampleLedger(t)
	for _, budget := range []int{0, 1, 5, 500} {
		points, err := SelectPoints(log, ledger, budget)
		if err != nil {
			t.Fatalf("SelectPoints(%d): %v", budget, err)
		}
		barriers := 0
		for _, point := range points {
			if point.Kind == PointBarrier {
				barriers++
			}
		}
		if barriers > budget {
			t.Fatalf("budget %d produced %d barrier points", budget, barriers)
		}
		if budget == 0 && barriers != 0 {
			t.Fatal("a zero budget still swept barriers")
		}
	}
}

// TestSelectPointsFailsOnAMissingMark is the fail-closed rule that matters
// most here: a mark the driver claims but the log does not carry means the
// mark channel broke, and every expectation after it would be evaluated at the
// wrong cut.
func TestSelectPointsFailsOnAMissingMark(t *testing.T) {
	log := markedLog(t, 1)
	ledger := sampleLedger(t)
	ledger.Checkpoints[1].Mark = "ckpt-missing"
	_, err := SelectPoints(log, ledger, 2)
	if err == nil {
		t.Fatal("SelectPoints proceeded past a mark the log does not carry")
	}
	if !strings.Contains(err.Error(), "the mark channel was broken") {
		t.Fatalf("SelectPoints error = %v, want it to name the broken mark channel", err)
	}
}

func TestSelectPointsRejectsAnEmptyLog(t *testing.T) {
	image := buildSynthLog(t, 512, nil)
	log, err := ParseLog(bytes.NewReader(image), int64(len(image)))
	if err != nil {
		t.Fatalf("ParseLog: %v", err)
	}
	if _, err := SelectPoints(log, sampleLedger(t), 4); err == nil {
		t.Fatal("SelectPoints accepted a log that recorded nothing")
	}
}

func TestSampleEvenlySpansTheWholeRange(t *testing.T) {
	values := make([]int, 100)
	for index := range values {
		values[index] = index * 3
	}
	tests := []struct {
		budget int
		want   int
	}{{0, 0}, {1, 1}, {2, 2}, {7, 7}, {100, 100}, {1000, 100}}
	for _, test := range tests {
		got := sampleEvenly(values, test.budget)
		if len(got) != test.want {
			t.Errorf("sampleEvenly(budget %d) length = %d, want %d", test.budget, len(got), test.want)
		}
		if test.budget >= 2 && len(got) > 0 {
			if got[0] != values[0] || got[len(got)-1] != values[len(values)-1] {
				t.Errorf("sampleEvenly(budget %d) = %v..%v, want it to span the whole range", test.budget, got[0], got[len(got)-1])
			}
		}
	}
}
