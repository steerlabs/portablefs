package powerloss

import (
	"fmt"
	"sort"
)

// PointKind names why a replay point was chosen. It appears verbatim in every
// report, so a green run says which cuts it actually took.
type PointKind string

const (
	// PointCheckpoint is a cut at a mark the workload took immediately after a
	// durability claim - a returned fsync for the Linux workload, an
	// acknowledged mutation for the FSKit one. These are the points that carry
	// each instrument's contract.
	PointCheckpoint PointKind = "checkpoint"
	// PointBarrier is a cut at a flush or FUA the filesystem issued on its own.
	// These carry no content expectation; they exist to prove XFS recovers.
	PointBarrier PointKind = "barrier"
	// PointFinal is a cut at the last logged entry, the state an orderly
	// unmount left behind.
	PointFinal PointKind = "final"
)

// Point is one power-cut position, expressed as the last log entry that
// reached the device.
type Point struct {
	EndEntry int       `json:"endEntry"`
	Kind     PointKind `json:"kind"`
	Mark     string    `json:"mark,omitempty"`
	Reason   string    `json:"reason"`
}

// markedPoint is one mark a ledger says the write log carries, with the prose
// a cut at it reports.
type markedPoint struct {
	mark   string
	owner  string // names the claim for a missing-mark error, e.g. "step 4"
	reason string
}

// markedLedger is a ledger whose marks name the cuts a run must replay. Both
// the fsync Ledger and the MutationLedger are, so one point selector serves
// both instruments.
type markedLedger interface {
	markedPoints() []markedPoint
}

// SelectPoints derives the cuts a run replays.
//
// Every ledger mark is always selected: those are the points the contract is
// asserted at, and dropping one to fit a budget would quietly weaken the run. Barrier cuts are the sweep that looks for a cut position
// nobody thought of, and only they are sampled, because their number scales
// with the workload while their individual value does not. maxBarrierPoints
// bounds the sweep; zero disables it.
//
// The returned points are ordered by entry and contain no duplicates, so a
// caller replaying them in order does strictly increasing work.
func SelectPoints(log *Log, ledger markedLedger, maxBarrierPoints int) ([]Point, error) {
	if log == nil || ledger == nil {
		return nil, fmt.Errorf("powerloss: SelectPoints needs both a log and a ledger")
	}
	if maxBarrierPoints < 0 {
		return nil, fmt.Errorf("powerloss: negative barrier-point budget %d", maxBarrierPoints)
	}
	if len(log.Entries) == 0 {
		return nil, fmt.Errorf("powerloss: the log has no entries; the device recorded nothing and no cut can be taken")
	}
	byEntry := make(map[int]Point)
	for _, marked := range ledger.markedPoints() {
		index, found := log.MarkEntry(marked.mark)
		if !found {
			// A mark the driver claims to have taken but the log does not
			// carry means the mark channel was broken for part of the run.
			// Every later expectation would then be evaluated at the wrong
			// cut, so this fails the run instead of skipping the claim.
			return nil, fmt.Errorf("powerloss: %s claims mark %q but the log does not carry it; the mark channel was broken and no cut can be trusted", marked.owner, marked.mark)
		}
		byEntry[index] = Point{EndEntry: index, Kind: PointCheckpoint, Mark: marked.mark, Reason: marked.reason}
	}
	if maxBarrierPoints > 0 {
		barriers := make([]int, 0, len(log.Entries))
		for _, entry := range log.Entries {
			if entry.IsBarrier() {
				barriers = append(barriers, entry.Index)
			}
		}
		for _, index := range sampleEvenly(barriers, maxBarrierPoints) {
			if _, taken := byEntry[index]; taken {
				continue
			}
			byEntry[index] = Point{
				EndEntry: index,
				Kind:     PointBarrier,
				Reason:   fmt.Sprintf("cut at log entry %d, a flush/FUA barrier the filesystem issued", index),
			}
		}
	}
	last := log.Entries[len(log.Entries)-1].Index
	if _, taken := byEntry[last]; !taken {
		byEntry[last] = Point{
			EndEntry: last,
			Kind:     PointFinal,
			Reason:   "cut at the last logged entry: every write the run issued reached the device",
		}
	}
	points := make([]Point, 0, len(byEntry))
	for _, point := range byEntry {
		points = append(points, point)
	}
	sort.Slice(points, func(i, j int) bool { return points[i].EndEntry < points[j].EndEntry })
	return points, nil
}

// sampleEvenly picks at most budget values spread across the whole slice,
// always including the first and the last. Spreading rather than taking a
// prefix matters: barriers cluster at mkfs time, and a prefix would sweep the
// filesystem's creation instead of the workload.
func sampleEvenly(values []int, budget int) []int {
	if budget <= 0 || len(values) == 0 {
		return nil
	}
	if len(values) <= budget {
		return append([]int(nil), values...)
	}
	if budget == 1 {
		return []int{values[len(values)-1]}
	}
	picked := make([]int, 0, budget)
	last := -1
	for slot := 0; slot < budget; slot++ {
		index := slot * (len(values) - 1) / (budget - 1)
		if index == last {
			continue
		}
		last = index
		picked = append(picked, values[index])
	}
	return picked
}
