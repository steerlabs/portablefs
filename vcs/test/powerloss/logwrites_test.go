package powerloss

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

// synthLog builds a dm-log-writes image in memory. It is the only place in the
// harness that writes the format rather than reading it, which is what lets
// the replay engine be tested on a machine with no device mapper.
type synthEntry struct {
	sector  uint64
	sectors uint64
	flags   uint64
	mark    string
	payload []byte
}

func buildSynthLog(t *testing.T, sectorSize uint32, entries []synthEntry) []byte {
	t.Helper()
	buffer := &bytes.Buffer{}
	super := make([]byte, sectorSize)
	binary.LittleEndian.PutUint64(super[0:8], logWritesMagic)
	binary.LittleEndian.PutUint64(super[8:16], logWritesVersion)
	binary.LittleEndian.PutUint64(super[16:24], uint64(len(entries)))
	binary.LittleEndian.PutUint32(super[24:28], sectorSize)
	buffer.Write(super)
	for _, entry := range entries {
		header := make([]byte, sectorSize)
		binary.LittleEndian.PutUint64(header[0:8], entry.sector)
		binary.LittleEndian.PutUint64(header[8:16], entry.sectors)
		binary.LittleEndian.PutUint64(header[16:24], entry.flags)
		if entry.mark != "" {
			binary.LittleEndian.PutUint64(header[24:32], uint64(len(entry.mark)))
			copy(header[logEntryHeaderSize:], entry.mark)
		}
		buffer.Write(header)
		if entry.sectors > 0 && entry.flags&FlagDiscard == 0 {
			payload := make([]byte, int(entry.sectors)*int(sectorSize))
			copy(payload, entry.payload)
			buffer.Write(payload)
		}
	}
	return buffer.Bytes()
}

// sparseTarget is a growable in-memory block device.
type sparseTarget struct{ data []byte }

func (s *sparseTarget) WriteAt(p []byte, offset int64) (int, error) {
	end := offset + int64(len(p))
	if int64(len(s.data)) < end {
		grown := make([]byte, end)
		copy(grown, s.data)
		s.data = grown
	}
	copy(s.data[offset:end], p)
	return len(p), nil
}

func TestParseLogReadsMarksAndBarriers(t *testing.T) {
	image := buildSynthLog(t, 512, []synthEntry{
		{sector: 0, sectors: 8, flags: FlagDiscard},
		{sector: 4, sectors: 1, payload: []byte("alpha")},
		{flags: FlagMark, mark: "checkpoint-0"},
		{sector: 5, sectors: 2, flags: FlagFUA, payload: []byte("beta")},
		{flags: FlagFlush},
	})
	log, err := ParseLog(bytes.NewReader(image), int64(len(image)))
	if err != nil {
		t.Fatalf("ParseLog: %v", err)
	}
	if log.SectorSize != 512 || log.DeclaredEntries != 5 || len(log.Entries) != 5 {
		t.Fatalf("log = sector %d entries %d/%d, want 512 5/5", log.SectorSize, log.DeclaredEntries, len(log.Entries))
	}
	if !log.Entries[0].IsDiscard() || log.Entries[0].DataOffset != 0 {
		t.Fatalf("entry 0 = %+v, want a payload-free discard", log.Entries[0])
	}
	index, found := log.MarkEntry("checkpoint-0")
	if !found || index != 2 {
		t.Fatalf("MarkEntry = %d %v, want 2 true", index, found)
	}
	if _, found := log.MarkEntry("checkpoint-1"); found {
		t.Fatal("MarkEntry resolved a mark the log does not carry")
	}
	for _, want := range []struct {
		index   int
		barrier bool
	}{{0, false}, {1, false}, {2, false}, {3, true}, {4, true}} {
		if got := log.Entries[want.index].IsBarrier(); got != want.barrier {
			t.Errorf("entry %d IsBarrier = %v, want %v", want.index, got, want.barrier)
		}
	}
}

func TestParseLogFailsClosed(t *testing.T) {
	valid := buildSynthLog(t, 512, []synthEntry{{sector: 1, sectors: 1, payload: []byte("x")}})
	tests := []struct {
		name    string
		image   func() []byte
		size    func(int) int64
		wantIs  error
		wantSub string
	}{
		{
			name:   "not a log device",
			image:  func() []byte { return make([]byte, 4096) },
			wantIs: ErrNotLogWrites,
		},
		{
			name: "future format version",
			image: func() []byte {
				image := append([]byte(nil), valid...)
				binary.LittleEndian.PutUint64(image[8:16], logWritesVersion+1)
				return image
			},
			wantSub: "unsupported dm-log-writes version",
		},
		{
			name: "implausible sector size",
			image: func() []byte {
				image := append([]byte(nil), valid...)
				binary.LittleEndian.PutUint32(image[24:28], 300)
				return image
			},
			wantSub: "implausible log sector size",
		},
		{
			name: "log device too small for the entries it declares",
			image: func() []byte {
				image := append([]byte(nil), valid...)
				binary.LittleEndian.PutUint64(image[16:24], 64)
				return image
			},
			wantSub: "the log device was too small",
		},
		{
			name: "inline payload larger than one block",
			image: func() []byte {
				image := append([]byte(nil), valid...)
				binary.LittleEndian.PutUint64(image[512+24:512+32], 1024)
				return image
			},
			wantSub: "does not fit one",
		},
		{
			name:    "truncated log device",
			image:   func() []byte { return append([]byte(nil), valid...) },
			size:    func(length int) int64 { return int64(length) - 8 },
			wantSub: "runs past the",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			image := test.image()
			size := int64(len(image))
			if test.size != nil {
				size = test.size(len(image))
			}
			_, err := ParseLog(bytes.NewReader(image), size)
			if err == nil {
				t.Fatal("ParseLog accepted an unusable log")
			}
			if test.wantIs != nil && !errors.Is(err, test.wantIs) {
				t.Fatalf("ParseLog error = %v, want %v", err, test.wantIs)
			}
			if test.wantSub != "" && !strings.Contains(err.Error(), test.wantSub) {
				t.Fatalf("ParseLog error = %v, want it to name %q", err, test.wantSub)
			}
		})
	}
}

func TestReplayToReconstructsEachCut(t *testing.T) {
	const sectorSize = 512
	first := bytes.Repeat([]byte{0xa1}, sectorSize)
	second := bytes.Repeat([]byte{0xb2}, sectorSize)
	image := buildSynthLog(t, sectorSize, []synthEntry{
		{sector: 0, sectors: 4, flags: FlagDiscard},
		{sector: 1, sectors: 1, payload: first},
		{flags: FlagMark, mark: "after-first"},
		{sector: 2, sectors: 1, flags: FlagFUA, payload: second},
		{flags: FlagMark, mark: "after-second"},
	})
	log, err := ParseLog(bytes.NewReader(image), int64(len(image)))
	if err != nil {
		t.Fatalf("ParseLog: %v", err)
	}
	tests := []struct {
		mark        string
		wantFirst   bool
		wantSecond  bool
		description string
	}{
		{mark: "after-first", wantFirst: true, description: "only the first write reached the device"},
		{mark: "after-second", wantFirst: true, wantSecond: true, description: "both writes reached the device"},
	}
	for _, test := range tests {
		t.Run(test.mark, func(t *testing.T) {
			end, found := log.MarkEntry(test.mark)
			if !found {
				t.Fatalf("mark %q is missing", test.mark)
			}
			target := &sparseTarget{}
			if err := log.ReplayTo(target, end); err != nil {
				t.Fatalf("ReplayTo: %v", err)
			}
			gotFirst := bytes.Equal(target.data[sectorSize:2*sectorSize], first)
			if gotFirst != test.wantFirst {
				t.Errorf("first sector present = %v, want %v (%s)", gotFirst, test.wantFirst, test.description)
			}
			if len(target.data) >= 3*sectorSize {
				gotSecond := bytes.Equal(target.data[2*sectorSize:3*sectorSize], second)
				if gotSecond != test.wantSecond {
					t.Errorf("second sector present = %v, want %v (%s)", gotSecond, test.wantSecond, test.description)
				}
			} else if test.wantSecond {
				t.Errorf("second sector absent, want present (%s)", test.description)
			}
		})
	}
}

// TestReplayDiscardZeroesRatherThanPreserves pins the one place the replayer
// makes a choice the kernel leaves undefined. A discard that preserved the
// previous bytes would let a replayed image show data the device was told to
// forget, which would make every later cut optimistic.
func TestReplayDiscardZeroesRatherThanPreserves(t *testing.T) {
	const sectorSize = 512
	payload := bytes.Repeat([]byte{0x7e}, sectorSize)
	image := buildSynthLog(t, sectorSize, []synthEntry{
		{sector: 0, sectors: 1, payload: payload},
		{sector: 0, sectors: 1, flags: FlagDiscard},
	})
	log, err := ParseLog(bytes.NewReader(image), int64(len(image)))
	if err != nil {
		t.Fatalf("ParseLog: %v", err)
	}
	target := &sparseTarget{}
	if err := log.ReplayTo(target, 1); err != nil {
		t.Fatalf("ReplayTo: %v", err)
	}
	if !bytes.Equal(target.data[:sectorSize], make([]byte, sectorSize)) {
		t.Fatal("a replayed discard left the discarded bytes in place")
	}
}

// TestThroughDropsTheTidyUpWrites covers the truncation that keeps the writes
// an unmount performs after the simulated cut out of every replay point.
func TestThroughDropsTheTidyUpWrites(t *testing.T) {
	image := buildSynthLog(t, 512, []synthEntry{
		{sector: 1, sectors: 1, payload: []byte("workload")},
		{flags: FlagMark, mark: "power-cut"},
		{sector: 2, sectors: 1, flags: FlagFlush, payload: []byte("writeback the unmount performed")},
	})
	log, err := ParseLog(bytes.NewReader(image), int64(len(image)))
	if err != nil {
		t.Fatalf("ParseLog: %v", err)
	}
	cut, found := log.MarkEntry("power-cut")
	if !found {
		t.Fatal("the power-cut mark is missing")
	}
	view, err := log.Through(cut)
	if err != nil {
		t.Fatalf("Through: %v", err)
	}
	if len(view.Entries) != cut+1 || view.DeclaredEntries != uint64(cut+1) {
		t.Fatalf("view has %d entries declaring %d, want %d", len(view.Entries), view.DeclaredEntries, cut+1)
	}
	if err := view.ReplayTo(&sparseTarget{}, len(view.Entries)-1); err != nil {
		t.Fatalf("ReplayTo on the truncated view: %v", err)
	}
	if err := view.ReplayTo(&sparseTarget{}, cut+1); err == nil {
		t.Fatal("the truncated view still replayed an entry from after the cut")
	}
	for _, outside := range []int{-1, len(log.Entries)} {
		if _, err := log.Through(outside); err == nil {
			t.Errorf("Through(%d) accepted an entry outside the log", outside)
		}
	}
}

func TestReplayToRejectsCutsOutsideTheLog(t *testing.T) {
	image := buildSynthLog(t, 512, []synthEntry{{sector: 1, sectors: 1, payload: []byte("x")}})
	log, err := ParseLog(bytes.NewReader(image), int64(len(image)))
	if err != nil {
		t.Fatalf("ParseLog: %v", err)
	}
	for _, end := range []int{-2, 1, 99} {
		if err := log.ReplayTo(&sparseTarget{}, end); err == nil {
			t.Errorf("ReplayTo(%d) accepted a cut outside the log", end)
		}
	}
}
