package powerloss

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

// The dm-log-writes on-disk log format, transcribed from the pinned product
// kernel's drivers/md/dm-log-writes.c. It is reimplemented here rather than
// shelling out to xfstests' replay-log for two reasons: xfstests is not a
// dependency this repository pins, and a Go implementation is unit testable on
// any platform, which is the only way the replay engine gets coverage outside
// the privileged runner.
//
// The layout was also confirmed against a log a real 6.x kernel produced
// before this code was written; docs/power-loss-testing.md records that probe.
// If a future kernel changes the format, ParseLog fails closed on the magic or
// the version rather than replaying nonsense.
const (
	logWritesMagic   uint64 = 0x6a736677736872
	logWritesVersion uint64 = 1

	// A log entry header is 32 bytes and occupies one whole sectorsize-byte
	// block. Inline payload (only marks carry one) starts immediately after it.
	logEntryHeaderSize = 32
)

// Log entry flags. Values are the kernel's LOG_*_FLAG.
const (
	FlagFlush uint64 = 1 << 0
	// FlagFUA marks a write the filesystem required to be on stable storage
	// before completion. Together with FlagFlush these are the only points a
	// power cut may be simulated at without inventing device behaviour.
	FlagFUA      uint64 = 1 << 1
	FlagDiscard  uint64 = 1 << 2
	FlagMark     uint64 = 1 << 3
	FlagMetadata uint64 = 1 << 4
)

// Entry is one recorded bio, or one operator mark.
type Entry struct {
	// Index is the entry's position in the log, counting from zero. It is the
	// unit every replay point is expressed in.
	Index int
	// HeaderOffset is the byte offset of the entry header on the log device.
	HeaderOffset int64
	// DataOffset is the byte offset of the entry's payload on the log device,
	// valid when Sectors is non-zero and the entry is not a discard.
	DataOffset int64
	// Sector and Sectors are in units of the log's SectorSize, not 512-byte
	// bio sectors, because that is what the kernel records.
	Sector  uint64
	Sectors uint64
	Flags   uint64
	DataLen uint64
	// Mark is the operator label carried by a FlagMark entry, empty otherwise.
	Mark string
}

// IsMark reports whether the entry is an operator mark rather than a bio.
func (e Entry) IsMark() bool { return e.Flags&FlagMark != 0 }

// IsBarrier reports whether the entry carries a flush or FUA. A power cut
// simulated immediately after a barrier is the only cut the device model
// guarantees anything about, so these are the interesting replay points.
func (e Entry) IsBarrier() bool { return e.Flags&(FlagFlush|FlagFUA) != 0 }

// IsDiscard reports whether the entry is a discard, which carries no payload.
func (e Entry) IsDiscard() bool { return e.Flags&FlagDiscard != 0 }

// Log is a parsed dm-log-writes log device.
type Log struct {
	SectorSize uint32
	// DeclaredEntries is the count the log superblock carries. ParseLog
	// requires the parsed entries to match it exactly: a log that stops early
	// is a log that silently lost writes, and replaying it would understate
	// what reached the device.
	DeclaredEntries uint64
	Entries         []Entry

	source io.ReaderAt
}

// ErrNotLogWrites reports a device that does not carry a dm-log-writes
// superblock. It is separated from every other parse failure because the
// harness must distinguish "you pointed me at the wrong device" from "the log
// is damaged".
var ErrNotLogWrites = errors.New("powerloss: device does not carry a dm-log-writes superblock")

// ParseLog reads the superblock and walks the whole entry chain. size is the
// log device's byte size; a walk that would run past it fails rather than
// wrapping, because dm-log-writes stops logging when the log device fills and
// a wrapped read would fabricate entries.
func ParseLog(source io.ReaderAt, size int64) (*Log, error) {
	header := make([]byte, logEntryHeaderSize+8)
	if _, err := source.ReadAt(header, 0); err != nil {
		return nil, fmt.Errorf("powerloss: read log superblock: %w", err)
	}
	magic := binary.LittleEndian.Uint64(header[0:8])
	if magic != logWritesMagic {
		return nil, fmt.Errorf("%w (magic %#x)", ErrNotLogWrites, magic)
	}
	version := binary.LittleEndian.Uint64(header[8:16])
	if version != logWritesVersion {
		return nil, fmt.Errorf("powerloss: unsupported dm-log-writes version %d, this harness understands %d", version, logWritesVersion)
	}
	declared := binary.LittleEndian.Uint64(header[16:24])
	sectorSize := binary.LittleEndian.Uint32(header[24:28])
	if sectorSize < logEntryHeaderSize || sectorSize%512 != 0 {
		return nil, fmt.Errorf("powerloss: implausible log sector size %d", sectorSize)
	}
	log := &Log{SectorSize: sectorSize, DeclaredEntries: declared, source: source}
	block := make([]byte, sectorSize)
	offset := int64(sectorSize)
	for index := 0; uint64(index) < declared; index++ {
		if offset+int64(sectorSize) > size {
			return nil, fmt.Errorf("powerloss: log declares %d entries but entry %d starts past the %d-byte log device; the log device was too small and writes were lost", declared, index, size)
		}
		if _, err := source.ReadAt(block, offset); err != nil {
			return nil, fmt.Errorf("powerloss: read log entry %d: %w", index, err)
		}
		entry := Entry{
			Index:        index,
			HeaderOffset: offset,
			Sector:       binary.LittleEndian.Uint64(block[0:8]),
			Sectors:      binary.LittleEndian.Uint64(block[8:16]),
			Flags:        binary.LittleEndian.Uint64(block[16:24]),
			DataLen:      binary.LittleEndian.Uint64(block[24:32]),
		}
		if entry.DataLen > uint64(sectorSize)-logEntryHeaderSize {
			return nil, fmt.Errorf("powerloss: log entry %d declares %d inline bytes, which does not fit one %d-byte block", index, entry.DataLen, sectorSize)
		}
		if entry.IsMark() {
			entry.Mark = strings.TrimRight(string(block[logEntryHeaderSize:logEntryHeaderSize+entry.DataLen]), "\x00")
		}
		offset += int64(sectorSize)
		if entry.Sectors > 0 && !entry.IsDiscard() {
			entry.DataOffset = offset
			payload := int64(entry.Sectors) * int64(sectorSize)
			if payload < 0 || offset+payload > size {
				return nil, fmt.Errorf("powerloss: log entry %d payload of %d bytes runs past the %d-byte log device", index, payload, size)
			}
			offset += payload
		}
		log.Entries = append(log.Entries, entry)
	}
	if uint64(len(log.Entries)) != declared {
		return nil, fmt.Errorf("powerloss: parsed %d entries but the superblock declares %d", len(log.Entries), declared)
	}
	return log, nil
}

// MarkEntry resolves an operator mark to its entry index. Marks are the
// harness's own labels, so an unresolvable one is always a harness defect
// rather than a product finding, and callers must fail closed on it.
func (l *Log) MarkEntry(name string) (int, bool) {
	for _, entry := range l.Entries {
		if entry.IsMark() && entry.Mark == name {
			return entry.Index, true
		}
	}
	return 0, false
}

// Through returns a view of the log that ends at endEntry.
//
// It exists for one specific and unavoidable step. Reading the log requires
// releasing the device-mapper target, which requires unmounting the
// filesystem, and an unmount writes back dirty pages - writes that the
// simulated power cut, by definition, never happened. Cutting the log at the
// mark taken the instant the authority was killed removes them, so no replay
// point can be contaminated by a write that only exists because the harness
// had to tidy up after itself.
func (l *Log) Through(endEntry int) (*Log, error) {
	if endEntry < 0 || endEntry >= len(l.Entries) {
		return nil, fmt.Errorf("powerloss: cannot truncate a %d-entry log at entry %d", len(l.Entries), endEntry)
	}
	return &Log{
		SectorSize:      l.SectorSize,
		DeclaredEntries: uint64(endEntry + 1),
		Entries:         l.Entries[:endEntry+1],
		source:          l.source,
	}, nil
}

// ReplayTo writes every entry with index <= endEntry onto target, in log
// order, reconstructing the device image a power cut immediately after that
// entry would have left.
//
// target must start out zeroed for the result to be the real device: entry
// zero is normally mkfs's whole-device discard, and discards are replayed as
// zeroing. Callers therefore create a fresh sparse image per replay point
// rather than replaying incrementally onto the previous one, which would also
// make a point depend on the point before it.
func (l *Log) ReplayTo(target io.WriterAt, endEntry int) error {
	if endEntry < -1 || endEntry >= len(l.Entries) {
		return fmt.Errorf("powerloss: replay end entry %d is outside the %d-entry log", endEntry, len(l.Entries))
	}
	sector := int64(l.SectorSize)
	buffer := make([]byte, 0, 1<<20)
	zeros := make([]byte, 1<<20)
	for index := 0; index <= endEntry; index++ {
		entry := l.Entries[index]
		if entry.IsMark() || entry.Sectors == 0 {
			continue
		}
		offset := int64(entry.Sector) * sector
		length := int64(entry.Sectors) * sector
		if offset < 0 || length < 0 {
			return fmt.Errorf("powerloss: log entry %d describes an out-of-range extent", index)
		}
		if entry.IsDiscard() {
			if err := writeZeros(target, offset, length, zeros); err != nil {
				return fmt.Errorf("powerloss: replay discard of entry %d: %w", index, err)
			}
			continue
		}
		if int64(cap(buffer)) < length {
			buffer = make([]byte, length)
		}
		payload := buffer[:length]
		if _, err := l.source.ReadAt(payload, entry.DataOffset); err != nil {
			return fmt.Errorf("powerloss: read payload of log entry %d: %w", index, err)
		}
		if _, err := target.WriteAt(payload, offset); err != nil {
			return fmt.Errorf("powerloss: replay entry %d: %w", index, err)
		}
	}
	return nil
}

// writeZeros replays a discard. The kernel leaves discarded content undefined;
// zeroing is the deterministic choice, and it is also what a target that
// reports discard_zeroes_data does, so a replay never invents bytes that were
// never written.
func writeZeros(target io.WriterAt, offset, length int64, zeros []byte) error {
	for length > 0 {
		chunk := int64(len(zeros))
		if chunk > length {
			chunk = length
		}
		if _, err := target.WriteAt(zeros[:chunk], offset); err != nil {
			return err
		}
		offset += chunk
		length -= chunk
	}
	return nil
}
