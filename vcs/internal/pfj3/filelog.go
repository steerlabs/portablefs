package pfj3

import (
	"crypto/rand"
	"fmt"
	"sync"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/pfc2"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// FileEntryLog is a durable PFJ3 entry log over the local file WAL — the
// BENCH/TORTURE/TEST authority backend. It gives the managed (journaled)
// generation a single-node, fsync-durable, crash-replayable log so the
// harness authorities speak exactly the product coordination plane without
// PostgreSQL. It is NOT a production journal: production durability is the
// fenced remote PostgreSQL journal (internal/remotejournal), and the manager
// never spawns a child on a file log.
//
// Each journal row is one canonical PFJ3 entry payload framed in a
// wal.OpJournalEntry record; the record Seq is the entry LSN. Admission facts
// mirror the SQL append transaction's contract (issue against the durable
// floor, validate the manifest, consume exactly once, advance the floor) with
// host wall time standing in for database time — acceptable only because this
// log is single-node by construction.
type FileEntryLog struct {
	*wal.WAL

	mu    sync.Mutex
	next  uint64 // next LSN to reserve (== the WAL's next record Seq)
	dbNow int64
	floor int64
	facts map[[16]byte]*fileLogFact
}

type fileLogFact struct {
	issued  int64
	expires int64
	purpose pfc2.FactPurpose
	session pfc2.SessionRef
}

// fileLogFactTTLMs bounds one issued admission fact's validity (mirrors the
// SQL fact TTL scale; facts are consumed within one control round-trip).
const fileLogFactTTLMs = 30_000

// NewFileEntryLog opens (or replays) a file-backed PFJ3 entry log over w.
// Every retained record must be an OpJournalEntry row; the durable fact
// floor is recovered from the replayed entries' fact manifests.
func NewFileEntryLog(w *wal.WAL) (*FileEntryLog, error) {
	f := &FileEntryLog{WAL: w, facts: map[[16]byte]*fileLogFact{}}
	if err := w.ReplayInto(func(r wal.Record) error {
		if r.Op != wal.OpJournalEntry {
			return fmt.Errorf("pfj3: file entry log carries a non-entry record op %d at LSN %d", r.Op, r.Seq)
		}
		entry, err := Decode(r.Data)
		if err != nil {
			return err
		}
		manifest, err := entry.FactManifest()
		if err != nil {
			return err
		}
		for _, ref := range manifest {
			if ref.DbMs > f.floor {
				f.floor = ref.DbMs
			}
		}
		f.next = r.Seq + 1
		return nil
	}); err != nil {
		return nil, err
	}
	f.dbNow = time.Now().UnixMilli()
	if f.dbNow <= f.floor {
		f.dbNow = f.floor + 1
	}
	return f, nil
}

// RecordCodec identifies the PFJ3 entry payload framing.
func (f *FileEntryLog) RecordCodec() string { return RecordCodec }

// ControlCodec identifies the PFC2 control codec the entries carry.
func (f *FileEntryLog) ControlCodec() string { return ControlCodec }

// tick advances the log's database-time stand-in monotonically. Caller holds mu.
func (f *FileEntryLog) tick() int64 {
	now := time.Now().UnixMilli()
	if now <= f.dbNow {
		now = f.dbNow + 1
	}
	f.dbNow = now
	return now
}

// IssueAdmissionFact mints one short-lived fact for a PFC2 control
// transition, enforcing the same issue/freeze/consume contract as the SQL
// append: the issuer's floor must equal the durable floor, and the fact is
// deleted exactly once at consume.
func (f *FileEntryLog) IssueAdmissionFact(scope pfc2.FactScope) (pfc2.IssuedFact, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if scope.Session.SessionID == "" || scope.Session.Generation == 0 {
		return pfc2.IssuedFact{}, fmt.Errorf("pfj3: admission fact requires a session")
	}
	if !scope.Purpose.Valid() {
		return pfc2.IssuedFact{}, fmt.Errorf("pfj3: admission fact requires a known purpose")
	}
	if scope.PriorDbTimeFloorMs != f.floor {
		return pfc2.IssuedFact{}, fmt.Errorf("pfj3: issuer floor %d does not equal the durable floor %d",
			scope.PriorDbTimeFloorMs, f.floor)
	}
	now := f.tick()
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return pfc2.IssuedFact{}, err
	}
	f.facts[id] = &fileLogFact{
		issued: now, expires: now + fileLogFactTTLMs,
		purpose: scope.Purpose, session: scope.Session,
	}
	return pfc2.IssuedFact{
		Fact:            pfc2.TimeFact{Source: pfc2.TimeSourceDB, FactID: id, DbMs: now},
		FactExpiresDbMs: now + fileLogFactTTLMs,
	}, nil
}

// AppendEntriesBuffered assigns contiguous LSNs, validates and consumes each
// entry's fact manifest, and stages the canonical payloads in the file WAL.
// Durability still flows through CommitThrough (fsync).
func (f *FileEntryLog) AppendEntriesBuffered(entries []JournalEntry) (uint64, uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	first := f.next
	now := f.tick()
	consumed := map[[16]byte]bool{}
	floor := f.floor
	records := make([]wal.Record, 0, len(entries))
	for i := range entries {
		entries[i].LSN = first + uint64(i)
		if entries[i].Tree != nil {
			entries[i].Tree.Seq = entries[i].LSN
		}
		manifest, err := entries[i].FactManifest()
		if err != nil {
			return 0, 0, err
		}
		for _, ref := range manifest {
			fact := f.facts[ref.FactID]
			if fact == nil || consumed[ref.FactID] {
				return 0, 0, fmt.Errorf("pfj3: admission fact unknown or already consumed")
			}
			if fact.purpose != ref.Purpose || fact.session != ref.Session {
				return 0, 0, fmt.Errorf("pfj3: admission fact purpose/session mismatch")
			}
			if fact.issued != ref.DbMs || fact.expires <= now || fact.issued < floor {
				return 0, 0, fmt.Errorf("pfj3: admission fact rejected")
			}
			consumed[ref.FactID] = true
			if fact.issued > floor {
				floor = fact.issued
			}
		}
		payload, err := Encode(&entries[i])
		if err != nil {
			return 0, 0, err
		}
		records = append(records, wal.Record{Op: wal.OpJournalEntry, Data: payload})
	}
	gotFirst, gotEnd, err := f.WAL.AppendBatchBuffered(records)
	if err != nil {
		return 0, 0, err
	}
	if gotFirst != first {
		// The WAL and this log share one LSN space by construction (every
		// append goes through here); a divergence means the file was touched
		// by something else and nothing about the staged entries is trustworthy.
		f.WAL.Poison()
		return 0, 0, fmt.Errorf("pfj3: file entry log LSN %d diverged from the WAL reservation %d", first, gotFirst)
	}
	for id := range consumed {
		delete(f.facts, id)
	}
	f.floor = floor
	f.next = gotEnd
	return gotFirst, gotEnd, nil
}

// ReplayEntriesInto streams the retained entries in LSN order.
func (f *FileEntryLog) ReplayEntriesInto(fn func(JournalEntry) error) error {
	return f.WAL.ReplayInto(func(r wal.Record) error {
		if r.Op != wal.OpJournalEntry {
			return fmt.Errorf("pfj3: file entry log carries a non-entry record op %d at LSN %d", r.Op, r.Seq)
		}
		entry, err := Decode(r.Data)
		if err != nil {
			return err
		}
		if entry.LSN != r.Seq {
			return fmt.Errorf("pfj3: entry LSN %d does not match its WAL record Seq %d", entry.LSN, r.Seq)
		}
		return fn(entry)
	})
}

var _ EntryLog = (*FileEntryLog)(nil)
