package wal

// Test-only accessors. These live in *_test.go so they are compiled only for tests and
// add nothing to the production binary. durableSeq is read/written solely under commitMu
// (see CommitThrough/flushLocked), so a race-clean read must take commitMu too.

// durableSeqForTest returns the current durableSeq, read under commitMu so the race
// detector sees a properly synchronized access.
func (w *WAL) durableSeqForTest() uint64 {
	w.commitMu.Lock()
	defer w.commitMu.Unlock()
	return w.durableSeq
}
