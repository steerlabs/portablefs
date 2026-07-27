package session

// Test-only observables (compiled only into test binaries), mirroring
// wal/export_test.go: they let the external session_test package assert the
// journal-first contract's internals — that a close actually made every
// appended record fsync-durable and actually closed the log — without
// widening the production API.

// AllRecordsDurableForTest reports whether every record ever appended to this
// session's WAL is fsync-durable (DurableWatermark is an exclusive bound).
func (s *Session) AllRecordsDurableForTest() bool {
	s.mu.Lock()
	last, has := s.lastSeq, s.hasSeq
	s.mu.Unlock()
	if !has {
		return true
	}
	return s.log.DurableWatermark() > last
}

// LogClosedForTest reports whether the WAL was closed (closeLogOnce ran).
func (s *Session) LogClosedForTest() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.logClosed
}
