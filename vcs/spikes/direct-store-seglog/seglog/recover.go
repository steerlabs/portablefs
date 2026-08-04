package seglog

import "time"

// RecoveryReport describes how the in-memory index was established at Open.
type RecoveryReport struct {
	Mode         string
	Duration     time.Duration
	BytesScanned int64
	Keys         int
	Segments     int
	IndexEntries int
}

// Recovery returns the report for the most recent Open.
func (s *Store) Recovery() RecoveryReport {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.recovery
}

// recoverFast loads the persistent index and scans only the log tail that the
// index has not yet absorbed.
func (s *Store) recoverFast(idx Index) (bool, error) {
	head, err := idx.Load(func(key []byte, loc Loc) {
		s.index[string(key)] = loc
	})
	if err != nil {
		return false, err
	}
	s.recovery.IndexEntries = len(s.index)
	for _, loc := range s.index {
		seg := s.segments[loc.Seg]
		if seg == nil || loc.Off+int64(loc.Len) > seg.size {
			return false, nil
		}
	}
	if head.Seg != 0 || head.Off != 0 {
		if seg := s.segments[head.Seg]; seg == nil {
			return false, nil
		}
	}
	var scanned int64
	for _, id := range s.order {
		seg := s.segments[id]
		if id < head.Seg {
			continue
		}
		from := int64(0)
		if id == head.Seg {
			from = head.Off
		}
		if from > seg.size {
			from = seg.size
		}
		good, err := s.scanSegmentFrom(seg, from)
		if err != nil {
			return false, err
		}
		scanned += seg.size - from
		if good < seg.size {
			if err := truncateSegment(seg, good); err != nil {
				return false, err
			}
		}
	}
	s.recovery.BytesScanned = scanned
	return true, nil
}
