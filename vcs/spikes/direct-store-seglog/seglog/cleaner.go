package seglog

import (
	"os"
	"sort"
	"time"
)

// maxSegmentsPerPass bounds how much relocation one cleaning pass performs
// before it reclaims the sources, so the cleaner yields to the writer.
const maxSegmentsPerPass = 8

// cleanLoop keeps live/total at or above CleanUtilization by relocating live
// records out of the emptiest sealed segments and reclaiming them.
func (s *Store) cleanLoop() {
	defer s.wg.Done()
	for {
		select {
		case <-s.stop:
			return
		default:
		}
		cleaned, err := s.clean()
		if err != nil {
			s.recordIndexError(err)
		}
		if cleaned {
			// There may be more to do; do not wait for a tick.
			continue
		}
		select {
		case <-s.stop:
			return
		case <-time.After(s.opts.CleanInterval):
		}
	}
}

// Clean runs one cleaning pass: choose the emptiest sealed segments, relocate
// their live records into the head, make the relocated index entries durable,
// then delete the sources. It is exported so measurements can drive it
// deterministically.
func (s *Store) Clean() error {
	_, err := s.clean()
	return err
}

func (s *Store) clean() (bool, error) {
	if s.reclaimEmpty() {
		return true, nil
	}
	selected := s.selectSegments()
	if len(selected) == 0 {
		return false, nil
	}
	for _, seg := range selected {
		if err := s.relocate(seg); err != nil {
			s.clearCleaning(selected)
			return false, err
		}
	}
	// The relocated records must be durable in the log before their source
	// segments disappear. The persistent index does not need to be flushed
	// here: it is a rebuildable cache, and recovery refuses to trust an index
	// that references a segment the cleaner has already reclaimed.
	if err := s.Barrier(); err != nil {
		s.clearCleaning(selected)
		return false, err
	}
	s.mu.Lock()
	s.stats.CleanPasses++
	s.mu.Unlock()
	for _, seg := range selected {
		if err := s.reclaim(seg); err != nil {
			s.clearCleaning(selected)
			return false, err
		}
	}
	return true, nil
}

// reclaimEmpty deletes sealed segments that hold nothing. They are produced
// when two writers both decide to roll the head, and they would otherwise
// accumulate forever because relocation has nothing to move out of them.
func (s *Store) reclaimEmpty() bool {
	s.mu.Lock()
	var empty []*segment
	for _, seg := range s.segments {
		if seg != s.head && seg.sealed && !seg.cleaning && seg.size == 0 {
			seg.cleaning = true
			empty = append(empty, seg)
		}
	}
	s.mu.Unlock()
	for _, seg := range empty {
		if err := s.reclaim(seg); err != nil {
			s.recordIndexError(err)
		}
	}
	return len(empty) > 0
}

type candidate struct {
	seg   *segment
	ratio float64
}

// selectSegments picks the segments whose relocation restores the target
// utilization, cheapest first, and marks them so a concurrent pass or the
// candidate scan does not consider them again.
func (s *Store) selectSegments() []*segment {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recomputeTotals()
	if s.opts.CleanUtilization <= 0 || s.stats.TotalBytes == 0 {
		return nil
	}
	if float64(s.stats.LiveBytes) >= s.opts.CleanUtilization*float64(s.stats.TotalBytes) {
		return nil
	}
	var candidates []candidate
	for _, seg := range s.segments {
		if seg == s.head || !seg.sealed || seg.cleaning || seg.size == 0 {
			continue
		}
		ratio := float64(seg.live) / float64(seg.size)
		if ratio >= s.opts.CleanUtilization {
			continue
		}
		candidates = append(candidates, candidate{seg: seg, ratio: ratio})
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].ratio != candidates[j].ratio {
			return candidates[i].ratio < candidates[j].ratio
		}
		return candidates[i].seg.id < candidates[j].seg.id
	})

	projectedLive := s.stats.LiveBytes
	projectedTotal := s.stats.TotalBytes
	var selected []*segment
	for _, c := range candidates {
		if len(selected) >= maxSegmentsPerPass {
			break
		}
		// Relocation keeps the live bytes and releases the dead remainder.
		projectedTotal -= c.seg.size - c.seg.live
		c.seg.cleaning = true
		selected = append(selected, c.seg)
		if float64(projectedLive) >= s.opts.CleanUtilization*float64(projectedTotal) {
			break
		}
	}
	return selected
}

func (s *Store) clearCleaning(segments []*segment) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, seg := range segments {
		seg.cleaning = false
	}
}

// relocate copies every still-live record of seg into the head segment.
func (s *Store) relocate(seg *segment) error {
	data, err := os.ReadFile(seg.path)
	if err != nil {
		return err
	}
	var offset int64
	for offset < int64(len(data)) {
		h, key, value, err := DecodeRecord(data[offset:])
		if err != nil {
			break
		}
		total := h.Total()
		if h.Kind == KindPut {
			loc := Loc{Off: offset, Seq: h.Seq, Seg: seg.id, Len: int32(total)}
			if err := s.stage(KindPut, string(key), value, h.Seq, &loc); err != nil {
				return err
			}
		}
		offset += total
	}
	return nil
}

// verifyLive recomputes a segment's live bytes directly from the index.
func (s *Store) verifyLive(seg *segment) (int64, error) {
	data, err := os.ReadFile(seg.path)
	if err != nil {
		return 0, err
	}
	var (
		offset int64
		live   int64
	)
	s.mu.Lock()
	defer s.mu.Unlock()
	for offset < int64(len(data)) {
		h, key, _, err := DecodeRecord(data[offset:])
		if err != nil {
			break
		}
		total := h.Total()
		if h.Kind == KindPut {
			if loc, ok := s.index[string(key)]; ok && loc.Seg == seg.id && loc.Off == offset {
				live += total
			}
		}
		offset += total
	}
	return live, nil
}

func (s *Store) reclaim(seg *segment) error {
	s.mu.Lock()
	if seg == s.head {
		seg.cleaning = false
		s.mu.Unlock()
		return nil
	}
	counted := seg.live
	s.mu.Unlock()
	if counted != 0 {
		// The per-segment counter is a selection heuristic. The index is the
		// only authority on liveness, so verify against it before giving up:
		// a stale counter would otherwise pin the segment forever and stall
		// the cleaner.
		actual, err := s.verifyLive(seg)
		if err != nil {
			return err
		}
		s.mu.Lock()
		if actual != 0 {
			seg.cleaning = false
			s.stats.CleanRetries++
			s.mu.Unlock()
			return nil
		}
		s.stats.LiveCorrections++
		s.stats.LiveCorrectedBytes += uint64(seg.live)
		seg.live = 0
		s.mu.Unlock()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := seg.read.Close(); err != nil {
		return err
	}
	if err := os.Remove(seg.path); err != nil {
		return err
	}
	delete(s.segments, seg.id)
	for i, id := range s.order {
		if id == seg.id {
			s.order = append(s.order[:i], s.order[i+1:]...)
			break
		}
	}
	s.stats.SegmentsReclaimed++
	s.stats.ReclaimedBytes += uint64(seg.size)
	s.recomputeTotals()
	return nil
}
