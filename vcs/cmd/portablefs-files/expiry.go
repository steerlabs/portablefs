package main

import "time"

// Registry mutations wake the expiry owner when its next real deadline may
// have changed. The empty registry owns no timer.
func (s *server) signalExpiryChangedLocked() {
	if s.expiryChanged != nil {
		close(s.expiryChanged)
		s.expiryChanged = nil
	}
}

func (s *server) sweep(stop <-chan struct{}) {
	for {
		now := time.Now()
		var next time.Time
		retainDeadline := func(deadline time.Time) {
			if next.IsZero() || deadline.Before(next) {
				next = deadline
			}
		}
		var staleCursors []cursorRecord
		var staleSessions []*volumeSession
		s.mu.Lock()
		if s.expiryChanged == nil {
			s.expiryChanged = make(chan struct{})
		}
		changed := s.expiryChanged
		for token, record := range s.cursors {
			if !now.Before(record.expiresAt) {
				staleCursors = append(staleCursors, record)
				delete(s.cursors, token)
			} else {
				retainDeadline(record.expiresAt)
			}
		}
		for volumeID, record := range s.fences {
			deadline := record.recordedAt.Add(fenceRetention)
			if !now.Before(deadline) {
				delete(s.fences, volumeID)
			} else {
				retainDeadline(deadline)
			}
		}
		for volumeID, session := range s.sessions {
			deadline := session.expiresAt
			idle := time.Unix(0, session.lastUsedUnix.Load()).Add(sessionIdleTime)
			if idle.Before(deadline) {
				deadline = idle
			}
			if !now.Before(deadline) || session.client.Err() != nil {
				staleSessions = append(staleSessions, session)
				delete(s.sessions, volumeID)
				staleCursors = append(staleCursors, s.removeVolumeCursorsLocked(volumeID)...)
			} else {
				retainDeadline(deadline)
			}
		}
		s.mu.Unlock()
		closeCursors(staleCursors)
		for _, session := range staleSessions {
			session.mu.Lock()
			_ = session.client.Close()
			session.mu.Unlock()
		}
		var timer *time.Timer
		var expired <-chan time.Time
		if !next.IsZero() {
			timer = time.NewTimer(time.Until(next))
			expired = timer.C
		}
		select {
		case <-stop:
			if timer != nil {
				timer.Stop()
			}
			return
		case <-changed:
		case <-expired:
		}
		if timer != nil {
			timer.Stop()
		}
	}
}
