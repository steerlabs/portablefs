package volumeserver

import (
	"context"
	"time"
)

// CacheAdmission records facts that a reply may install. Call while the storage
// dependencies protecting that reply are still held. Admissions are scoped to
// the exact cold-subscription incarnation, never just the session ID.
type CacheAdmission struct {
	Directories, Attributes, Data [][16]byte
}

type cacheFootprint struct {
	identities map[[16]byte]struct{}
	all        bool
}

func (f *cacheFootprint) add(ids [][16]byte, limit int) {
	if f.all {
		return
	}
	for _, id := range ids {
		if id == ([16]byte{}) {
			continue
		}
		if _, ok := f.identities[id]; ok {
			continue
		}
		if len(f.identities) >= limit {
			f.identities = nil
			f.all = true
			return
		}
		if f.identities == nil {
			f.identities = make(map[[16]byte]struct{})
		}
		f.identities[id] = struct{}{}
	}
}
func (f *cacheFootprint) has(id [16]byte) bool {
	if f.all {
		return true
	}
	_, ok := f.identities[id]
	return ok
}
func (s *changeSubscriber) admit(a CacheAdmission, limit int) {
	s.directories.add(a.Directories, limit)
	s.attributes.add(a.Attributes, limit)
	s.data.add(a.Data, limit)
}
func (s *changeSubscriber) couldCache(e ChangeEntry) bool {
	switch e.Kind {
	case NamespaceChanged:
		return s.directories.has(e.ParentIdentity)
	case DirectoryChanged:
		return s.directories.has(e.Identity)
	case AttributesChanged:
		return s.attributes.has(e.Identity)
	case DataChanged:
		return s.data.has(e.Identity)
	default:
		return true
	}
}

func (c *CoherenceCoordinator) AdmitCache(token SubscriptionToken, a CacheAdmission) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, err := c.subscriberLocked(token)
	if err != nil {
		return err
	}
	s.admit(a, c.maxCacheFootprint)
	return nil
}

// Withdrawal retains exact target incarnations from the commit cut. Broadcast
// delivery remains intact; a subscriber with no affected facts need not delay
// the committing syscall while it processes the stream.
type Withdrawal struct {
	// SourceCurrent is false if a cold replacement won before the commit.
	// The caller must refuse the old request's cache-bearing reply.
	SourceCurrent bool
	Position      uint64
	targets       []SubscriptionToken
	deadline      time.Time
}

func (c *CoherenceCoordinator) OnCommitTargeted(entries []ChangeEntry, source SubscriptionToken, a CacheAdmission) Withdrawal {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked()
	result := Withdrawal{deadline: c.clock.Now().Add(SubscriptionTTL)}
	if len(entries) > 0 {
		for _, s := range c.subscribers {
			if s.token == source || s.ackIndex < 0 {
				continue
			}
			for _, e := range entries {
				if s.couldCache(e) {
					result.targets = append(result.targets, s.token)
					break
				}
			}
		}
		for _, e := range entries {
			c.watermark = max(c.watermark, e.VolumeVersion)
			result.Position = c.appendLocked(StreamEvent{Kind: StreamChange, Change: e, Source: source.Session, LocalOwner: source})
		}
	}
	// Source facts describe the post-commit reply, including successful CREATE
	// of an existing name with no change entries. A cold successor cannot inherit
	// an old request's source exclusion or its reply admission.
	if s := c.subscribers[source.Session]; s != nil && s.token == source && s.ackIndex >= 0 {
		s.admit(a, c.maxCacheFootprint)
		result.SourceCurrent = true
	}
	return result
}

func (c *CoherenceCoordinator) WaitTargeted(ctx context.Context, w Withdrawal) error {
	for {
		c.mu.Lock()
		c.expireLocked()
		if w.Position > c.position {
			c.mu.Unlock()
			return ErrSubscriptionPosition
		}
		var pending *changeSubscriber
		now := c.clock.Now()
		for _, token := range w.targets {
			s := c.subscribers[token.Session]
			if s == nil || s.token != token || s.ackIndex < 0 || s.acked >= w.Position {
				continue
			}
			if !now.Before(w.deadline) {
				c.retireSubscriberLocked(s)
				continue
			}
			if pending == nil || s.horizon.Before(pending.horizon) {
				pending = s
			}
		}
		if pending == nil {
			c.mu.Unlock()
			return nil
		}
		changed, deadline := c.notificationLocked(), minTime(pending.horizon, w.deadline)
		c.mu.Unlock()
		if err := c.wait(ctx, changed, deadline); err != nil {
			return err
		}
	}
}
