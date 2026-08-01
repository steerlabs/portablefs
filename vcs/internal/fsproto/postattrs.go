package fsproto

// Post-op mutation attributes, client side.
//
// A mutation reply already carries the post-op state of every name its version
// stamp covered (Response.PostAttrs, see fsproto.go). This file hands that
// observation to the caller that issued the mutation, so the mount can INSTALL
// it in its version-gated caches rather than evict and re-read what it just
// wrote.
//
// The handoff is a context-carried sink rather than a return value or a
// mount-wide callback, for two reasons that are both about ORDER:
//
//   - The install must happen AFTER the operation's own cache bookkeeping. The
//     typed helpers publish self-write versions and the mount evicts around
//     them; an install that ran inside the helper would be clobbered by the
//     eviction that follows it. The caller owns that order and is the only
//     place that can be sure the install is last.
//   - One frontend operation can issue several authority mutations (an unlink
//     that parks an orphan, a rename that resolves a destination), each with
//     its own version. Keeping the observations as a list preserves that: each
//     one carries the anchor it was stamped with, and none is attributed to
//     another's version.
//
// The sink is deliberately inert on its own: collecting costs nothing but a
// slice append, and a caller that installs nothing simply keeps the
// evict-and-refetch behavior.

import (
	"context"
	"sync"
)

// PostObservation is one mutation reply's post-op attribute set together with
// the coherence anchor every element of it shares.
type PostObservation struct {
	Gen     uint64
	Version uint64
	Attrs   []PathAttr
}

// PostAttrSink accumulates the post-op observations of one frontend operation.
// The zero value is ready to use. It is mutex-guarded because a single
// operation may issue its mutations from more than one goroutine.
type PostAttrSink struct {
	mu  sync.Mutex
	obs []PostObservation
}

// Observations returns the observations collected so far, oldest first.
func (s *PostAttrSink) Observations() []PostObservation {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]PostObservation(nil), s.obs...)
}

func (s *PostAttrSink) add(o PostObservation) {
	s.mu.Lock()
	s.obs = append(s.obs, o)
	s.mu.Unlock()
}

type postAttrSinkKey struct{}

// WithPostAttrs arms ctx to collect the post-op attributes of every authority
// mutation issued under it.
func WithPostAttrs(ctx context.Context, sink *PostAttrSink) context.Context {
	if sink == nil {
		return ctx
	}
	return context.WithValue(ctx, postAttrSinkKey{}, sink)
}

func postAttrSinkOf(ctx context.Context) *PostAttrSink {
	s, _ := ctx.Value(postAttrSinkKey{}).(*PostAttrSink)
	return s
}

// collectPostAttrs records a successful mutation reply's post-op attributes in
// the caller's sink.
//
// The lane is selected from the negotiated feature bit, never from the reply's
// shape: an empty PostAttrs is a legitimate answer (a handle- or
// orphan-addressed mutation stamps no nameable path), so it cannot be read as
// "this authority does not speak it".
//
// A DUPLICATE reply is excluded on purpose. Its stored outcome is the essential
// bytes only — it carries no attributes, and it is answered from a slot table
// rather than from a fresh ordered apply, so there is no observation whose
// version anchor could be trusted. The replaying client re-stats, exactly as it
// does today.
func (c *Client) collectPostAttrs(ctx context.Context, r *Response) {
	if r == nil || r.Status != OK || r.Duplicate || r.Gen == 0 || len(r.PostAttrs) == 0 {
		return
	}
	if c.Features()&FeatureMutationAttrs == 0 {
		return
	}
	sink := postAttrSinkOf(ctx)
	if sink == nil {
		return
	}
	sink.add(PostObservation{
		Gen:     r.Gen,
		Version: r.Version,
		Attrs:   append([]PathAttr(nil), r.PostAttrs...),
	})
}
