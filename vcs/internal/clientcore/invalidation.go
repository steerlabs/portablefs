package clientcore

import (
	"context"
	"path"
	"strings"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/coherence"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// InvalidationSubscriber is the fsproto subscription surface used by the shared invalidation loop.
// The AckFunc reports processed batch positions back to the authority (may be
// nil for sources without barrier-ack semantics).
type InvalidationSubscriber interface {
	Subscribe() (<-chan coherence.Batch, fsproto.AckFunc, error)
}

// InvalidationHandler is implemented by frontends to translate shared cache-coherence events into
// their kernel/cache invalidation mechanism. The core owns ordering, generation handling, recall,
// and version gates; the frontend owns only concrete notifications.
type InvalidationHandler interface {
	FlushAll()
	InvalidatePath(path string, inPlace bool)
	MarkOrphan(path string, ino uint64)
	ReleaseSubtree(path string)
}

type relatedInodeInvalidationHandler interface {
	InvalidateRelatedInodes(inos []uint64, eventPath string)
}

// InvalidationOptions holds frontend diagnostics/test seams.
type InvalidationOptions struct {
	DropOrphan  bool
	ClearRecent func()
	Debugf      func(string, ...any)

	// sleep overrides the resubscribe wait (tests observe the backoff
	// schedule without real sleeps). nil = a ctx-aware timer sleep.
	sleep func(ctx context.Context, d time.Duration)
}

func (o InvalidationOptions) clearRecent() {
	if o.ClearRecent != nil {
		o.ClearRecent()
	}
}

func (o InvalidationOptions) debugf(format string, args ...any) {
	if o.Debugf != nil {
		o.Debugf(format, args...)
	}
}

func (o InvalidationOptions) resubscribeWait(ctx context.Context, d time.Duration) {
	if o.sleep != nil {
		o.sleep(ctx, d)
		return
	}
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

// WatchInvalidations keeps a subscription to the authority and maintains the shared generation,
// attr-cache, recall, and orphan-redirection state. It reconnects when the stream drops, pacing
// resubscribe attempts with full-jitter exponential backoff — a fixed short timer here once meant
// a fleet of mounts pounded a recovering router in lockstep (1,000 mounts = thousands of connection
// attempts per second). A successful subscribe resets the schedule, so a single blip still recovers
// within the base delay. Callers cancel ctx when the frontend is detaching.
func WatchInvalidations(ctx context.Context, sub InvalidationSubscriber, versions *VersionCache, attrs *AttrCache, h InvalidationHandler, opts InvalidationOptions) {
	retry := fsproto.NewBackoff(fsproto.DefaultReconnectBase, fsproto.DefaultReconnectCap)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		stream, ack, err := sub.Subscribe()
		if err != nil {
			opts.resubscribeWait(ctx, retry.Next())
			continue
		}
		retry.Reset()
		h.FlushAll()
		opts.clearRecent()
		attrs.Clear()
		versions.Reset()
		for batch := range stream {
			for _, inv := range batch.Invs {
				if inv.Gen != 0 && !versions.SeenGen(inv.Gen) {
					versions.RefreshAll(inv.Gen)
					h.FlushAll()
					opts.clearRecent()
					attrs.Clear()
				}
				if inv.Recall {
					opts.debugf("RECALL received path=%q -> ReleaseSubtree", inv.Path)
					go h.ReleaseSubtree(inv.Path)
					continue
				}
				if inv.FlushAll {
					versions.RefreshAll(inv.Gen)
					h.FlushAll()
					opts.clearRecent()
					attrs.Clear()
					continue
				}
				if inv.Path == "" {
					continue
				}
				// P4 (deliberate coherence improvement over the old path-only apply): a NAME change
				// (create/remove/rename — anything not in-place) also advances the PARENT directory's
				// recorded version, not just the named path's. This is what lets a client evict a cached
				// negative for a sibling name the instant a peer creates/removes any child, closing the
				// window where a stale ENOENT could outlive the directory mutation that invalidated it.
				// Its server pair is workfs stampVersion's parent stamping, which bumps the parent
				// directory's version on the same mutations so the two versions advance together.
				if !inv.InPlace {
					versions.FillOK(inv.Gen, parentPath(inv.Path), inv.Version)
				}
				if versions.Apply(inv.Gen, inv.Path, inv.Version) {
					if inv.Orphaned && inv.OrphanIno != 0 && !opts.DropOrphan {
						h.MarkOrphan(inv.Path, inv.OrphanIno)
					}
					h.InvalidatePath(inv.Path, inv.InPlace)
					attrs.Evict(inv.Path)
					if related, ok := h.(relatedInodeInvalidationHandler); ok {
						related.InvalidateRelatedInodes(inv.RelatedInos, inv.Path)
					}
				}
			}
			// Acknowledge AFTER the batch is fully applied to every cache:
			// the authority's barriers treat this position as "this peer's
			// subsequent reads cannot serve pre-batch state".
			if ack != nil && (batch.Pos != 0 || batch.Bootstrap) {
				ack(batch.Pos)
			}
		}
		h.FlushAll()
		opts.clearRecent()
		attrs.Clear()
		versions.Reset()
	}
}

func parentPath(p string) string {
	d := path.Dir(strings.Trim(path.Clean("/"+p), "/"))
	if d == "." || d == "/" {
		return ""
	}
	return d
}
