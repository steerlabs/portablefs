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
	InvalidateRelatedInodes(inos []uint64, eventPath string, gen, version uint64, namespaceChange bool)
}

// InvalidationOptions holds frontend diagnostics/test seams.
type InvalidationOptions struct {
	DropOrphan  bool
	ClearRecent func()
	Debugf      func(string, ...any)

	// Anchored fires each time the authority confirms this mount is a
	// registered subscriber (the stream's bootstrap message) and the caches
	// have been fenced against everything filled before that point. Frontends
	// use the first call as "this mount may now serve cached reads".
	Anchored func()

	// sleep overrides the resubscribe wait (tests observe the backoff
	// schedule without real sleeps). nil = a ctx-aware timer sleep.
	sleep func(ctx context.Context, d time.Duration)
}

func (o InvalidationOptions) clearRecent() {
	if o.ClearRecent != nil {
		o.ClearRecent()
	}
}

func (o InvalidationOptions) anchored() {
	if o.Anchored != nil {
		o.Anchored()
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
		streamToken := versions.CaptureToken()
		for batch := range stream {
			if batch.Bootstrap {
				// SUBSCRIPTION ANCHOR. The flush above happened when the
				// subscribe REQUEST was written; the authority only added this
				// mount to its subscriber set (and snapshotted the stream
				// position) later, when it read that request. Every mutation
				// committed in between was published to a set this mount was
				// not in, and the stream has no replay — so those events are
				// gone forever. Anything cached in that window would then be
				// stale with no event left that could evict it, which is how a
				// peer's create stayed invisible for minutes.
				//
				// Adopting the generation below cannot close that window: a
				// frontend read racing the subscribe already adopts the same
				// generation, after which AcceptGeneration is a no-op and the
				// pre-registration fills survive. The bootstrap is the exact
				// point at which the authority guarantees "from here on you get
				// every event", so it fences unconditionally instead.
				h.FlushAll()
				opts.clearRecent()
				attrs.Clear()
				streamToken = versions.AnchorSubscription(bootstrapGen(batch))
				opts.debugf("invalidation stream anchored gen=%d pos=%d",
					bootstrapGen(batch), batch.Pos)
				opts.anchored()
			}
			for _, inv := range batch.Invs {
				generationOK := true
				if inv.Gen != 0 {
					if !versions.SeenGen(inv.Gen) {
						var ok bool
						streamToken, ok = versions.AcceptGeneration(streamToken, inv.Gen)
						generationOK = ok
						h.FlushAll()
						opts.clearRecent()
						attrs.Clear()
					} else {
						// A concurrent tokened read may adopt this valid
						// stream's generation first. Join that same nonce so
						// a later overflow FlushAll can retire every retained
						// version floor; a different-generation stream still
						// fails closed above.
						var ok bool
						streamToken, ok = versions.TokenForGeneration(inv.Gen)
						generationOK = ok
					}
				}
				if inv.Recall {
					opts.debugf("RECALL received path=%q -> ReleaseSubtree", inv.Path)
					go h.ReleaseSubtree(inv.Path)
					continue
				}
				if inv.FlushAll {
					if generationOK {
						var ok bool
						streamToken, ok = versions.FlushGeneration(streamToken, inv.Gen)
						generationOK = ok
					}
					h.FlushAll()
					opts.clearRecent()
					attrs.Clear()
					continue
				}
				if !generationOK {
					// This stream lost the generation race to a newer tokened
					// observation. Its events may conservatively flush caches
					// and recall grants, but can never re-anchor versions.
					continue
				}
				if inv.Path == "" {
					if related, ok := h.(relatedInodeInvalidationHandler); ok &&
						len(inv.RelatedInos) != 0 {
						related.InvalidateRelatedInodes(
							inv.RelatedInos,
							"",
							inv.Gen,
							inv.Version,
							false,
						)
					}
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
					versions.Apply(inv.Gen, parentPath(inv.Path), inv.Version)
				}
				appliedPath := versions.Apply(inv.Gen, inv.Path, inv.Version)
				if appliedPath {
					if inv.Orphaned && inv.OrphanIno != 0 && !opts.DropOrphan {
						h.MarkOrphan(inv.Path, inv.OrphanIno)
					}
					h.InvalidatePath(inv.Path, inv.InPlace)
					attrs.Evict(inv.Path)
				}
				if related, ok := h.(relatedInodeInvalidationHandler); ok {
					// The primary path may already have this exact (or a
					// newer) version because an authority read raced ahead of
					// stream delivery. Related aliases have independent path
					// floors and caches, so their fan-out cannot be conditional
					// on Apply(primary) advancing. Per-alias FillOK remains
					// monotonic, and generationOK above excludes stale streams.
					relatedGen, relatedVersion := uint64(0), uint64(0)
					if inv.InPlace {
						// Only in-place events stamp the same inode changed
						// through all aliases. Namespace events may name a
						// surviving related inode with its own version.
						relatedGen, relatedVersion = inv.Gen, inv.Version
					}
					related.InvalidateRelatedInodes(
						inv.RelatedInos,
						inv.Path,
						relatedGen,
						relatedVersion,
						!inv.InPlace,
					)
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

// bootstrapGen reads the authority generation the stream announced in its
// bootstrap message. A source without generations reports zero, which anchors
// the caches to "unknown generation" exactly like a fresh Reset.
func bootstrapGen(batch coherence.Batch) uint64 {
	for _, inv := range batch.Invs {
		if inv.Gen != 0 {
			return inv.Gen
		}
	}
	return 0
}

func parentPath(p string) string {
	d := path.Dir(strings.Trim(path.Clean("/"+p), "/"))
	if d == "." || d == "/" {
		return ""
	}
	return d
}
