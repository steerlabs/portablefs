package clientcore

// Installing a mutation's own post-op attributes.
//
// Every authority mutation reply carries the post-op state of the names its
// version stamp covered — the mutated name (or its proven absence) and, for a
// namespace mutation, the parent directory it rebound — anchored to the reply's
// generation and version (fsproto.PathAttr). This file installs that
// observation in the mount's version-gated caches.
//
// It is the root fix for the mutation→re-stat round trip. A write-through
// create used to evict its own name and its parent and then pay a full
// authority round trip for each one the moment the kernel asked for them again;
// the attributes it needed had already crossed the wire on the create reply.
// Nothing here caches anything the authority did not just state, and nothing
// here has a TTL: an installed entry lives under exactly the version anchor a
// read fill lives under, and a peer's invalidation supersedes it by the same
// monotonic comparison.
//
// ── THE COHERENCE RULE ──────────────────────────────────────────────────────
//
// An install is admitted by VersionCache.PublishOKToken, the SAME gate a
// tokened read fill goes through, and it therefore inherits all three of that
// gate's refusals:
//
//   - GENERATION: an authority restart/promotion re-anchors the cache; a reply
//     from the old generation cannot publish into the new one.
//   - FENCE: the token is captured at the START of the frontend operation,
//     before any RPC. A delegation ownership transition installed while the
//     mutation was in flight makes the token stale, so the reply — which
//     describes pre-transition authority state — cannot become readable
//     underneath the new owner's grant.
//   - MONOTONICITY: the entry publishes only while the path's retained version
//     floor has not passed this mutation's version. A concurrent peer mutation
//     carries a strictly greater version, so its invalidation either already
//     raised the floor (this install is refused) or arrives later and evicts
//     what was installed. An install can never travel backwards.
//
// Ordering with the operation's own eviction is deliberate and load-bearing:
// the mount evicts around a self-write (Volume.noteSelfMutation) while the
// reply is being processed, so the install runs LAST, from a defer in the
// frontend-facing operation, after every cache and registry step that operation
// performs. Reversing the two would leave the eviction as the final word and
// the round trip back where it started.

import (
	"context"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

type postAttrKey struct{}

// postAttrCollector is one frontend operation's install context: the cache
// epoch snapshot taken before its first authority RPC, and the sink its replies
// accumulate into.
type postAttrCollector struct {
	token CacheToken
	sink  fsproto.PostAttrSink
}

// withPostAttrs arms ctx to collect the post-op attributes of every authority
// mutation the operation issues, and snapshots the cache epoch they will be
// published against.
//
// The snapshot is taken HERE — at the top of the operation, before lane
// classification, before any delegation transition, before the RPC — because a
// token may only ever be too OLD, never too new. An operation whose token
// predates a fence that lands mid-flight simply does not publish; one that
// captured the fence it raced would publish state the fence exists to hide.
func (v *Volume) withPostAttrs(ctx context.Context) context.Context {
	c := &postAttrCollector{token: v.VersionCache.CaptureToken()}
	return fsproto.WithPostAttrs(context.WithValue(ctx, postAttrKey{}, c), &c.sink)
}

// installPostAttrs publishes everything the operation's mutation replies
// carried. It is a no-op for an operation that issued no authority mutation
// (the delegated lane acknowledges locally and reports nothing) and for an
// authority that does not advertise the capability.
func (v *Volume) installPostAttrs(ctx context.Context) {
	c, _ := ctx.Value(postAttrKey{}).(*postAttrCollector)
	if c == nil {
		return
	}
	for _, obs := range c.sink.Observations() {
		for _, entry := range obs.Attrs {
			v.installPostAttr(c.token, obs.Gen, obs.Version, entry)
		}
	}
}

// latestPostAttr returns the post-op attributes the operation's most recent
// authority mutation reported for path, and whether it reported any.
//
// It exists so an operation that OWES its caller the post-mutation attributes —
// setattr is the one that does — can answer from the reply that already
// produced them instead of issuing a getattr for state it just wrote. "Most
// recent" is what makes it correct for a multi-RPC setattr: a combined
// size+mode+owner request splits into one exact identity per group, and the
// last group's observation is the one that describes the final inode.
//
// An absent answer is not a degraded one: it means no mutation in this
// operation stamped a version on THIS name — an authority that does not carry
// post-op attributes at all, or a handle-addressed mutation whose wire path a
// peer renamed away, in which case the name is not evidence about the inode and
// the caller must address it by handle anyway.
func (v *Volume) latestPostAttr(ctx context.Context, path string) (fsproto.Attr, bool) {
	c, _ := ctx.Value(postAttrKey{}).(*postAttrCollector)
	if c == nil {
		return fsproto.Attr{}, false
	}
	path = cleanVolumePath(path)
	var (
		found fsproto.Attr
		ok    bool
	)
	for _, obs := range c.sink.Observations() {
		for _, entry := range obs.Attrs {
			if entry.Exists && cleanVolumePath(entry.Path) == path {
				found, ok = entry.Attr, true
			}
		}
	}
	return found, ok
}

func (v *Volume) installPostAttr(token CacheToken, gen, version uint64, entry fsproto.PathAttr) {
	path := cleanVolumePath(entry.Path)
	if !entry.Exists && !v.negativeCache {
		// The negative cache is switched off for this mount: the absence is
		// still a true statement, but the mount does not serve cached
		// negatives, so there is nothing to install.
		return
	}
	attr := entry.Attr
	exists := entry.Exists
	v.VersionCache.PublishOKToken(token, gen, path, version, func() {
		if exists {
			v.AttrCache.PutAttr(gen, version, path, attr)
			return
		}
		// A cached negative is ordered against its PARENT's version, which the
		// authority stamped with this same mutation — the parent rides the same
		// observation, so its floor is published in this same loop and the
		// lookup gate compares equal-to-equal.
		v.AttrCache.PutNegative(gen, version, path)
	})
}
