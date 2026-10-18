package portablefsd

import (
	"context"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// The daemon metadata cache.
//
// While this exact FSKit session holds the authority's compatibility-writer
// exclusion (fskit-versioned-metadata-v1), every logical metadata change the
// Mac can observe either returns through this data plane as a coherent read
// sample or whole mutation PostState, or ends eligibility before another
// writer can act. The cache is therefore exact state the daemon already
// receives, not a TTL: hits are served only under a KeepAlive proof horizon,
// immediate client admission, and the source-publication gate.
//
// Ordering uses the authority's one storage sequence. Attributes are ordered
// by actual object version within a sample snapshot; names by a per-directory
// watermark W of the newest applied name observation; and one attach-wide
// cold floor C, the greatest mutation snapshot processed, keeps a record
// interned from an older Lookup from adopting attrs or names that a mutation
// already processed while the identity was unheld had superseded. Allocation
// blocks and ctime are observational: they are retained as last observed and
// excluded from the equal-version agreement check.
const (
	// Negative entries are bounded by count and by name bytes; exhausting
	// either clears them all, because they are only a cache.
	v3MaxNegativeNames = 1 << 14
	v3MaxNegativeBytes = 1 << 20
)

// v3LogicalAttrEqual compares the fields that must agree whenever the object
// version agrees. Blocks and ctime are observational (allocation drift and the
// restore-mode ctime exception); blksize is not rendered.
func v3LogicalAttrEqual(left, right *authoritypb.Attr) bool {
	return left != nil && right != nil &&
		left.GetKind() == right.GetKind() && left.GetInode() == right.GetInode() &&
		left.GetSize() == right.GetSize() && left.GetMode() == right.GetMode() &&
		left.GetUid() == right.GetUid() && left.GetGid() == right.GetGid() &&
		left.GetNlink() == right.GetNlink() && left.GetAtimeNs() == right.GetAtimeNs() &&
		left.GetMtimeNs() == right.GetMtimeNs() && left.GetBirthTimeNs() == right.GetBirthTimeNs() &&
		left.GetRdev() == right.GetRdev() && left.GetFlags() == right.GetFlags()
}

// v3LookupPermissionsEqual reports whether a directory's lookup-relevant
// permission state is unchanged. The daemon does not evaluate permissions
// itself; it only refuses to let a name observed under one permission state
// answer under another.
func v3LookupPermissionsEqual(previous, next *authoritypb.Attr) bool {
	return previous != nil && previous.GetMode() == next.GetMode() &&
		previous.GetUid() == next.GetUid() && previous.GetGid() == next.GetGid()
}

// observeLocked applies one validated sample (0 < v <= s) to a live record,
// for reads and mutations alike. An older version is discarded even while the
// record is invalid; an invalid record also respects its snapshot floor; at an
// equal version the logical fields must agree, a newer snapshot may refresh
// the observational ones, and an exact tie keeps what is held. A legally
// concurrent older result arriving later is simply discarded. d.mu is held.
func (d *v3DataPlane) observeLocked(record *v3ItemRecord, attr *authoritypb.Attr, version, snapshot uint64) error {
	if attr.GetInode() != record.inode || attr.GetKind() != record.kind {
		return errors.New("portablefsd: authority sample changed the inode or kind of a held identity")
	}
	switch {
	case version < record.version:
		return nil
	case !record.valid:
		if snapshot < record.snapshot {
			return nil
		}
	case version == record.version:
		if !v3LogicalAttrEqual(record.attr, attr) {
			return fmt.Errorf("portablefsd: authority object version %d carried different logical attributes", version)
		}
		if snapshot <= record.snapshot {
			return nil
		}
	}
	previous := record.attr
	record.attr = cloneAuthorityAttr(attr)
	record.valid, record.version, record.snapshot = true, version, snapshot
	if record.kind == authoritypb.Attr_DIRECTORY && !v3LookupPermissionsEqual(previous, attr) {
		// Every name below was observed under the previous permission state.
		d.forgetNamesLocked(record)
		record.watermark = max(record.watermark, version)
	}
	return nil
}

// bindNameLocked records child as the remembered binding at parent/name. A
// record remembers one binding, so a hard-link alias replaces the previous
// one. d.mu is held.
func (d *v3DataPlane) bindNameLocked(parent *v3ItemRecord, name string, child *v3ItemRecord) {
	d.dropNameLocked(parent, name)
	if child.root {
		return
	}
	if previous := child.binding; previous != nil && previous.parent.children[previous.name] == child {
		delete(previous.parent.children, previous.name)
	}
	if parent.children == nil {
		parent.children = make(map[string]*v3ItemRecord)
	}
	parent.children[name] = child
	child.binding = &v3Binding{parent: parent, name: name}
}

// dropNameLocked forgets both cached answers at one coordinate. d.mu is held.
func (d *v3DataPlane) dropNameLocked(parent *v3ItemRecord, name string) {
	if child := parent.children[name]; child != nil {
		child.binding = nil
		delete(parent.children, name)
	}
	if _, absent := parent.negatives[name]; absent {
		delete(parent.negatives, name)
		d.negativeNames--
		d.negativeBytes -= len(name)
		if len(parent.negatives) == 0 {
			parent.negatives = nil
			delete(d.negativeDirs, parent)
		}
	}
}

// recordAbsenceLocked caches an authoritative absence. d.mu is held.
func (d *v3DataPlane) recordAbsenceLocked(parent *v3ItemRecord, name string) {
	d.dropNameLocked(parent, name)
	if d.negativeNames+1 > v3MaxNegativeNames || d.negativeBytes+len(name) > v3MaxNegativeBytes {
		for dir := range d.negativeDirs {
			dir.negatives = nil
		}
		clear(d.negativeDirs)
		d.negativeNames, d.negativeBytes = 0, 0
	}
	if parent.negatives == nil {
		parent.negatives = make(map[string]struct{})
		d.negativeDirs[parent] = struct{}{}
	}
	parent.negatives[name] = struct{}{}
	d.negativeNames++
	d.negativeBytes += len(name)
}

// forgetNamesLocked drops every positive and negative entry beneath a
// directory, and the parent references of the children it named. d.mu is
// held.
func (d *v3DataPlane) forgetNamesLocked(dir *v3ItemRecord) {
	for _, child := range dir.children {
		child.binding = nil
	}
	dir.children = nil
	if dir.negatives != nil {
		for name := range dir.negatives {
			d.negativeNames--
			d.negativeBytes -= len(name)
		}
		dir.negatives = nil
		delete(d.negativeDirs, dir)
	}
}

// fillLookupLocked applies a coherent Lookup sample's name through the exact
// parent record the request used. It fills only when that record is still
// live and the sample is not older than the directory's watermark; an older
// sample installs neither a positive nor a negative and leaves newer entries
// alone. target is nil for a genuine authoritative absence. d.mu is held.
func (d *v3DataPlane) fillLookupLocked(parent *v3ItemRecord, name string, target *v3ItemRecord, snapshot uint64) {
	if d.terminal != nil || d.itemsByID[parent.item.ItemID] != parent || snapshot < parent.watermark {
		return
	}
	parent.watermark = snapshot
	switch {
	case target == nil:
		d.recordAbsenceLocked(parent, name)
	case d.itemsByID[target.item.ItemID] == target:
		d.bindNameLocked(parent, name, target)
	default:
		d.dropNameLocked(parent, name)
	}
}

// observeHeld applies a read sample to a record still live under its exact
// local handle; an escaped pointer to a retired record never fills its
// replacement. It reports a terminal disagreement.
func (d *v3DataPlane) observeHeld(record *v3ItemRecord, attr *authoritypb.Attr, version, snapshot uint64) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.terminal != nil || d.itemsByID[record.item.ItemID] != record {
		return nil
	}
	return d.observeLocked(record, attr, version, snapshot)
}

// applyMutation installs one durable source effect at its authority snapshot.
// Advancing the cold floor first prevents older in-flight reads from restoring
// metadata or name knowledge contradicted by this settled effect.
func (d *v3DataPlane) applyMutation(effect *v3MutationEffect) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.coldFloor = max(d.coldFloor, effect.snapshot)
	if d.terminal != nil {
		return nil
	}
	for _, object := range effect.objects {
		if record := d.itemsByIdentity[object.identity]; record != nil {
			if err := d.observeLocked(record, object.attr, object.version, effect.snapshot); err != nil {
				return err
			}
		}
	}
	for start := 0; start < len(effect.names); {
		parent := effect.names[start].parent
		end := start
		for end < len(effect.names) && effect.names[end].parent == parent {
			end++
		}
		touched := effect.names[start:end]
		start = end
		if d.itemsByID[parent.item.ItemID] != parent {
			continue
		}
		current := effect.snapshot >= parent.watermark
		for _, name := range touched {
			switch {
			case !current:
				d.dropNameLocked(parent, name.name)
			case !name.bound:
				d.recordAbsenceLocked(parent, name.name)
			default:
				if child := d.itemsByIdentity[name.identity]; child != nil {
					d.bindNameLocked(parent, name.name, child)
				} else {
					d.dropNameLocked(parent, name.name)
				}
			}
		}
		if current {
			parent.watermark = effect.snapshot
		}
	}
	return nil
}

// cacheAdmissionLocked is the session half of hit admission: a live data
// plane, a proven horizon not yet reached on the continuous clock, immediate
// client admission, and the installed signed authorization deadline as an
// extra local denial. H expiry alone does not end the session; it only makes
// every read take the authority path. d.mu is held.
func (d *v3DataPlane) cacheAdmissionLocked() v3CacheResult {
	if d.terminal != nil || !d.client.LocalAdmissionOpen() {
		return v3CacheTerminal
	}
	if !d.authorizationDeadline.IsZero() && !time.Now().Before(d.authorizationDeadline) {
		return v3CacheAuthorization
	}
	if d.horizon == 0 {
		return v3CacheHorizon
	}
	if now, err := d.readClockLocked(); err != nil {
		return v3CacheClock
	} else if now >= d.horizon {
		return v3CacheHorizon
	}
	return v3CacheHit
}

func v3AttributeCoordinate(record *v3ItemRecord) v3PublicationCoordinate {
	return v3PublicationCoordinate{kind: v3PublicationItemAttributes, item: v3PublicationIdentity(record.item.StableIdentity)}
}

func v3NamespaceCoordinate(parent *v3ItemRecord, name string) v3PublicationCoordinate {
	return v3PublicationCoordinate{kind: v3PublicationNamespaceName, parent: v3PublicationIdentity(parent.item.StableIdentity), name: name}
}

// attrHitLocked answers an item or handle GetAttr from a valid, unconflicted
// record. Coordinator then d.mu are held.
func (d *v3DataPlane) attrHitLocked(conflict v3CacheConflict, item *v3ItemRecord, handle *v3HandleRecord) (pfslocal.Attr, v3CacheResult) {
	if reason := d.cacheAdmissionLocked(); reason != v3CacheHit {
		return pfslocal.Attr{}, reason
	}
	if d.itemsByID[item.item.ItemID] != item || handle != nil && d.handles[handle.id] != handle {
		return pfslocal.Attr{}, v3CacheResource
	}
	if !item.valid {
		return pfslocal.Attr{}, v3CacheCold
	}
	if reason := conflict(v3AttributeCoordinate(item)); reason != v3CacheHit {
		return pfslocal.Attr{}, reason
	}
	attr, err := d.localAttr(item, item.attr, d.parentOfLocked(item))
	if err != nil {
		return pfslocal.Attr{}, v3CacheResource
	}
	return attr, v3CacheHit
}

func (d *v3DataPlane) lookupHitLocked(conflict v3CacheConflict, parent *v3ItemRecord, name string, collector *v3ReplyResourceCollector) (any, int32, v3CacheResult) {
	if reason := d.cacheAdmissionLocked(); reason != v3CacheHit {
		return nil, 0, reason
	}
	if d.itemsByID[parent.item.ItemID] != parent {
		return nil, 0, v3CacheResource
	}
	if !parent.valid {
		return nil, 0, v3CacheCold
	}
	if reason := conflict(v3AttributeCoordinate(parent), v3NamespaceCoordinate(parent, name)); reason != v3CacheHit {
		return nil, 0, reason
	}
	if child := parent.children[name]; child != nil {
		if d.itemsByID[child.item.ItemID] != child {
			return nil, 0, v3CacheResource
		}
		if !child.valid {
			return nil, 0, v3CacheCold
		}
		if reason := conflict(v3AttributeCoordinate(child)); reason != v3CacheHit {
			return nil, 0, reason
		}
		attr, err := d.localAttr(child, child.attr, v3ParentOf(parent))
		if err != nil || collector != nil && child.provisional == math.MaxUint32 {
			return nil, 0, v3CacheResource
		}
		if collector != nil {
			child.provisional++
			collector.items = append(collector.items, child)
		}
		return &pfslocal.LookupReply{Attr: attr}, 0, v3CacheHit
	}
	if _, absent := parent.negatives[name]; absent {
		return nil, darwinENOENT, v3CacheHit
	}
	return nil, 0, v3CacheUnknownName
}

// v3CachedReply owns an unexposed snapshot. Proof or authorization expiry admits
// one authority miss; terminal admission or lost ownership never substitutes a reply.
type v3CachedReply struct {
	revalidate func() bool
	expired    bool
	metric     int
	accounted  bool
}

// serveCachedAttr is the GetAttr half of hit admission for currentAttr.
func (d *v3DataPlane) serveCachedAttr(ctx context.Context, operationID uint64, item *v3ItemRecord, handle *v3HandleRecord) (pfslocal.Attr, bool, int32) {
	var attr pfslocal.Attr
	hit, errno := d.serveCached(ctx, operationID, 0, func(conflict v3CacheConflict, _ *v3ReplyResourceCollector) v3CacheResult {
		var reason v3CacheResult
		attr, reason = d.attrHitLocked(conflict, item, handle)
		return reason
	}, func() bool {
		return d.itemsByID[item.item.ItemID] == item && (handle == nil || d.handles[handle.id] == handle)
	})
	return attr, hit, errno
}

// serveCachedLookup is the Lookup half of hit admission.
func (d *v3DataPlane) serveCachedLookup(ctx context.Context, operationID uint64, parent *v3ItemRecord, name string) (any, int32, bool) {
	var (
		reply  any
		errno  int32
		target *v3ItemRecord
	)
	hit, localErrno := d.serveCached(ctx, operationID, 1, func(conflict v3CacheConflict, collector *v3ReplyResourceCollector) v3CacheResult {
		var reason v3CacheResult
		reply, errno, reason = d.lookupHitLocked(conflict, parent, name, collector)
		if reason == v3CacheHit && reply != nil {
			target = collector.items[len(collector.items)-1]
		}
		return reason
	}, func() bool {
		return d.itemsByID[parent.item.ItemID] == parent && (target == nil || d.itemsByID[target.item.ItemID] == target && target.provisional != 0)
	})
	if localErrno != 0 {
		return nil, localErrno, true
	}
	return reply, errno, hit
}

// serveCached admits one hit as an operation: it takes an immediate client
// admission receipt that participates in terminal revocation, snapshots the
// cache atomically with the nonwaiting source-publication check
// (coordinator → d.mu), retains the receipt for the callback's publication
// lifetime exactly like an authority response, and records the revalidation
// the physical write will run. A conflict, an unadmitted session, or any other
// miss returns hit=false for the ordinary coherent authority path.
func (d *v3DataPlane) serveCached(
	ctx context.Context,
	operationID uint64,
	metric int,
	snapshot func(v3CacheConflict, *v3ReplyResourceCollector) v3CacheResult,
	owns func() bool,
) (bool, int32) {
	result := v3CacheBypass
	collector, _ := ctx.Value(v3ReplyResourceContextKey{}).(*v3ReplyResourceCollector)
	// An exposure-expired candidate already records the miss that caused its
	// one authority attempt; that attempt is not a second cache decision.
	if collector != nil && collector.bypassCache {
		return false, 0
	}
	defer func() {
		if result != v3CacheHit {
			d.recordCacheResult(metric, result)
		}
	}()
	if collector == nil || collector.d != d || collector.taken {
		return false, 0
	}
	// A session that cannot admit any hit right now (no proof horizon, say)
	// takes the authority path without registering a receipt.
	d.mu.Lock()
	result = d.cacheAdmissionLocked()
	d.mu.Unlock()
	if d.endOnClockFault() != nil {
		return true, darwinEIO
	}
	if result != v3CacheHit {
		return false, 0
	}
	receipt, err := d.client.BeginLocalPublication(func(cause error) {
		d.revokeRetainedResponse(ctx, errors.Join(
			errors.New("portablefsd: cached reply crossed its frontend delivery bound"), cause,
		))
	})
	if err != nil {
		result = v3CacheTerminal
		return false, 0
	}
	receipt = traceV3Consumption(ctx, receipt)
	d.bridge.sourcePublication.cacheRead(func(conflict v3CacheConflict) {
		d.mu.Lock()
		defer d.mu.Unlock()
		result = snapshot(conflict, collector)
	})
	if d.endOnClockFault() != nil {
		result = v3CacheClock
		receipt.Consume()
		return true, darwinEIO
	}
	if result != v3CacheHit {
		receipt.Consume()
		return false, 0
	}
	if err := d.retainLocalPublication(ctx, collector, operationID, receipt); err != nil {
		result = v3CacheTerminal
		d.revokeRetainedResponse(ctx, err)
		return true, darwinEIO
	}
	candidate := &v3CachedReply{metric: metric}
	candidate.revalidate = func() bool {
		d.mu.Lock()
		reason := d.cacheAdmissionLocked()
		owned := owns()
		candidate.expired = (reason == v3CacheHorizon || reason == v3CacheAuthorization) && owned && d.clockFault == nil
		if reason == v3CacheHit && !owned {
			reason = v3CacheResource
		}
		if reason != v3CacheHit && !candidate.accounted {
			d.cacheCounters.reads[metric][reason]++
			candidate.accounted = true
		}
		d.mu.Unlock()
		return d.endOnClockFault() == nil && reason == v3CacheHit && owned
	}
	collector.cached = candidate
	return true, 0
}

func (d *v3DataPlane) retainLocalPublication(ctx context.Context, collector *v3ReplyResourceCollector, operationID uint64, receipt authorityrpc.ResponseConsumption) error {
	if operationID == 0 {
		return retainV3HandlerResponse(collector, receipt)
	}
	return d.bridge.sourcePublication.retainFrontendResponseConsumption(v3Callback(ctx, operationID), receipt)
}

// settleNameErrno invalidates an affected name on a definite namespace
// refusal. It does not manufacture a causal proof from previously cached state.
func (d *v3DataPlane) settleNameErrno(parent *v3ItemRecord, name []byte, errno int32) int32 {
	if errno == darwinEEXIST || errno == darwinENOENT {
		d.mu.Lock()
		if d.itemsByID[parent.item.ItemID] == parent {
			d.dropNameLocked(parent, string(name))
		}
		d.mu.Unlock()
	}
	return errno
}
