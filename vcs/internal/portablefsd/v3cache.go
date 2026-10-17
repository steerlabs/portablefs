package portablefsd

import (
	"context"
	"errors"
	"fmt"
	"math"
	"reflect"
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

// applyMutation applies one whole validated mutation result in one
// transaction: the cold floor first, then every held identity's attrs, then
// the touched names directory by directory. A directory whose watermark is
// newer than this snapshot drops the touched coordinates instead of installing
// them, because an unrelated newer observation may have advanced W without
// repairing this name. Unheld identities allocate nothing.
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

// cacheAdmissibleLocked is the session half of hit admission: a live data
// plane, a proven horizon not yet reached on the continuous clock, immediate
// client admission, and the installed signed authorization deadline as an
// extra local denial. H expiry alone does not end the session; it only makes
// every read take the authority path. d.mu is held.
func (d *v3DataPlane) cacheAdmissibleLocked() bool {
	if d.terminal != nil || d.horizon == 0 || !d.client.LocalAdmissionOpen() {
		return false
	}
	if now, err := d.clock(); err != nil || now >= d.horizon {
		return false
	}
	return d.authorizationDeadline.IsZero() || time.Now().Before(d.authorizationDeadline)
}

func v3AttributeCoordinate(record *v3ItemRecord) v3PublicationCoordinate {
	return v3PublicationCoordinate{kind: v3PublicationItemAttributes, item: v3PublicationIdentity(record.item.StableIdentity)}
}

func v3NamespaceCoordinate(parent *v3ItemRecord, name string) v3PublicationCoordinate {
	return v3PublicationCoordinate{kind: v3PublicationNamespaceName, parent: v3PublicationIdentity(parent.item.StableIdentity), name: name}
}

// attrHitLocked answers an item or handle GetAttr from a valid, unconflicted
// record. Coordinator then d.mu are held.
func (d *v3DataPlane) attrHitLocked(conflict v3CacheConflict, item *v3ItemRecord, handle *v3HandleRecord) (pfslocal.Attr, bool) {
	if !d.cacheAdmissibleLocked() || d.itemsByID[item.item.ItemID] != item || !item.valid ||
		handle != nil && d.handles[handle.id] != handle || conflict(v3AttributeCoordinate(item)) {
		return pfslocal.Attr{}, false
	}
	attr, err := d.localAttr(item, item.attr, d.parentOfLocked(item))
	return attr, err == nil
}

// lookupHitLocked answers a Lookup from the name cache. A positive hit needs a
// valid parent, its remembered binding, and valid target attrs, and it retains
// one provisional reference on the target when collector is non-nil; a
// negative hit needs a valid parent and a recorded absence. Coordinator then
// d.mu are held.
func (d *v3DataPlane) lookupHitLocked(conflict v3CacheConflict, parent *v3ItemRecord, name string, collector *v3ReplyResourceCollector) (any, int32, bool) {
	if !d.cacheAdmissibleLocked() || d.itemsByID[parent.item.ItemID] != parent || !parent.valid ||
		conflict(v3AttributeCoordinate(parent), v3NamespaceCoordinate(parent, name)) {
		return nil, 0, false
	}
	if child := parent.children[name]; child != nil {
		if !child.valid || d.itemsByID[child.item.ItemID] != child || conflict(v3AttributeCoordinate(child)) {
			return nil, 0, false
		}
		attr, err := d.localAttr(child, child.attr, v3ParentOf(parent))
		if err != nil || collector != nil && child.provisional == math.MaxUint32 {
			return nil, 0, false
		}
		if collector != nil {
			child.provisional++
			collector.items = append(collector.items, child)
		}
		return &pfslocal.LookupReply{Attr: attr}, 0, true
	}
	if _, absent := parent.negatives[name]; absent {
		return nil, darwinENOENT, true
	}
	return nil, 0, false
}

// v3CachedReply is a reply computed from the cache but not yet exposed. Its
// revalidation runs under the frontend's frame write lock immediately before
// the physical write, so poison, horizon expiry, an intervening mutation, or a
// new source hold between the hit and the write cannot let a stale unexposed
// success escape.
type v3CachedReply struct {
	revalidate func() bool
}

// serveCachedAttr is the GetAttr half of hit admission for currentAttr.
func (d *v3DataPlane) serveCachedAttr(ctx context.Context, operationID uint64, item *v3ItemRecord, handle *v3HandleRecord) (pfslocal.Attr, bool, int32) {
	var attr pfslocal.Attr
	hit, errno := d.serveCached(ctx, operationID, func(conflict v3CacheConflict, _ *v3ReplyResourceCollector) bool {
		var ok bool
		attr, ok = d.attrHitLocked(conflict, item, handle)
		return ok
	}, func(conflict v3CacheConflict) bool {
		again, ok := d.attrHitLocked(conflict, item, handle)
		return ok && reflect.DeepEqual(again, attr)
	})
	return attr, hit, errno
}

// serveCachedLookup is the Lookup half of hit admission.
func (d *v3DataPlane) serveCachedLookup(ctx context.Context, operationID uint64, parent *v3ItemRecord, name string) (any, int32, bool) {
	var (
		reply any
		errno int32
	)
	hit, localErrno := d.serveCached(ctx, operationID, func(conflict v3CacheConflict, collector *v3ReplyResourceCollector) bool {
		var ok bool
		reply, errno, ok = d.lookupHitLocked(conflict, parent, name, collector)
		return ok
	}, func(conflict v3CacheConflict) bool {
		again, againErrno, ok := d.lookupHitLocked(conflict, parent, name, nil)
		return ok && againErrno == errno && reflect.DeepEqual(again, reply)
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
	snapshot func(v3CacheConflict, *v3ReplyResourceCollector) bool,
	recheck func(v3CacheConflict) bool,
) (bool, int32) {
	collector, _ := ctx.Value(v3ReplyResourceContextKey{}).(*v3ReplyResourceCollector)
	if collector == nil || collector.d != d || collector.taken || collector.bypassCache {
		return false, 0
	}
	// A session that cannot admit any hit right now (no proof horizon, say)
	// takes the authority path without registering a receipt.
	d.mu.Lock()
	admissible := d.cacheAdmissibleLocked()
	d.mu.Unlock()
	if !admissible {
		return false, 0
	}
	receipt, err := d.client.BeginLocalPublication(func(cause error) {
		d.revokeRetainedResponse(ctx, errors.Join(
			errors.New("portablefsd: cached reply crossed its frontend delivery bound"), cause,
		))
	})
	if err != nil {
		return false, 0
	}
	hit := false
	d.bridge.sourcePublication.cacheRead(func(conflict v3CacheConflict) {
		d.mu.Lock()
		defer d.mu.Unlock()
		hit = snapshot(conflict, collector)
	})
	if !hit {
		receipt.Consume()
		return false, 0
	}
	if err := d.retainLocalPublication(collector, operationID, receipt); err != nil {
		d.revokeRetainedResponse(ctx, err)
		return true, darwinEIO
	}
	collector.cached = &v3CachedReply{revalidate: func() bool {
		admitted := false
		d.bridge.sourcePublication.cacheRead(func(conflict v3CacheConflict) {
			d.mu.Lock()
			defer d.mu.Unlock()
			admitted = recheck(conflict)
		})
		return admitted
	}}
	return true, 0
}

func (d *v3DataPlane) retainLocalPublication(collector *v3ReplyResourceCollector, operationID uint64, receipt authorityrpc.ResponseConsumption) error {
	if operationID == 0 {
		return retainV3HandlerResponse(collector, receipt)
	}
	return d.bridge.sourcePublication.retainFrontendResponseConsumption(operationID, receipt)
}

// v3NameWitness is the causal witness that lets a namespace mutation's errno
// prove an invariant violation: the cached answer at the coordinate was valid
// under the horizon when the operation obtained its source cut, the parent and
// permission state stayed valid, and no other request of the same callback
// could have touched the coordinate in between. Only then is EEXIST against a
// proved absence, or ENOENT against a proved presence, terminal; otherwise the
// coordinate is conservatively evicted.
type v3NameWitness struct {
	parent *v3ItemRecord
	name   string
	// contradiction is the errno that would contradict the witnessed state:
	// darwinEEXIST for a proved absence, darwinENOENT for a proved presence.
	contradiction int32
	lease         *v3SourcePublicationLease
	acquisitions  uint64
	proved        bool
}

func newV3NameWitness(parent *v3ItemRecord, name []byte, contradiction int32) *v3NameWitness {
	return &v3NameWitness{parent: parent, name: string(name), contradiction: contradiction}
}

// witnessedLocked reports whether the cache still proves the predicate the
// errno would contradict. Coordinator then d.mu are held.
func (w *v3NameWitness) witnessedLocked(d *v3DataPlane) bool {
	parent := w.parent
	if d.itemsByID[parent.item.ItemID] != parent || !parent.valid || parent.attr.GetNlink() == 0 {
		return false
	}
	if w.contradiction == darwinEEXIST {
		_, absent := parent.negatives[w.name]
		return absent
	}
	return parent.children[w.name] != nil
}

// capture records the witness right after source admission.
func (w *v3NameWitness) capture(d *v3DataPlane, lease *v3SourcePublicationLease) {
	if w == nil {
		return
	}
	w.lease = lease
	d.bridge.sourcePublication.observeLease(lease, v3PublicationNamespace{
		parent: v3PublicationIdentity(w.parent.item.StableIdentity), name: w.name,
	}, func(acquisitions uint64, exclusive bool) {
		w.acquisitions = acquisitions
		if !exclusive {
			return
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		w.proved = d.cacheAdmissibleLocked() && w.witnessedLocked(d)
	})
}

// settle classifies a definite errno from the witnessed mutation. A proved
// contradiction stops serving; an unproved EEXIST/ENOENT evicts the
// coordinate; any other errno changes nothing.
func (d *v3DataPlane) settleNameErrno(w *v3NameWitness, errno int32) int32 {
	if w == nil || errno != darwinEEXIST && errno != darwinENOENT {
		return errno
	}
	contradicted := false
	if w.proved && errno == w.contradiction {
		d.bridge.sourcePublication.observeLease(w.lease, v3PublicationNamespace{
			parent: v3PublicationIdentity(w.parent.item.StableIdentity), name: w.name,
		}, func(acquisitions uint64, _ bool) {
			if acquisitions != w.acquisitions {
				return
			}
			d.mu.Lock()
			defer d.mu.Unlock()
			contradicted = w.witnessedLocked(d)
		})
	}
	if contradicted {
		// The writer-exclusion premise is broken, not the transport: keep the
		// session for the supervisor's exact absence proof.
		_ = d.stopServing(fmt.Errorf("portablefsd: authority errno %d contradicts the exclusively held cached name %q", errno, w.name))
		return darwinEIO
	}
	d.mu.Lock()
	if d.itemsByID[w.parent.item.ItemID] == w.parent {
		d.dropNameLocked(w.parent, w.name)
	}
	d.mu.Unlock()
	return errno
}
