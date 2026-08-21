//go:build linux

package fusev3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

// publicationIdentity is the exact stable filesystem identity carried by the
// authority protocol. It is intentionally distinct from kernel inode numbers.
type publicationIdentity [16]byte

func publicationIdentityFromBytes(raw []byte) (publicationIdentity, bool) {
	var identity publicationIdentity
	if len(raw) != len(identity) {
		return identity, false
	}
	copy(identity[:], raw)
	return identity, identity != (publicationIdentity{})
}

func publicationIdentityFromItem(item interface{ GetStableIdentity() []byte }) (publicationIdentity, bool) {
	if item == nil {
		return publicationIdentity{}, false
	}
	return publicationIdentityFromBytes(item.GetStableIdentity())
}

type publicationCoordinateKind uint8

const (
	publicationItemAttributes publicationCoordinateKind = iota + 1
	publicationItemData
	publicationItemEnumeration
	publicationNamespaceName
)

// publicationCoordinate is a local cache-publication coordinate. Item data and
// attributes are separate so an attributes-only mutation does not close more
// admission than its declaration. Namespace is the exact stable parent+name.
type publicationCoordinate struct {
	kind   publicationCoordinateKind
	item   publicationIdentity
	parent publicationIdentity
	name   string
}

type publicationNamespace struct {
	parent publicationIdentity
	name   string
}

type namespaceBounds struct {
	attributes bool
	data       bool
}

// sourcePublicationLease is one source callback's local publication cut. All
// fields after r are protected by r.mu. A revoked lease deliberately remains
// installed until mount teardown; reopening after an uncertain assigned result
// would permit stale state to become cacheable without an authoritative result.
type sourcePublicationLease struct {
	r                    *rawFileSystem
	coordinates          map[publicationCoordinate]struct{}
	names                map[publicationNamespace]namespaceBounds
	preBindings          map[publicationNamespace]publicationIdentity
	unresolvedAttributes int
	unresolvedData       int
	assigned             bool
	ready                bool
	revoked              bool
	released             bool
}

type sourceItemSpec struct {
	identity   publicationIdentity
	attributes bool
	data       bool
}

type sourceNamespaceSpec struct {
	parent     publicationIdentity
	name       string
	attributes bool
	data       bool
}

// sourcePublicationGate is daemon-local admission state. Protocol 6 derives
// authority coordinates from the mutation itself; this footprint is never
// serialized and exists only to close/drain this mount's local publications.
type sourcePublicationGate struct {
	items []sourceItemSpec
	names []sourceNamespaceSpec
}

func sourceItem(item *authoritypb.Item, attributes, data bool) (sourceItemSpec, error) {
	identity, ok := publicationIdentityFromItem(item)
	if !ok || !attributes || data && !attributes {
		return sourceItemSpec{}, errors.New("fusev3: visible mutation has an invalid stable item publication target")
	}
	return sourceItemSpec{identity: identity, attributes: attributes, data: data}, nil
}

func sourceNamespace(parent *authoritypb.Item, name string, attributes, data bool) (sourceNamespaceSpec, error) {
	identity, ok := publicationIdentityFromItem(parent)
	if !ok || !validSourceNamespaceName(name) || data && !attributes {
		return sourceNamespaceSpec{}, errors.New("fusev3: visible mutation has an invalid stable namespace publication target")
	}
	return sourceNamespaceSpec{parent: identity, name: name, attributes: attributes, data: data}, nil
}

func validSourceNamespaceName(name string) bool {
	raw := []byte(name)
	return len(raw) != 0 && len(raw) <= 255 && name != "." && name != ".." &&
		bytes.IndexByte(raw, 0) < 0 && bytes.IndexByte(raw, '/') < 0
}

// canonicalSourcePublicationGate canonicalizes an exact potential callback
// footprint. Duplicate coordinates are merged before local admission.
func canonicalSourcePublicationGate(items []sourceItemSpec, names []sourceNamespaceSpec) (*sourcePublicationGate, error) {
	itemSet := make(map[publicationIdentity]sourceItemSpec, len(items))
	for _, item := range items {
		if item.identity == (publicationIdentity{}) || !item.attributes || item.data && !item.attributes {
			return nil, errors.New("fusev3: invalid item in source publication footprint")
		}
		merged := itemSet[item.identity]
		merged.identity = item.identity
		merged.attributes = merged.attributes || item.attributes
		merged.data = merged.data || item.data
		itemSet[item.identity] = merged
	}
	nameSet := make(map[publicationNamespace]sourceNamespaceSpec, len(names))
	for _, name := range names {
		if name.parent == (publicationIdentity{}) || !validSourceNamespaceName(name.name) || name.data && !name.attributes {
			return nil, errors.New("fusev3: invalid namespace in source publication footprint")
		}
		key := publicationNamespace{parent: name.parent, name: name.name}
		merged := nameSet[key]
		merged.parent, merged.name = name.parent, name.name
		merged.attributes = merged.attributes || name.attributes
		merged.data = merged.data || name.data
		nameSet[key] = merged
	}
	if len(itemSet)+len(nameSet) == 0 {
		return nil, errors.New("fusev3: visible mutation has an empty source publication footprint")
	}
	orderedItems := make([]sourceItemSpec, 0, len(itemSet))
	for _, item := range itemSet {
		orderedItems = append(orderedItems, item)
	}
	sort.Slice(orderedItems, func(i, j int) bool {
		return bytes.Compare(orderedItems[i].identity[:], orderedItems[j].identity[:]) < 0
	})
	orderedNames := make([]sourceNamespaceSpec, 0, len(nameSet))
	for _, name := range nameSet {
		orderedNames = append(orderedNames, name)
	}
	sort.Slice(orderedNames, func(i, j int) bool {
		if compared := bytes.Compare(orderedNames[i].parent[:], orderedNames[j].parent[:]); compared != 0 {
			return compared < 0
		}
		return bytes.Compare([]byte(orderedNames[i].name), []byte(orderedNames[j].name)) < 0
	})
	return &sourcePublicationGate{items: orderedItems, names: orderedNames}, nil
}

func exactSourceGate(items []sourceItemSpec, names []sourceNamespaceSpec) (*sourcePublicationGate, error) {
	return canonicalSourcePublicationGate(items, names)
}

func itemSourceGate(item *authoritypb.Item, data bool) (*sourcePublicationGate, error) {
	target, err := sourceItem(item, true, data)
	if err != nil {
		return nil, err
	}
	return exactSourceGate([]sourceItemSpec{target}, nil)
}

func namespaceSourceGate(parent *authoritypb.Item, name string, boundData bool, additionalItems ...*authoritypb.Item) (*sourcePublicationGate, error) {
	namespace, err := sourceNamespace(parent, name, true, boundData)
	if err != nil {
		return nil, err
	}
	parentItem, err := sourceItem(parent, true, false)
	if err != nil {
		return nil, err
	}
	items := []sourceItemSpec{parentItem}
	for _, additional := range additionalItems {
		item, err := sourceItem(additional, true, false)
		if err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return exactSourceGate(items, []sourceNamespaceSpec{namespace})
}

func renameSourceGate(oldParent *authoritypb.Item, oldName string, newParent *authoritypb.Item, newName string) (*sourcePublicationGate, error) {
	oldNamespace, err := sourceNamespace(oldParent, oldName, true, false)
	if err != nil {
		return nil, err
	}
	newNamespace, err := sourceNamespace(newParent, newName, true, false)
	if err != nil {
		return nil, err
	}
	oldItem, err := sourceItem(oldParent, true, false)
	if err != nil {
		return nil, err
	}
	newItem, err := sourceItem(newParent, true, false)
	if err != nil {
		return nil, err
	}
	return exactSourceGate([]sourceItemSpec{oldItem, newItem}, []sourceNamespaceSpec{oldNamespace, newNamespace})
}

func coordinatesForSourceGate(gate *sourcePublicationGate) (map[publicationCoordinate]struct{}, map[publicationNamespace]namespaceBounds, error) {
	if gate == nil || len(gate.items)+len(gate.names) == 0 {
		return nil, nil, errors.New("fusev3: source publication gate is missing")
	}
	coordinates := make(map[publicationCoordinate]struct{}, (len(gate.items)+len(gate.names))*2)
	names := make(map[publicationNamespace]namespaceBounds)
	for _, item := range gate.items {
		if item.identity == (publicationIdentity{}) || !item.attributes || item.data && !item.attributes {
			return nil, nil, errors.New("fusev3: malformed item source publication target")
		}
		coordinates[publicationCoordinate{kind: publicationItemAttributes, item: item.identity}] = struct{}{}
		if item.data {
			coordinates[publicationCoordinate{kind: publicationItemData, item: item.identity}] = struct{}{}
		}
	}
	for _, namespace := range gate.names {
		if namespace.parent == (publicationIdentity{}) || !validSourceNamespaceName(namespace.name) || namespace.data && !namespace.attributes {
			return nil, nil, errors.New("fusev3: malformed namespace source publication target")
		}
		name := publicationNamespace{parent: namespace.parent, name: namespace.name}
		coordinates[publicationCoordinate{kind: publicationNamespaceName, parent: namespace.parent, name: namespace.name}] = struct{}{}
		names[name] = namespaceBounds{attributes: namespace.attributes, data: namespace.data}
	}
	return coordinates, names, nil
}

func (r *rawFileSystem) signalSourceChangedLocked() {
	close(r.sourceChanged)
	r.sourceChanged = make(chan struct{})
}

func (r *rawFileSystem) sourceLeaseOverlapLocked(coordinates map[publicationCoordinate]struct{}, owner *sourcePublicationLease) bool {
	for coordinate := range coordinates {
		if held := r.sourceHolds[coordinate]; held != nil && held != owner {
			return true
		}
	}
	return false
}

func (r *rawFileSystem) leaseRecallHeldLocked(coordinates map[publicationCoordinate]struct{}) bool {
	for coordinate := range coordinates {
		if r.repairingCoordinates[coordinate] {
			return true
		}
	}
	return false
}

func (r *rawFileSystem) leaseRecallOverlapsUnresolvedLocked(attributes, data int) bool {
	if attributes == 0 && data == 0 {
		return false
	}
	for coordinate, held := range r.repairingCoordinates {
		if !held {
			continue
		}
		if attributes != 0 && coordinate.kind == publicationItemAttributes ||
			data != 0 && coordinate.kind == publicationItemData {
			return true
		}
	}
	return false
}

func (r *rawFileSystem) unresolvedSourceOverlapLocked(coordinates map[publicationCoordinate]struct{}, owner *sourcePublicationLease) bool {
	for coordinate := range coordinates {
		switch coordinate.kind {
		case publicationItemAttributes:
			for lease := range r.sourceUnresolvedAttributes {
				if lease != owner {
					return true
				}
			}
		case publicationItemData:
			for lease := range r.sourceUnresolvedData {
				if lease != owner {
					return true
				}
			}
		}
	}
	return false
}

// unresolvedGateOverlapsSourceHoldsLocked handles the converse direction: a
// new namespace wildcard may bind any item identity of its declared scope, so
// it cannot be installed across an already-owned item source lease. Distinct
// namespace wildcards remain independent until either resolves to an exact
// common identity; attachBinding then serializes that exact collision.
func (r *rawFileSystem) unresolvedGateOverlapsSourceHoldsLocked(attributes, data int, owner *sourcePublicationLease) bool {
	if attributes == 0 && data == 0 {
		return false
	}
	for coordinate, lease := range r.sourceHolds {
		if lease == owner {
			continue
		}
		if attributes != 0 && coordinate.kind == publicationItemAttributes ||
			data != 0 && coordinate.kind == publicationItemData {
			return true
		}
	}
	return false
}

func addBoundCoordinates(coordinates map[publicationCoordinate]struct{}, identity publicationIdentity, bounds namespaceBounds) {
	if identity == (publicationIdentity{}) {
		return
	}
	if bounds.attributes {
		coordinates[publicationCoordinate{kind: publicationItemAttributes, item: identity}] = struct{}{}
	}
	if bounds.data {
		coordinates[publicationCoordinate{kind: publicationItemData, item: identity}] = struct{}{}
	}
}

// supersedableNegativePublicationLocked encodes the kernel's atomic-open merge
// guarantee. Once this mount's absence reply has physically reached the kernel,
// a source mutation for the same name may complete the outer scope which owns
// its deferred receipt. Foreign or not-yet-written replies stay ordered behind
// the gate so a racing repair cannot expire an entry before it is installed.
func (r *rawFileSystem) supersedableNegativePublicationLocked(publication *negativeNamePublication, owner *sourcePublicationLease) bool {
	if publication == nil || owner == nil || publication.owner != owner.r || publication.reply == nil {
		return false
	}
	reply := publication.reply
	if reply.owner != owner.r || !reply.originalWrote || !reply.originalStatus.Ok() || reply.source != nil ||
		len(reply.attrs) != 0 || len(reply.data) != 0 || len(reply.names) == 0 {
		return false
	}
	for _, name := range reply.names {
		if !name.negative {
			return false
		}
	}
	return true
}

func (r *rawFileSystem) sourceCoordinateBusyLocked(coordinate publicationCoordinate, owner *sourcePublicationLease) bool {
	publishing := r.sourcePublishing[coordinate]
	if publishing == 0 {
		return false
	}
	if coordinate.kind == publicationNamespaceName {
		for negative := range r.publishingNegativeNames[coordinate] {
			if r.supersedableNegativePublicationLocked(negative, owner) {
				publishing--
			}
		}
	}
	return publishing != 0
}

func (r *rawFileSystem) sourcePublicationsBusyLocked(coordinates map[publicationCoordinate]struct{}, unresolvedAttributes, unresolvedData int, owner *sourcePublicationLease) bool {
	for coordinate := range coordinates {
		if r.sourceCoordinateBusyLocked(coordinate, owner) {
			return true
		}
	}
	// Before the authority result supplies the child's stable identity, an
	// admitted item publication cannot be proven disjoint from the exact bound
	// namespace. Drain the declared scope globally only for this unresolved
	// interval; attachBinding immediately narrows it back to exact identity.
	if unresolvedAttributes != 0 || unresolvedData != 0 {
		for coordinate, publishing := range r.sourcePublishing {
			if publishing == 0 {
				continue
			}
			if unresolvedAttributes != 0 && coordinate.kind == publicationItemAttributes ||
				unresolvedData != 0 && coordinate.kind == publicationItemData {
				return true
			}
		}
	}
	return false
}

// acquireSourcePublication closes every exact coordinate atomically, then
// drains publication decisions made before the cut. It happens before replay
// assignment, so an acquisition failure cannot have reached the authority.
func (r *rawFileSystem) acquireSourcePublication(ctx context.Context, gate *sourcePublicationGate) (*sourcePublicationLease, error) {
	base, names, err := coordinatesForSourceGate(gate)
	if err != nil {
		return nil, err
	}
	lease := &sourcePublicationLease{r: r, names: names, preBindings: make(map[publicationNamespace]publicationIdentity)}
	for _, bounds := range names {
		if bounds.attributes {
			lease.unresolvedAttributes++
		}
		if bounds.data {
			lease.unresolvedData++
		}
	}
	for {
		coordinates := make(map[publicationCoordinate]struct{}, len(base)+len(names)*2)
		for coordinate := range base {
			coordinates[coordinate] = struct{}{}
		}
		r.mu.Lock()
		clear(lease.preBindings)
		for name, bounds := range names {
			if record := r.cachedStableNames[name]; record != nil {
				lease.preBindings[name] = record.identity
				addBoundCoordinates(coordinates, record.identity, bounds)
			}
		}
		// The strict kernel expires namespace bindings without the parent inode
		// lock, so every source gate can wait behind an older peer publication.
		// This is an internal scheduling boundary: no synthetic EINTR escapes to
		// applications for either namespace or inode mutations.
		if r.leaseRecallHeldLocked(coordinates) || r.leaseRecallOverlapsUnresolvedLocked(lease.unresolvedAttributes, lease.unresolvedData) {
			changed := r.sourceChanged
			r.mu.Unlock()
			select {
			case <-changed:
				continue
			case <-ctx.Done():
				return nil, fmt.Errorf("fusev3: wait for prior peer publication: %w", ctx.Err())
			}
		}
		if r.sourceLeaseOverlapLocked(coordinates, nil) ||
			r.unresolvedSourceOverlapLocked(coordinates, nil) ||
			r.unresolvedGateOverlapsSourceHoldsLocked(lease.unresolvedAttributes, lease.unresolvedData, nil) {
			changed := r.sourceChanged
			r.mu.Unlock()
			select {
			case <-changed:
				continue
			case <-ctx.Done():
				return nil, fmt.Errorf("fusev3: wait for overlapping source publication gate: %w", ctx.Err())
			}
		}
		lease.coordinates = coordinates
		for coordinate := range coordinates {
			r.sourceHolds[coordinate] = lease
		}
		if lease.unresolvedAttributes != 0 {
			r.sourceUnresolvedAttributes[lease] = lease.unresolvedAttributes
		}
		if lease.unresolvedData != 0 {
			r.sourceUnresolvedData[lease] = lease.unresolvedData
		}
		r.signalSourceChangedLocked()
		r.mu.Unlock()
		break
	}
	if err := lease.drain(ctx); err != nil {
		lease.release()
		return nil, err
	}
	// A cacheable LOOKUP may have been admitted before the cut and completed
	// while the namespace coordinate was draining. Refresh under the closed
	// gate so that unlink/rename also retain the exact child which became the
	// locally bound pre-state during that drain.
	if err := lease.refreshPreBindings(ctx); err != nil {
		lease.release()
		return nil, err
	}
	return lease, nil
}

func (l *sourcePublicationLease) refreshPreBindings(ctx context.Context) error {
	for {
		additional := make(map[publicationCoordinate]struct{})
		bindings := make(map[publicationNamespace]publicationIdentity)
		l.r.mu.Lock()
		if l.released || l.revoked {
			l.r.mu.Unlock()
			return errors.New("fusev3: cannot refresh bindings on an inactive source publication lease")
		}
		for namespace, bounds := range l.names {
			if _, known := l.preBindings[namespace]; known {
				continue
			}
			if record := l.r.cachedStableNames[namespace]; record != nil {
				bindings[namespace] = record.identity
				addBoundCoordinates(additional, record.identity, bounds)
			}
		}
		if l.r.sourceLeaseOverlapLocked(additional, l) {
			changed := l.r.sourceChanged
			l.r.mu.Unlock()
			select {
			case <-changed:
				continue
			case <-ctx.Done():
				return fmt.Errorf("fusev3: wait to refresh source pre-bindings: %w", ctx.Err())
			}
		}
		for namespace, identity := range bindings {
			l.preBindings[namespace] = identity
		}
		for coordinate := range additional {
			if _, exists := l.coordinates[coordinate]; !exists {
				l.coordinates[coordinate] = struct{}{}
				l.r.sourceHolds[coordinate] = l
			}
		}
		l.r.signalSourceChangedLocked()
		l.r.mu.Unlock()
		return l.drain(ctx)
	}
}

func (l *sourcePublicationLease) drain(ctx context.Context) error {
	for {
		l.r.mu.Lock()
		busy := l.r.sourcePublicationsBusyLocked(l.coordinates, l.unresolvedAttributes, l.unresolvedData, l)
		changed := l.r.sourceChanged
		l.r.mu.Unlock()
		if !busy {
			return nil
		}
		select {
		case <-changed:
		case <-ctx.Done():
			return fmt.Errorf("fusev3: source publication gate could not drain admitted publication: %w", ctx.Err())
		}
	}
}

func (l *sourcePublicationLease) markAssigned() error {
	if l == nil {
		return nil
	}
	l.r.mu.Lock()
	defer l.r.mu.Unlock()
	if l.released || l.revoked || l.assigned {
		return errors.New("fusev3: source publication lease has an invalid replay-assignment transition")
	}
	l.assigned = true
	return nil
}

func (l *sourcePublicationLease) isAssigned() bool {
	if l == nil {
		return false
	}
	l.r.mu.Lock()
	defer l.r.mu.Unlock()
	return l.assigned
}

// markDefiniteNoChange records a response which proves the mutation did not
// apply. It may be pre-assignment (the transport never crossed its assignment
// callback) or an assigned authoritative errno. The gate still remains held
// until the kernel receives that error reply.
func (l *sourcePublicationLease) markDefiniteNoChange() error {
	if l == nil {
		return nil
	}
	l.r.mu.Lock()
	defer l.r.mu.Unlock()
	if l.released || l.revoked || l.ready {
		return errors.New("fusev3: source publication lease has an invalid definite-no-change transition")
	}
	if l.unresolvedAttributes != 0 || l.unresolvedData != 0 {
		return errors.New("fusev3: definite no-change source result retained unresolved namespace bindings")
	}
	l.ready = true
	return nil
}

// markCallbackPublicationReady is the final local semantic-commit edge. It is
// called only after a successful authority result has been validated and all
// handle/inode/cache bookkeeping needed to construct the kernel reply has
// succeeded. A successful authority response followed by any local failure
// must never reach this edge: filesystem phases are peer-only, so the source
// publication lease and its physically written callback reply are the sole
// local commit boundary. Reopening early would leave old local state
// serviceable with no later source repair phase.
func (l *sourcePublicationLease) markCallbackPublicationReady() error {
	if l == nil {
		return nil
	}
	l.r.mu.Lock()
	defer l.r.mu.Unlock()
	if l.released || l.revoked || l.ready || !l.assigned {
		return errors.New("fusev3: source publication lease has an invalid callback-publication transition")
	}
	if l.unresolvedAttributes != 0 || l.unresolvedData != 0 {
		return errors.New("fusev3: source callback publication retained unresolved namespace bindings")
	}
	l.ready = true
	return nil
}

func (l *sourcePublicationLease) terminalAtCallbackReturn() bool {
	if l == nil {
		return false
	}
	l.r.mu.Lock()
	defer l.r.mu.Unlock()
	return !l.revoked && !l.released && !l.ready
}

// attachBinding extends a namespace wildcard to a definitive returned/post
// item before the owner makes that binding or its attributes cacheable.
func (l *sourcePublicationLease) attachBinding(ctx context.Context, namespace publicationNamespace, identity publicationIdentity) error {
	if l == nil || identity == (publicationIdentity{}) {
		return nil
	}
	l.r.mu.Lock()
	bounds, ownsName := l.names[namespace]
	l.r.mu.Unlock()
	if !ownsName || !bounds.attributes && !bounds.data {
		return nil
	}
	additional := make(map[publicationCoordinate]struct{}, 2)
	addBoundCoordinates(additional, identity, bounds)
	for {
		l.r.mu.Lock()
		if l.released || l.revoked {
			l.r.mu.Unlock()
			return errors.New("fusev3: cannot attach a binding to an inactive source publication lease")
		}
		// A peer PREPARE may already be installed here: the unresolved
		// namespace wildcard made it wait for this owner. Attaching the
		// definitive item narrows that wildcard without yielding ownership;
		// rejecting the waiting peer would terminalize the valid source-first
		// ordering. Other source owners still conflict below.
		if l.r.sourceLeaseOverlapLocked(additional, l) {
			changed := l.r.sourceChanged
			l.r.mu.Unlock()
			select {
			case <-changed:
				continue
			case <-ctx.Done():
				return fmt.Errorf("fusev3: wait to attach definitive source binding: %w", ctx.Err())
			}
		}
		for coordinate := range additional {
			if _, exists := l.coordinates[coordinate]; !exists {
				l.coordinates[coordinate] = struct{}{}
				l.r.sourceHolds[coordinate] = l
			}
		}
		l.resolveNamespaceLocked(namespace, bounds)
		l.r.signalSourceChangedLocked()
		l.r.mu.Unlock()
		return l.drain(ctx)
	}
}

func (l *sourcePublicationLease) resolveNamespaceLocked(namespace publicationNamespace, bounds namespaceBounds) {
	if _, unresolved := l.names[namespace]; !unresolved {
		return
	}
	delete(l.names, namespace)
	if bounds.attributes && l.unresolvedAttributes > 0 {
		l.unresolvedAttributes--
		if l.unresolvedAttributes == 0 {
			delete(l.r.sourceUnresolvedAttributes, l)
		} else {
			l.r.sourceUnresolvedAttributes[l] = l.unresolvedAttributes
		}
	}
	if bounds.data && l.unresolvedData > 0 {
		l.unresolvedData--
		if l.unresolvedData == 0 {
			delete(l.r.sourceUnresolvedData, l)
		} else {
			l.r.sourceUnresolvedData[l] = l.unresolvedData
		}
	}
}

func (l *sourcePublicationLease) resolveNoBinding(namespace publicationNamespace) {
	if l == nil {
		return
	}
	l.r.mu.Lock()
	bounds, exists := l.names[namespace]
	if exists {
		l.resolveNamespaceLocked(namespace, bounds)
		l.r.signalSourceChangedLocked()
	}
	l.r.mu.Unlock()
}

func (l *sourcePublicationLease) resolveAllNoBinding() {
	if l == nil {
		return
	}
	l.r.mu.Lock()
	for namespace, bounds := range l.names {
		l.resolveNamespaceLocked(namespace, bounds)
	}
	l.r.signalSourceChangedLocked()
	l.r.mu.Unlock()
}

func (l *sourcePublicationLease) hasUnresolvedBinding() bool {
	if l == nil {
		return false
	}
	l.r.mu.Lock()
	defer l.r.mu.Unlock()
	return l.unresolvedAttributes != 0 || l.unresolvedData != 0
}

func (l *sourcePublicationLease) preBinding(namespace publicationNamespace) (publicationIdentity, bool) {
	if l == nil {
		return publicationIdentity{}, false
	}
	l.r.mu.Lock()
	defer l.r.mu.Unlock()
	identity, ok := l.preBindings[namespace]
	return identity, ok
}

func (l *sourcePublicationLease) attachRename(ctx context.Context, oldName, newName publicationNamespace, newPost publicationIdentity, oldPost *publicationIdentity) error {
	if l == nil {
		return nil
	}
	// These are authoritative post-state identities returned under mutation
	// order. Pre-bindings exist only to drain publications at the initial cut;
	// they cannot prove what a completed rename left at either name.
	if newPost == (publicationIdentity{}) {
		return errors.New("fusev3: successful rename returned a zero destination identity")
	}
	if err := l.attachBinding(ctx, newName, newPost); err != nil {
		return err
	}
	if oldPost != nil {
		if *oldPost == (publicationIdentity{}) {
			return errors.New("fusev3: successful rename returned a zero retained-source identity")
		}
		return l.attachBinding(ctx, oldName, *oldPost)
	}
	l.resolveNoBinding(oldName)
	return nil
}

func (l *sourcePublicationLease) revoke() {
	if l == nil {
		return
	}
	l.r.mu.Lock()
	l.revoked = true
	// Revocation is a terminal fail-closed transition, not a release. In
	// particular, an unresolved namespace wildcard remains closed until the
	// authority fences this dead session; reopening it would admit a local
	// cache publication through the same uncertain mutation result.
	l.r.signalSourceChangedLocked()
	l.r.mu.Unlock()
}

func (l *sourcePublicationLease) release() {
	if l == nil {
		return
	}
	l.r.mu.Lock()
	defer l.r.mu.Unlock()
	if l.released || l.revoked || !l.ready {
		return
	}
	l.released = true
	delete(l.r.sourceUnresolvedAttributes, l)
	delete(l.r.sourceUnresolvedData, l)
	for coordinate := range l.coordinates {
		if l.r.sourceHolds[coordinate] == l {
			delete(l.r.sourceHolds, coordinate)
		}
	}
	l.r.signalSourceChangedLocked()
}

func (r *rawFileSystem) sourcePublicationAllowedLocked(coordinate publicationCoordinate, owner *sourcePublicationLease) bool {
	held := r.sourceHolds[coordinate]
	if held != nil && held != owner {
		return false
	}
	// An unresolved exact namespace wildcard owns the potential bound item.
	// Ordinary cached replies have no owner and therefore publish with zero TTL
	// until the definitive identity narrows the wildcard. The owning callback is
	// allowed so it can attach and publish its returned binding.
	switch coordinate.kind {
	case publicationItemAttributes:
		for lease := range r.sourceUnresolvedAttributes {
			if lease != owner {
				return false
			}
		}
	case publicationItemData:
		for lease := range r.sourceUnresolvedData {
			if lease != owner {
				return false
			}
		}
	}
	return true
}

func (r *rawFileSystem) admitSourcePublicationLocked(coordinate publicationCoordinate) {
	r.sourcePublishing[coordinate]++
}

func (r *rawFileSystem) settleSourcePublicationLocked(coordinate publicationCoordinate) {
	if r.sourcePublishing[coordinate]--; r.sourcePublishing[coordinate] <= 0 {
		delete(r.sourcePublishing, coordinate)
	}
	r.signalSourceChangedLocked()
}
