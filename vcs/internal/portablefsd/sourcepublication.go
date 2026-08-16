package portablefsd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
	"github.com/steerlabs/portablefs/vcs/internal/visibilitywire"
)

const maxV3SourcePublicationTargets = 16

var errV3SourcePublicationInterrupted = errors.New("portablefsd: source publication interrupted by an already-owned peer repair cut")
var errV3SourcePublicationNotPublished = errors.New("portablefsd: authority-committed visible mutation did not cross the FSKit publication boundary")

type v3PublicationIdentity [16]byte

func v3PublicationIdentityFromItem(item pfslocal.Item) (v3PublicationIdentity, error) {
	identity := v3PublicationIdentity(item.StableIdentity)
	if item.ItemID == 0 || identity == (v3PublicationIdentity{}) {
		return identity, errors.New("portablefsd: item omitted its stable publication identity")
	}
	return identity, nil
}

type v3PublicationCoordinateKind uint8

const (
	v3PublicationItemAttributes v3PublicationCoordinateKind = iota + 1
	v3PublicationItemData
	v3PublicationNamespaceName
)

type v3PublicationCoordinate struct {
	kind   v3PublicationCoordinateKind
	item   v3PublicationIdentity
	parent v3PublicationIdentity
	name   string
}

type v3PublicationNamespace struct {
	parent v3PublicationIdentity
	name   string
}

type v3PublicationBounds struct {
	attributes bool
	data       bool
}

// v3PublicationClaims counts unresolved post-binding claims per mutation
// call. A callback can issue concurrent calls for the same namespace, so one
// call's definitive result must consume one claim without resolving its peers.
type v3PublicationClaims struct {
	attributes int
	data       int
}

type v3SourceItemSpec struct {
	identity   v3PublicationIdentity
	attributes bool
	data       bool
}

type v3SourceNamespaceSpec struct {
	parent     v3PublicationIdentity
	name       string
	attributes bool
	data       bool
}

func v3SourceItem(item pfslocal.Item, data bool) (v3SourceItemSpec, error) {
	identity, err := v3PublicationIdentityFromItem(item)
	if err != nil {
		return v3SourceItemSpec{}, err
	}
	return v3SourceItemSpec{identity: identity, attributes: true, data: data}, nil
}

func v3SourceNamespace(parent pfslocal.Item, name []byte, boundData bool) (v3SourceNamespaceSpec, error) {
	identity, err := v3PublicationIdentityFromItem(parent)
	if err != nil || !visibilitywire.ValidName(name) {
		return v3SourceNamespaceSpec{}, errors.New("portablefsd: namespace omitted its stable publication coordinate")
	}
	return v3SourceNamespaceSpec{
		parent: identity, name: string(name), attributes: true, data: boundData,
	}, nil
}

func v3CanonicalSourceGate(items []v3SourceItemSpec, names []v3SourceNamespaceSpec) (*authoritypb.SourcePublicationGate, error) {
	itemSet := make(map[v3PublicationIdentity]v3SourceItemSpec, len(items))
	for _, item := range items {
		if item.identity == (v3PublicationIdentity{}) || !item.attributes || item.data && !item.attributes {
			return nil, errors.New("portablefsd: malformed item source-publication target")
		}
		merged := itemSet[item.identity]
		merged.identity = item.identity
		merged.attributes = merged.attributes || item.attributes
		merged.data = merged.data || item.data
		itemSet[item.identity] = merged
	}
	nameSet := make(map[v3PublicationNamespace]v3SourceNamespaceSpec, len(names))
	for _, name := range names {
		if name.parent == (v3PublicationIdentity{}) || !visibilitywire.ValidName([]byte(name.name)) || name.data && !name.attributes {
			return nil, errors.New("portablefsd: malformed namespace source-publication target")
		}
		key := v3PublicationNamespace{parent: name.parent, name: name.name}
		merged := nameSet[key]
		merged.parent, merged.name = name.parent, name.name
		merged.attributes = merged.attributes || name.attributes
		merged.data = merged.data || name.data
		nameSet[key] = merged
	}
	if len(itemSet)+len(nameSet) == 0 || len(itemSet)+len(nameSet) > maxV3SourcePublicationTargets {
		return nil, errors.New("portablefsd: visible mutation has an invalid source-publication target count")
	}
	orderedItems := make([]v3SourceItemSpec, 0, len(itemSet))
	for _, item := range itemSet {
		orderedItems = append(orderedItems, item)
	}
	sort.Slice(orderedItems, func(i, j int) bool {
		return bytes.Compare(orderedItems[i].identity[:], orderedItems[j].identity[:]) < 0
	})
	orderedNames := make([]v3SourceNamespaceSpec, 0, len(nameSet))
	for _, name := range nameSet {
		orderedNames = append(orderedNames, name)
	}
	sort.Slice(orderedNames, func(i, j int) bool {
		if compared := bytes.Compare(orderedNames[i].parent[:], orderedNames[j].parent[:]); compared != 0 {
			return compared < 0
		}
		return bytes.Compare([]byte(orderedNames[i].name), []byte(orderedNames[j].name)) < 0
	})
	gate := &authoritypb.SourcePublicationGate{
		Targets: make([]*authoritypb.SourcePublicationTarget, 0, len(orderedItems)+len(orderedNames)),
	}
	for _, item := range orderedItems {
		gate.Targets = append(gate.Targets, &authoritypb.SourcePublicationTarget{
			Coordinate: &authoritypb.SourcePublicationTarget_Item{Item: &authoritypb.SourcePublicationItem{
				Identity: append([]byte(nil), item.identity[:]...), Attributes: item.attributes, Data: item.data,
			}},
		})
	}
	for _, name := range orderedNames {
		gate.Targets = append(gate.Targets, &authoritypb.SourcePublicationTarget{
			Coordinate: &authoritypb.SourcePublicationTarget_Namespace{Namespace: &authoritypb.SourcePublicationNamespace{
				ParentIdentity: append([]byte(nil), name.parent[:]...), Name: []byte(name.name),
				BoundAttributes: name.attributes, BoundData: name.data,
			}},
		})
	}
	return gate, nil
}

func v3ItemSourceGate(item pfslocal.Item, data bool) (*authoritypb.SourcePublicationGate, error) {
	target, err := v3SourceItem(item, data)
	if err != nil {
		return nil, err
	}
	return v3CanonicalSourceGate([]v3SourceItemSpec{target}, nil)
}

func v3NamespaceSourceGate(parent pfslocal.Item, name []byte, boundData bool, additional ...pfslocal.Item) (*authoritypb.SourcePublicationGate, error) {
	namespace, err := v3SourceNamespace(parent, name, boundData)
	if err != nil {
		return nil, err
	}
	parentItem, err := v3SourceItem(parent, false)
	if err != nil {
		return nil, err
	}
	items := []v3SourceItemSpec{parentItem}
	for _, candidate := range additional {
		item, itemErr := v3SourceItem(candidate, false)
		if itemErr != nil {
			return nil, itemErr
		}
		items = append(items, item)
	}
	return v3CanonicalSourceGate(items, []v3SourceNamespaceSpec{namespace})
}

func v3RenameSourceGate(oldParent pfslocal.Item, oldName []byte, newParent pfslocal.Item, newName []byte) (*authoritypb.SourcePublicationGate, error) {
	oldNamespace, err := v3SourceNamespace(oldParent, oldName, false)
	if err != nil {
		return nil, err
	}
	newNamespace, err := v3SourceNamespace(newParent, newName, false)
	if err != nil {
		return nil, err
	}
	oldItem, err := v3SourceItem(oldParent, false)
	if err != nil {
		return nil, err
	}
	newItem, err := v3SourceItem(newParent, false)
	if err != nil {
		return nil, err
	}
	return v3CanonicalSourceGate(
		[]v3SourceItemSpec{oldItem, newItem},
		[]v3SourceNamespaceSpec{oldNamespace, newNamespace},
	)
}

type v3SourcePublicationOperation struct {
	reserved             bool
	acknowledged         bool
	committed            bool
	lease                *v3SourcePublicationLease
	responseConsumptions []authorityrpc.ResponseConsumption
}

type v3SourcePublicationLease struct {
	gate                 *v3SourcePublicationCoordinator
	operationID          uint64
	coordinates          map[v3PublicationCoordinate]struct{}
	names                map[v3PublicationNamespace]v3PublicationClaims
	unresolvedAttributes int
	unresolvedData       int
	assigned             uint32
	released             bool
}

// v3SourcePublicationCoordinator is the one local ordering point between
// callback-owned source publication and authority-owned peer repair. It uses
// stable identities only. The older mount-wide path handoff gate remains a
// separate delegation mechanism and is never consulted for this correctness
// cut.
type v3SourcePublicationCoordinator struct {
	mu                   sync.Mutex
	changed              chan struct{}
	terminal             error
	operations           map[uint64]*v3SourcePublicationOperation
	sourceHolds          map[v3PublicationCoordinate]*v3SourcePublicationLease
	unresolvedAttributes map[*v3SourcePublicationLease]int
	unresolvedData       map[*v3SourcePublicationLease]int
	peerSequence         uint64
	peerHolds            map[v3PublicationCoordinate]struct{}
	// peerContended records an ordered request definitely refused behind this
	// exact peer cut before Swift could observe PREPARE. COMPLETE consumes it
	// into the existing Ack contention bit, preserving dormant FIFO credit
	// without another wire field.
	peerContended bool
}

func newV3SourcePublicationCoordinator() *v3SourcePublicationCoordinator {
	return &v3SourcePublicationCoordinator{
		changed:              make(chan struct{}),
		operations:           make(map[uint64]*v3SourcePublicationOperation),
		sourceHolds:          make(map[v3PublicationCoordinate]*v3SourcePublicationLease),
		unresolvedAttributes: make(map[*v3SourcePublicationLease]int),
		unresolvedData:       make(map[*v3SourcePublicationLease]int),
		peerHolds:            make(map[v3PublicationCoordinate]struct{}),
	}
}

func (c *v3SourcePublicationCoordinator) signalLocked() {
	close(c.changed)
	c.changed = make(chan struct{})
}

func v3PublicationCoordinatesOverlap(left, right v3PublicationCoordinate) bool {
	return left == right
}

func (c *v3SourcePublicationCoordinator) reserve(operationID uint64) {
	if operationID == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.terminal != nil {
		return
	}
	op := c.operations[operationID]
	if op == nil {
		op = &v3SourcePublicationOperation{}
		c.operations[operationID] = op
	}
	op.reserved = true
}

func (c *v3SourcePublicationCoordinator) retire(operationID uint64) {
	if operationID == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	op := c.operations[operationID]
	if op == nil {
		return
	}
	op.reserved = false
	if op.acknowledged && op.lease != nil {
		c.releaseSourceLocked(op.lease)
	}
	if op.acknowledged && len(op.responseConsumptions) == 0 {
		delete(c.operations, operationID)
	}
}

func (c *v3SourcePublicationCoordinator) acknowledge(
	operationID uint64,
	semanticCommit pfslocal.PublicationSemanticCommit,
) (bool, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	op := c.operations[operationID]
	if op == nil || op.acknowledged {
		return false, nil
	}
	if semanticCommit != pfslocal.PublicationSemanticCommitPublished &&
		semanticCommit != pfslocal.PublicationSemanticCommitNotPublished {
		return false, errors.New("portablefsd: PublicationAck omitted its semantic-commit verdict")
	}
	op.acknowledged = true
	if semanticCommit == pfslocal.PublicationSemanticCommitNotPublished && op.committed {
		if c.terminal == nil {
			c.terminal = errV3SourcePublicationNotPublished
			c.signalLocked()
		}
		return true, errV3SourcePublicationNotPublished
	}
	if !op.reserved && op.lease != nil {
		c.releaseSourceLocked(op.lease)
	}
	if !op.reserved && len(op.responseConsumptions) == 0 {
		delete(c.operations, operationID)
	}
	return true, nil
}

func (c *v3SourcePublicationCoordinator) operationLease(operationID uint64) *v3SourcePublicationLease {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.operationLeaseLocked(operationID)
}

func (c *v3SourcePublicationCoordinator) operationLeaseLocked(operationID uint64) *v3SourcePublicationLease {
	if op := c.operations[operationID]; op != nil {
		return op.lease
	}
	return nil
}

func coordinatesForV3SourceGate(gate *authoritypb.SourcePublicationGate) (map[v3PublicationCoordinate]struct{}, map[v3PublicationNamespace]v3PublicationBounds, error) {
	if gate == nil || len(gate.GetTargets()) == 0 || len(gate.GetTargets()) > maxV3SourcePublicationTargets {
		return nil, nil, errors.New("portablefsd: source publication gate is missing or oversized")
	}
	coordinates := make(map[v3PublicationCoordinate]struct{}, len(gate.GetTargets())*2)
	names := make(map[v3PublicationNamespace]v3PublicationBounds)
	var previous []byte
	for _, target := range gate.GetTargets() {
		var canonical []byte
		switch {
		case target.GetItem() != nil:
			item := target.GetItem()
			var identity v3PublicationIdentity
			if len(item.GetIdentity()) != len(identity) || !item.GetAttributes() || item.GetData() && !item.GetAttributes() {
				return nil, nil, errors.New("portablefsd: malformed item source publication target")
			}
			copy(identity[:], item.GetIdentity())
			if identity == (v3PublicationIdentity{}) {
				return nil, nil, errors.New("portablefsd: zero item source publication identity")
			}
			canonical = append([]byte{0}, identity[:]...)
			coordinates[v3PublicationCoordinate{kind: v3PublicationItemAttributes, item: identity}] = struct{}{}
			if item.GetData() {
				coordinates[v3PublicationCoordinate{kind: v3PublicationItemData, item: identity}] = struct{}{}
			}
		case target.GetNamespace() != nil:
			namespace := target.GetNamespace()
			var parent v3PublicationIdentity
			if len(namespace.GetParentIdentity()) != len(parent) || !visibilitywire.ValidName(namespace.GetName()) ||
				namespace.GetBoundData() && !namespace.GetBoundAttributes() {
				return nil, nil, errors.New("portablefsd: malformed namespace source publication target")
			}
			copy(parent[:], namespace.GetParentIdentity())
			if parent == (v3PublicationIdentity{}) {
				return nil, nil, errors.New("portablefsd: zero parent source publication identity")
			}
			canonical = append([]byte{1}, parent[:]...)
			canonical = append(canonical, namespace.GetName()...)
			name := v3PublicationNamespace{parent: parent, name: string(namespace.GetName())}
			coordinates[v3PublicationCoordinate{kind: v3PublicationNamespaceName, parent: parent, name: name.name}] = struct{}{}
			names[name] = v3PublicationBounds{
				attributes: namespace.GetBoundAttributes(), data: namespace.GetBoundData(),
			}
		default:
			return nil, nil, errors.New("portablefsd: source publication target omitted its coordinate")
		}
		if previous != nil && bytes.Compare(previous, canonical) >= 0 {
			return nil, nil, errors.New("portablefsd: source publication targets are not canonical and unique")
		}
		previous = canonical
	}
	return coordinates, names, nil
}

func coordinatesForV3PeerTargets(targets []*authoritypb.VisibilityTarget) (map[v3PublicationCoordinate]struct{}, error) {
	coordinates := make(map[v3PublicationCoordinate]struct{}, len(targets)*2)
	for _, target := range targets {
		if err := visibilitywire.ValidateTarget(target); err != nil {
			return nil, err
		}
		switch target.GetScope() {
		case authoritypb.VisibilityScope_VISIBILITY_SCOPE_NAMESPACE:
			var parent v3PublicationIdentity
			copy(parent[:], target.GetParentIdentity())
			coordinates[v3PublicationCoordinate{kind: v3PublicationNamespaceName, parent: parent, name: string(target.GetName())}] = struct{}{}
		case authoritypb.VisibilityScope_VISIBILITY_SCOPE_ATTRIBUTES:
			var identity v3PublicationIdentity
			copy(identity[:], target.GetIdentity())
			coordinates[v3PublicationCoordinate{kind: v3PublicationItemAttributes, item: identity}] = struct{}{}
		case authoritypb.VisibilityScope_VISIBILITY_SCOPE_DATA:
			var identity v3PublicationIdentity
			copy(identity[:], target.GetIdentity())
			coordinates[v3PublicationCoordinate{kind: v3PublicationItemAttributes, item: identity}] = struct{}{}
			coordinates[v3PublicationCoordinate{kind: v3PublicationItemData, item: identity}] = struct{}{}
		default:
			return nil, errors.New("portablefsd: peer target has no publication scope")
		}
	}
	return coordinates, nil
}

func (c *v3SourcePublicationCoordinator) sourceConflictLocked(coordinates map[v3PublicationCoordinate]struct{}, owner *v3SourcePublicationLease) bool {
	for coordinate := range coordinates {
		for heldCoordinate, held := range c.sourceHolds {
			if held != owner && v3PublicationCoordinatesOverlap(coordinate, heldCoordinate) {
				return true
			}
		}
	}
	return false
}

func (c *v3SourcePublicationCoordinator) peerConflictLocked(coordinates map[v3PublicationCoordinate]struct{}) bool {
	if c.sourceConflictLocked(coordinates, nil) {
		return true
	}
	for coordinate := range coordinates {
		switch coordinate.kind {
		case v3PublicationItemAttributes:
			if len(c.unresolvedAttributes) != 0 {
				return true
			}
		case v3PublicationItemData:
			if len(c.unresolvedData) != 0 {
				return true
			}
		}
	}
	return false
}

func (c *v3SourcePublicationCoordinator) peerConflictsSourceLocked(coordinates map[v3PublicationCoordinate]struct{}, names map[v3PublicationNamespace]v3PublicationBounds) bool {
	for coordinate := range coordinates {
		if _, held := c.peerHolds[coordinate]; held {
			return true
		}
	}
	attributes, data := false, false
	for _, bounds := range names {
		attributes = attributes || bounds.attributes
		data = data || bounds.data
	}
	for coordinate := range c.peerHolds {
		if attributes && coordinate.kind == v3PublicationItemAttributes || data && coordinate.kind == v3PublicationItemData {
			return true
		}
	}
	return false
}

func (c *v3SourcePublicationCoordinator) unresolvedConflictsExistingLocked(names map[v3PublicationNamespace]v3PublicationBounds, owner *v3SourcePublicationLease) bool {
	attributes, data := false, false
	for _, bounds := range names {
		attributes = attributes || bounds.attributes
		data = data || bounds.data
	}
	if !attributes && !data {
		return false
	}
	for coordinate, lease := range c.sourceHolds {
		if lease == owner {
			continue
		}
		if attributes && coordinate.kind == v3PublicationItemAttributes || data && coordinate.kind == v3PublicationItemData {
			return true
		}
	}
	if attributes {
		for lease := range c.unresolvedAttributes {
			if lease != owner {
				return true
			}
		}
	}
	if data {
		for lease := range c.unresolvedData {
			if lease != owner {
				return true
			}
		}
	}
	return false
}

func (c *v3SourcePublicationCoordinator) acquireSource(ctx context.Context, operationID uint64, gate *authoritypb.SourcePublicationGate) (*v3SourcePublicationLease, error) {
	if ctx == nil || operationID == 0 {
		return nil, errors.New("portablefsd: source publication needs a live callback identity")
	}
	coordinates, names, err := coordinatesForV3SourceGate(gate)
	if err != nil {
		return nil, err
	}
	for {
		c.mu.Lock()
		if c.terminal != nil {
			err := c.terminal
			c.mu.Unlock()
			return nil, err
		}
		op := c.operations[operationID]
		if op == nil || !op.reserved {
			c.mu.Unlock()
			return nil, errors.New("portablefsd: source mutation escaped its serial-reader callback reservation")
		}
		if op.acknowledged {
			c.mu.Unlock()
			return nil, errors.New("portablefsd: source callback already crossed PublicationAck")
		}
		// Peer-first is a definite local refusal, never a wait. The framework
		// callback may be the only actuator lane that can complete that peer
		// repair; parking it behind the cut would close the cycle. No replay
		// identity has been assigned and no DATA bytes have been sent here.
		if c.peerConflictsSourceLocked(coordinates, names) {
			c.peerContended = true
			c.mu.Unlock()
			return nil, errV3SourcePublicationInterrupted
		}
		lease := op.lease
		if lease == nil {
			lease = &v3SourcePublicationLease{
				gate: c, operationID: operationID,
				coordinates: make(map[v3PublicationCoordinate]struct{}),
				names:       make(map[v3PublicationNamespace]v3PublicationClaims),
			}
		}
		if c.sourceConflictLocked(coordinates, lease) || c.unresolvedConflictsExistingLocked(names, lease) {
			changed := c.changed
			c.mu.Unlock()
			select {
			case <-changed:
				continue
			case <-ctx.Done():
				return nil, fmt.Errorf("portablefsd: source publication gate wait: %w", ctx.Err())
			}
		}
		if op.lease == nil {
			op.lease = lease
		}
		for coordinate := range coordinates {
			if _, exists := lease.coordinates[coordinate]; !exists {
				lease.coordinates[coordinate] = struct{}{}
				c.sourceHolds[coordinate] = lease
			}
		}
		for namespace, bounds := range names {
			claims := lease.names[namespace]
			if bounds.attributes {
				claims.attributes++
				lease.unresolvedAttributes++
			}
			if bounds.data {
				claims.data++
				lease.unresolvedData++
			}
			if claims != (v3PublicationClaims{}) {
				lease.names[namespace] = claims
			}
		}
		if lease.unresolvedAttributes != 0 {
			c.unresolvedAttributes[lease] = lease.unresolvedAttributes
		}
		if lease.unresolvedData != 0 {
			c.unresolvedData[lease] = lease.unresolvedData
		}
		c.signalLocked()
		c.mu.Unlock()
		return lease, nil
	}
}

func (l *v3SourcePublicationLease) markAssigned() error {
	if l == nil || l.gate == nil {
		return errors.New("portablefsd: source publication assignment has no lease")
	}
	l.gate.mu.Lock()
	defer l.gate.mu.Unlock()
	op := l.gate.operations[l.operationID]
	if l.gate.terminal != nil || l.released || op == nil || op.lease != l || op.acknowledged {
		return errors.New("portablefsd: source mutation assignment crossed an inactive publication lease")
	}
	l.assigned++
	return nil
}

// markCommitted is the monotone semantic fact behind PublicationAck. It is
// recorded as soon as the daemon has an exact, successful authority response,
// before reply construction or socket exposure can fail. A callback-level
// NOT_PUBLISHED verdict is terminal whenever this bit is set, including when a
// later request in the same logical operation is the one that fails.
func (l *v3SourcePublicationLease) markCommitted() error {
	if l == nil || l.gate == nil {
		return errors.New("portablefsd: committed source mutation has no publication lease")
	}
	l.gate.mu.Lock()
	defer l.gate.mu.Unlock()
	op := l.gate.operations[l.operationID]
	if l.gate.terminal != nil || l.released || op == nil || op.lease != l ||
		op.acknowledged || l.assigned == 0 {
		return errors.New("portablefsd: committed source mutation crossed an inactive publication lease")
	}
	op.committed = true
	return nil
}

// retainResponseConsumption transfers one parsed authority response from the
// RPC call into the callback's logical publication lifetime. The source lease
// is the only object that already proves all three identities are the same
// operation: the pfslocal callback, the authority replay assignment, and the
// source-publication gate. The receipt is deliberately not consumed when the
// source coordinates are released; that can precede retirement of the broader
// frontend publication operation. finishFrontendPublication is the sole
// successful consumption point.
func (l *v3SourcePublicationLease) retainResponseConsumption(consumption authorityrpc.ResponseConsumption) error {
	if l == nil || l.gate == nil || consumption == nil {
		return errors.New("portablefsd: retained authority response has no publication lease")
	}
	l.gate.mu.Lock()
	defer l.gate.mu.Unlock()
	op := l.gate.operations[l.operationID]
	if l.gate.terminal != nil || l.released || op == nil || op.lease != l ||
		!op.committed || l.assigned == 0 {
		return errors.New("portablefsd: retained authority response crossed an inactive publication lease")
	}
	op.responseConsumptions = append(op.responseConsumptions, consumption)
	return nil
}

// retainFrontendResponseConsumption binds a parsed authority response which
// can publish frontend state but owns no source mutation lease (for example
// LOOKUP, GETATTR, READ, READLINK, xattr reads, and READDIR). The logical
// callback reservation is the exact lifetime shared by all of those replies:
// it begins before authority dispatch and ends only after the physical
// pfslocal reply, PublicationAck, and every handler retirement.
func (c *v3SourcePublicationCoordinator) retainFrontendResponseConsumption(
	operationID uint64,
	consumption authorityrpc.ResponseConsumption,
) error {
	if operationID == 0 || consumption == nil {
		return errors.New("portablefsd: retained frontend response omitted its publication identity")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	op := c.operations[operationID]
	if c.terminal != nil || op == nil || !op.reserved {
		return errors.New("portablefsd: retained frontend response crossed an inactive publication operation")
	}
	op.responseConsumptions = append(op.responseConsumptions, consumption)
	return nil
}

// finishFrontendPublication transfers every retained authority response only
// after the pfslocal PublicationAck and the logical frontend operation have
// both retired. A terminal coordinator may finish without an acknowledgement:
// in that case the serving boundary has already been revoked, which is the
// other boundary ResponseConsumption permits. Receipts are returned rather
// than consumed under mu because terminal receipts perform a CONTROL round
// trip and must never hold the source ordering lock while doing so.
func (c *v3SourcePublicationCoordinator) finishFrontendPublication(operationID uint64) ([]authorityrpc.ResponseConsumption, error) {
	if operationID == 0 {
		return nil, errors.New("portablefsd: frontend publication finish omitted its operation identity")
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	op := c.operations[operationID]
	if op == nil {
		return nil, nil
	}
	if len(op.responseConsumptions) == 0 {
		return nil, nil
	}
	if op.reserved && c.terminal == nil {
		return nil, errors.New("portablefsd: frontend publication finished before its handlers retired")
	}
	if !op.acknowledged && c.terminal == nil {
		return nil, errors.New("portablefsd: frontend publication finished without PublicationAck")
	}
	if op.lease != nil && !op.lease.released && c.terminal == nil {
		return nil, errors.New("portablefsd: frontend publication finished before its source gate released")
	}
	consumptions := op.responseConsumptions
	op.responseConsumptions = nil
	delete(c.operations, operationID)
	return consumptions, nil
}

func addV3BoundCoordinates(coordinates map[v3PublicationCoordinate]struct{}, identity v3PublicationIdentity, bounds v3PublicationBounds) {
	if bounds.attributes {
		coordinates[v3PublicationCoordinate{kind: v3PublicationItemAttributes, item: identity}] = struct{}{}
	}
	if bounds.data {
		coordinates[v3PublicationCoordinate{kind: v3PublicationItemData, item: identity}] = struct{}{}
	}
}

func (l *v3SourcePublicationLease) attachBinding(gate *authoritypb.SourcePublicationGate, namespace v3PublicationNamespace, identity v3PublicationIdentity) error {
	if l == nil || l.gate == nil {
		return errors.New("portablefsd: definitive source binding has no publication lease")
	}
	if identity == (v3PublicationIdentity{}) {
		return errors.New("portablefsd: definitive source binding has a zero identity")
	}
	_, names, err := coordinatesForV3SourceGate(gate)
	if err != nil {
		return err
	}
	bounds, declared := names[namespace]
	if !declared {
		return errors.New("portablefsd: definitive source binding was outside its call's declared namespace")
	}
	c := l.gate
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.terminal != nil || l.released {
		return errors.New("portablefsd: definitive source binding reached an inactive publication lease")
	}
	if !l.hasNamespaceClaimLocked(namespace, bounds) {
		return errors.New("portablefsd: definitive source binding was outside its declared namespace")
	}
	additional := make(map[v3PublicationCoordinate]struct{}, 2)
	addV3BoundCoordinates(additional, identity, bounds)
	if c.sourceConflictLocked(additional, l) {
		return errors.New("portablefsd: source publication crossed an unresolved source binding")
	}
	for coordinate := range additional {
		l.coordinates[coordinate] = struct{}{}
		c.sourceHolds[coordinate] = l
	}
	l.consumeNamespaceClaimLocked(namespace, bounds)
	l.updateUnresolvedIndexesLocked()
	c.signalLocked()
	return nil
}

func (l *v3SourcePublicationLease) resolveNoBinding(gate *authoritypb.SourcePublicationGate, namespace v3PublicationNamespace) error {
	if l == nil || l.gate == nil {
		return errors.New("portablefsd: source namespace resolution has no lease")
	}
	_, names, err := coordinatesForV3SourceGate(gate)
	if err != nil {
		return err
	}
	bounds, declared := names[namespace]
	if !declared {
		return errors.New("portablefsd: source namespace resolution was outside its call's declaration")
	}
	c := l.gate
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.terminal != nil || l.released {
		return errors.New("portablefsd: source namespace resolved after its publication lease ended")
	}
	if !l.hasNamespaceClaimLocked(namespace, bounds) {
		return errors.New("portablefsd: source namespace resolution was outside its declaration")
	}
	l.consumeNamespaceClaimLocked(namespace, bounds)
	l.updateUnresolvedIndexesLocked()
	c.signalLocked()
	return nil
}

func (l *v3SourcePublicationLease) resolveNoBindings(gate *authoritypb.SourcePublicationGate) error {
	if l == nil || l.gate == nil {
		return errors.New("portablefsd: source namespace resolution has no lease")
	}
	_, names, err := coordinatesForV3SourceGate(gate)
	if err != nil {
		return err
	}
	c := l.gate
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.terminal != nil || l.released {
		return errors.New("portablefsd: source namespaces resolved after their publication lease ended")
	}
	for namespace, bounds := range names {
		if !l.hasNamespaceClaimLocked(namespace, bounds) {
			return errors.New("portablefsd: source namespace resolution was outside its call's declaration")
		}
	}
	for namespace, bounds := range names {
		l.consumeNamespaceClaimLocked(namespace, bounds)
	}
	l.updateUnresolvedIndexesLocked()
	c.signalLocked()
	return nil
}

func (l *v3SourcePublicationLease) hasNamespaceClaimLocked(namespace v3PublicationNamespace, bounds v3PublicationBounds) bool {
	claims, exists := l.names[namespace]
	if !exists {
		return !bounds.attributes && !bounds.data
	}
	return (!bounds.attributes || claims.attributes > 0) && (!bounds.data || claims.data > 0)
}

func (l *v3SourcePublicationLease) consumeNamespaceClaimLocked(namespace v3PublicationNamespace, bounds v3PublicationBounds) {
	claims := l.names[namespace]
	if bounds.attributes {
		claims.attributes--
		l.unresolvedAttributes--
	}
	if bounds.data {
		claims.data--
		l.unresolvedData--
	}
	if claims == (v3PublicationClaims{}) {
		delete(l.names, namespace)
	} else {
		l.names[namespace] = claims
	}
}

func (l *v3SourcePublicationLease) updateUnresolvedIndexesLocked() {
	c := l.gate
	if l.unresolvedAttributes == 0 {
		delete(c.unresolvedAttributes, l)
	} else {
		c.unresolvedAttributes[l] = l.unresolvedAttributes
	}
	if l.unresolvedData == 0 {
		delete(c.unresolvedData, l)
	} else {
		c.unresolvedData[l] = l.unresolvedData
	}
}

func (c *v3SourcePublicationCoordinator) releaseSourceLocked(lease *v3SourcePublicationLease) {
	if lease == nil || lease.released || c.terminal != nil {
		return
	}
	lease.released = true
	delete(c.unresolvedAttributes, lease)
	delete(c.unresolvedData, lease)
	for coordinate := range lease.coordinates {
		if c.sourceHolds[coordinate] == lease {
			delete(c.sourceHolds, coordinate)
		}
	}
	c.signalLocked()
}

func (c *v3SourcePublicationCoordinator) acquirePeer(ctx context.Context, sequence uint64, targets []*authoritypb.VisibilityTarget) error {
	if ctx == nil || sequence == 0 {
		return errors.New("portablefsd: peer PREPARE omitted its sequence")
	}
	coordinates, err := coordinatesForV3PeerTargets(targets)
	if err != nil || len(coordinates) == 0 {
		return errors.Join(errors.New("portablefsd: peer PREPARE omitted its exact publication footprint"), err)
	}
	// Close peer admission first, atomically. Existing source leases remain
	// owners and are drained below; every later overlapping source acquisition
	// sees peerHolds and is definitely refused before replay assignment. A
	// check-then-install loop would let a source continuously slip through the
	// drain window and would not define a publication cut at all.
	c.mu.Lock()
	if c.terminal != nil {
		err := c.terminal
		c.mu.Unlock()
		return err
	}
	if c.peerSequence != 0 {
		c.mu.Unlock()
		return errors.New("portablefsd: peer PREPARE overlapped an unreleased phase")
	}
	c.peerSequence = sequence
	c.peerHolds = coordinates
	c.peerContended = false
	c.signalLocked()
	c.mu.Unlock()

	for {
		c.mu.Lock()
		if c.terminal != nil {
			err := c.terminal
			c.mu.Unlock()
			return err
		}
		if c.peerSequence != sequence {
			c.mu.Unlock()
			return errors.New("portablefsd: peer PREPARE lost its publication cut while draining")
		}
		if !c.peerConflictLocked(coordinates) {
			c.mu.Unlock()
			return nil
		}
		changed := c.changed
		c.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return fmt.Errorf("portablefsd: peer PREPARE waited for callback publication: %w", ctx.Err())
		}
	}
}

func (c *v3SourcePublicationCoordinator) validateComplete(sequence uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.terminal != nil {
		return c.terminal
	}
	if sequence == 0 || c.peerSequence != sequence || len(c.peerHolds) == 0 {
		return errors.New("portablefsd: peer COMPLETE has no matching held PREPARE cut")
	}
	return nil
}

func (c *v3SourcePublicationCoordinator) peerContention(sequence uint64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return sequence != 0 && c.peerSequence == sequence && c.peerContended
}

func (c *v3SourcePublicationCoordinator) releasePeer(sequence uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.terminal != nil {
		return c.terminal
	}
	if sequence == 0 || c.peerSequence != sequence {
		return errors.New("portablefsd: peer COMPLETE released a different publication cut")
	}
	c.peerSequence = 0
	c.peerHolds = make(map[v3PublicationCoordinate]struct{})
	c.peerContended = false
	c.signalLocked()
	return nil
}

func (c *v3SourcePublicationCoordinator) fail(cause error) {
	if cause == nil {
		cause = errors.New("portablefsd: source publication coordinator failed")
	}
	c.mu.Lock()
	if c.terminal == nil {
		c.terminal = cause
		c.signalLocked()
	}
	c.mu.Unlock()
}
