//go:build linux

package fusev3

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math"
	"sort"
	"sync"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"google.golang.org/protobuf/proto"
)

const (
	maxLeaseRenewalBatch  = 1024
	leaseExpiryWorkers    = 8
	leaseExpiryQueueDepth = 1024
	leaseMaintenanceTick  = 10 * time.Millisecond
	leaseHorizonAbortLead = time.Second
)

type leaseKey struct {
	family   authoritypb.LeaseFamily
	identity publicationIdentity
	parent   publicationIdentity
	name     string
}

type heldLease struct {
	grant       validatedLeaseGrant
	refreshAt   time.Time
	purgeAt     time.Time
	revoking    bool
	renewing    bool
	revokeEpoch uint64
}

type leaseRegistry struct {
	mount          *Mount
	mu             sync.Mutex
	leases         map[leaseKey]*heldLease
	leaseCounts    map[authoritypb.LeaseFamily]int
	maxPerFamily   int
	pendingRecalls map[leaseKey]*authoritypb.LeaseRecall
	grantFloor     uint64
}

func newLeaseRegistry(mount *Mount) *leaseRegistry {
	capacity := defaultCachedNameCapacity
	if mount != nil && mount.nameCapacity > 0 {
		capacity = mount.nameCapacity
	}
	return &leaseRegistry{
		mount: mount, leases: make(map[leaseKey]*heldLease), leaseCounts: make(map[authoritypb.LeaseFamily]int),
		maxPerFamily: capacity, pendingRecalls: make(map[leaseKey]*authoritypb.LeaseRecall),
	}
}

func (r *leaseRegistry) deleteLeaseLocked(key leaseKey) {
	if r.leases[key] == nil {
		return
	}
	delete(r.leases, key)
	if r.leaseCounts[key.family] > 0 {
		r.leaseCounts[key.family]--
	}
}

func (g validatedLeaseGrant) key() leaseKey {
	return leaseKey{family: g.family, identity: g.identity, parent: g.parent, name: g.name}
}

func (k leaseKey) publicationCoordinate() (publicationCoordinate, bool) {
	switch k.family {
	case authoritypb.LeaseFamily_LEASE_FAMILY_NAME:
		return publicationCoordinate{kind: publicationNamespaceName, parent: k.parent, name: k.name}, true
	case authoritypb.LeaseFamily_LEASE_FAMILY_ATTRIBUTES:
		return publicationCoordinate{kind: publicationItemAttributes, item: k.identity}, true
	case authoritypb.LeaseFamily_LEASE_FAMILY_DATA:
		return publicationCoordinate{kind: publicationItemData, item: k.identity}, true
	case authoritypb.LeaseFamily_LEASE_FAMILY_ENUMERATION:
		return publicationCoordinate{kind: publicationItemEnumeration, item: k.identity}, true
	default:
		return publicationCoordinate{}, false
	}
}

func (r *leaseRegistry) install(grants []validatedLeaseGrant, now time.Time) []validatedLeaseGrant {
	r.mu.Lock()
	defer r.mu.Unlock()
	accepted := make([]validatedLeaseGrant, 0, len(grants))
	for _, grant := range grants {
		grant.cacheDeadline = grant.deadline.Add(-volumeserver.Protocol6LeaseWithdrawalBudget)
		key := grant.key()
		if !grant.cacheDeadline.After(now) || grant.issuedSequence < r.grantFloor {
			continue
		}
		// A grant may race ahead of COMPLETE on the data lane. Keep this
		// coordinate closed until the recall transaction has completed locally.
		if r.pendingRecalls[key] != nil {
			continue
		}
		current := r.leases[key]
		if current != nil {
			// A new epoch cannot replace a live local obligation. D pages and E
			// directory continuations outlive the authority reply that created
			// them; borrowing a successor epoch before the old epoch is purged
			// would make that stale payload look current. Recall/expiry removes the
			// old obligation first, after which a later request can install the new
			// epoch. Same-epoch renewal is the only in-place update.
			if current.revoking || grant.epoch < current.grant.epoch || grant.epoch == current.grant.epoch && !grant.deadline.After(current.grant.deadline) {
				continue
			}
			if grant.epoch > current.grant.epoch && r.mount != nil && r.mount.raw != nil &&
				r.mount.raw.hasLeasePayload(key, current.grant.epoch) {
				continue
			}
		} else if r.leaseCounts[key.family] >= r.maxPerFamily {
			// The kernel cache budget also bounds userspace lease state. Refusing
			// a surplus grant is safe: a later recall is handled by the missing-
			// grant path, while this reply remains explicitly non-cacheable.
			continue
		}
		cacheFor := grant.cacheDeadline.Sub(now)
		r.leases[key] = &heldLease{
			grant: grant, refreshAt: now.Add(cacheFor / 2), purgeAt: grant.cacheDeadline,
		}
		if current == nil {
			r.leaseCounts[key.family]++
		}
		accepted = append(accepted, grant)
	}
	return accepted
}

func (r *rawFileSystem) hasLeasePayload(key leaseKey, epoch uint64) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch key.family {
	case authoritypb.LeaseFamily_LEASE_FAMILY_DATA:
		record := r.byIdentityLocked(key.identity)
		return record != nil && r.cachedData[record.key.inode] == record
	case authoritypb.LeaseFamily_LEASE_FAMILY_ENUMERATION:
		for _, handle := range r.handles {
			if handle != nil && handle.dir != nil && handle.inode != nil && handle.inode.identity == key.identity {
				// Treat an open directory handle as an obligation until the
				// recall/expiry path purges it. This conservative check avoids
				// taking dirHandle.mu under the lease registry lock.
				return true
			}
		}
	}
	return false
}

func (r *leaseRegistry) mergeSourceTombstones(sequence uint64, recalls map[leaseKey]uint64) error {
	if sequence == 0 {
		return errors.New("fusev3: zero source recall sequence")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.grantFloor = max(r.grantFloor, sequence)
	return nil
}

func (r *leaseRegistry) remaining(key leaseKey, right authoritypb.LeaseRight, now time.Time) time.Duration {
	if r == nil {
		return 0
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	lease := r.leases[key]
	if lease == nil || lease.revoking || lease.grant.right != right || !lease.purgeAt.After(now) {
		return 0
	}
	return lease.purgeAt.Sub(now)
}

func (r *leaseRegistry) beginRecalls(ctx context.Context, sequence uint64, recalls []*authoritypb.LeaseRecall) ([]leaseKey, error) {
	r.mu.Lock()
	if sequence == 0 {
		r.mu.Unlock()
		return nil, errors.New("fusev3: zero lease recall sequence")
	}
	keys := make([]leaseKey, 0, len(recalls))
	for _, recall := range recalls {
		validated, err := validateLeaseRecall(recall)
		if err != nil {
			r.mu.Unlock()
			return nil, err
		}
		key := validated.key()
		lease := r.leases[key]
		if pending := r.pendingRecalls[key]; pending != nil {
			if pending.GetGrantEpoch() != recall.GetGrantEpoch() || pending.GetRevokeEpoch() != recall.GetRevokeEpoch() || pending.GetRight() != recall.GetRight() {
				r.mu.Unlock()
				return nil, errors.New("fusev3: conflicting duplicate lease recall")
			}
			keys = append(keys, key)
			continue
		}
		if lease != nil && (lease.grant.epoch != recall.GetGrantEpoch() || lease.grant.right != recall.GetRight()) {
			r.mu.Unlock()
			return nil, errors.New("fusev3: lease recall does not match a live grant")
		}
		if lease != nil {
			lease.revoking, lease.revokeEpoch = true, recall.GetRevokeEpoch()
		}
		r.pendingRecalls[key] = proto.Clone(recall).(*authoritypb.LeaseRecall)
		keys = append(keys, key)
	}
	r.grantFloor = max(r.grantFloor, sequence)
	r.mu.Unlock()
	for _, key := range keys {
		if coordinate, ok := key.publicationCoordinate(); ok && r.mount.raw != nil {
			if err := r.mount.raw.closeLeaseCoordinate(ctx, coordinate); err != nil {
				return nil, err
			}
		}
	}
	return keys, nil
}

func validateLeaseRecall(recall *authoritypb.LeaseRecall) (validatedLeaseGrant, error) {
	if recall == nil || recall.GetGrantEpoch() == 0 || recall.GetRevokeEpoch() <= recall.GetGrantEpoch() {
		return validatedLeaseGrant{}, errors.New("fusev3: malformed lease recall")
	}
	grants, err := validateLeaseGrants([]*authoritypb.LeaseGrant{{
		Coordinate: recall.GetCoordinate(), Right: recall.GetRight(), Epoch: recall.GetGrantEpoch(), ValidForNanos: 1, IssuedSequence: 1,
	}}, time.Now())
	if err != nil {
		return validatedLeaseGrant{}, err
	}
	return grants[0], nil
}

func (r *leaseRegistry) completeRecalls(recalls []*authoritypb.LeaseRecall) ([]*authoritypb.LeaseDischarge, error) {
	type recalled struct {
		key    leaseKey
		recall *authoritypb.LeaseRecall
	}
	items := make([]recalled, 0, len(recalls))
	r.mu.Lock()
	for _, recall := range recalls {
		validated, err := validateLeaseRecall(recall)
		if err != nil {
			r.mu.Unlock()
			return nil, err
		}
		key := validated.key()
		pending := r.pendingRecalls[key]
		if pending == nil || pending.GetGrantEpoch() != recall.GetGrantEpoch() || pending.GetRevokeEpoch() != recall.GetRevokeEpoch() {
			r.mu.Unlock()
			return nil, errors.New("fusev3: COMPLETE does not match the pending recall")
		}
		items = append(items, recalled{key: key, recall: recall})
	}
	r.mu.Unlock()
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].key.family == authoritypb.LeaseFamily_LEASE_FAMILY_NAME && items[j].key.family != authoritypb.LeaseFamily_LEASE_FAMILY_NAME
	})
	discharges := make([]*authoritypb.LeaseDischarge, 0, len(items))
	for _, item := range items {
		if r.mount.raw != nil {
			if err := r.mount.raw.invalidateLease(item.key); err != nil {
				return nil, err
			}
		}
		discharges = append(discharges, &authoritypb.LeaseDischarge{
			Coordinate: item.recall.GetCoordinate(), RevokeEpoch: item.recall.GetRevokeEpoch(),
			Mode: authoritypb.LeaseDischargeMode_LEASE_DISCHARGE_MODE_TO_NONE,
		})
	}
	return discharges, nil
}

func (r *leaseRegistry) finishRecalls(recalls []*authoritypb.LeaseRecall) {
	r.mu.Lock()
	keys := make([]leaseKey, 0, len(recalls))
	for _, recall := range recalls {
		validated, err := validateLeaseRecall(recall)
		if err != nil {
			continue
		}
		key := validated.key()
		r.deleteLeaseLocked(key)
		delete(r.pendingRecalls, key)
		keys = append(keys, key)
	}
	r.mu.Unlock()
	for _, key := range keys {
		if coordinate, ok := key.publicationCoordinate(); ok && r.mount.raw != nil {
			r.mount.raw.openLeaseCoordinate(coordinate)
		}
	}
}

func (m *Mount) dischargeSourceLeases(discharge *authoritypb.SourceLeaseDischarge) error {
	if discharge == nil || discharge.GetSequence() == 0 || len(discharge.GetRecalls()) == 0 {
		return errors.New("fusev3: source reply omitted its exact lease discharge")
	}
	type recalled struct {
		key    leaseKey
		recall *authoritypb.LeaseRecall
	}
	items := make([]recalled, 0, len(discharge.GetRecalls()))
	for _, recall := range discharge.GetRecalls() {
		grant, err := validateLeaseRecall(recall)
		if err != nil {
			return err
		}
		items = append(items, recalled{key: grant.key(), recall: recall})
	}
	recalledEpochs := make(map[leaseKey]uint64, len(items))
	for _, item := range items {
		recalledEpochs[item.key] = item.recall.GetRevokeEpoch()
	}
	if err := m.leases.mergeSourceTombstones(discharge.GetSequence(), recalledEpochs); err != nil {
		return err
	}
	for _, item := range items {
		m.leases.mu.Lock()
		if held := m.leases.leases[item.key]; held != nil && held.grant.epoch <= item.recall.GetGrantEpoch() {
			m.leases.deleteLeaseLocked(item.key)
		}
		m.leases.mu.Unlock()
	}
	ctx, cancel := context.WithTimeout(m.ctx, m.repairBudget)
	err := m.rpc.AcknowledgeSourceLeaseDischarge(ctx, discharge.GetSequence())
	cancel()
	if err != nil {
		return fmt.Errorf("fusev3: acknowledge source lease discharge %d: %w", discharge.GetSequence(), err)
	}
	return nil
}

// prepareSourceLeaseDischarge purges daemon name/enumeration state and retained
// inode state before the source mutation reply can wake another local syscall.
// Kernel dentries carry zero validity, so N needs no post-write notification.
func (m *Mount) prepareSourceLeaseDischarge(publication *replyPublication) error {
	if publication == nil || publication.sourceLeaseDischarge == nil {
		return nil
	}
	items := make([]leaseKey, 0, len(publication.sourceLeaseDischarge.GetRecalls()))
	for _, recall := range publication.sourceLeaseDischarge.GetRecalls() {
		grant, err := validateLeaseRecall(recall)
		if err != nil {
			return err
		}
		items = append(items, grant.key())
	}
	sort.SliceStable(items, func(i, j int) bool {
		return items[i].family == authoritypb.LeaseFamily_LEASE_FAMILY_ENUMERATION && items[j].family != authoritypb.LeaseFamily_LEASE_FAMILY_ENUMERATION
	})
	for _, key := range items {
		if m.raw == nil {
			continue
		}
		if key.family == authoritypb.LeaseFamily_LEASE_FAMILY_NAME {
			if _, err := m.raw.invalidateDaemonNameLease(key); err != nil {
				return err
			}
			continue
		}
		if err := m.raw.invalidateLease(key); err != nil {
			return err
		}
	}
	return nil
}

func (r *rawFileSystem) forgetLeaseTracking(key leaseKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch key.family {
	case authoritypb.LeaseFamily_LEASE_FAMILY_NAME:
		parent := r.byIdentityLocked(key.parent)
		if parent == nil {
			return
		}
		name := nameKey{parent: parent.key.inode, name: key.name}
		r.dropCachedNameLocked(name)
		r.dropCachedNegativeLocked(name)
	case authoritypb.LeaseFamily_LEASE_FAMILY_ATTRIBUTES:
		delete(r.cachedAttrs, key.identity)
		delete(r.cachedAttrPayloads, key.identity)
	case authoritypb.LeaseFamily_LEASE_FAMILY_DATA:
		if record := r.byIdentityLocked(key.identity); record != nil {
			delete(r.cachedData, record.key.inode)
		}
	}
}

func (r *leaseRegistry) dueExpirations(now time.Time) (expired []leaseKey) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, lease := range r.leases {
		if lease.revoking {
			continue
		}
		if !lease.purgeAt.After(now) {
			lease.revoking = true
			expired = append(expired, key)
		}
	}
	return expired
}

// dueRenewals selects one bounded frame of still-held cache obligations.
// Kernel A/D hits bypass this daemon, so absence of userspace traffic is not
// evidence that an obligation is cold and cannot suppress its renewal.
func (r *leaseRegistry) dueRenewals(now time.Time, limit int) (renewals []*authoritypb.LeaseRenewal) {
	if limit <= 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, lease := range r.leases {
		if len(renewals) == limit {
			break
		}
		if lease.revoking || lease.renewing || lease.refreshAt.After(now) || !lease.purgeAt.After(now) {
			continue
		}
		lease.renewing = true
		renewals = append(renewals, &authoritypb.LeaseRenewal{Coordinate: leaseCoordinateFromKey(key), Epoch: lease.grant.epoch})
	}
	return renewals
}

func leaseCoordinateFromKey(key leaseKey) *authoritypb.LeaseCoordinate {
	coordinate := &authoritypb.LeaseCoordinate{Family: key.family}
	if key.family == authoritypb.LeaseFamily_LEASE_FAMILY_NAME {
		coordinate.ParentIdentity = append([]byte(nil), key.parent[:]...)
		coordinate.Name = []byte(key.name)
	} else {
		coordinate.Identity = append([]byte(nil), key.identity[:]...)
	}
	return coordinate
}

func leaseKeyFromRenewal(renewal *authoritypb.LeaseRenewal) (leaseKey, error) {
	if renewal == nil || renewal.GetEpoch() == 0 || renewal.GetCoordinate() == nil {
		return leaseKey{}, errors.New("fusev3: malformed withdrawn lease renewal")
	}
	right := authoritypb.LeaseRight_LEASE_RIGHT_UNSPECIFIED
	switch renewal.GetCoordinate().GetFamily() {
	case authoritypb.LeaseFamily_LEASE_FAMILY_NAME:
		right = authoritypb.LeaseRight_LEASE_RIGHT_NAME_READ
	case authoritypb.LeaseFamily_LEASE_FAMILY_ATTRIBUTES:
		right = authoritypb.LeaseRight_LEASE_RIGHT_ATTRIBUTES_READ
	case authoritypb.LeaseFamily_LEASE_FAMILY_DATA:
		right = authoritypb.LeaseRight_LEASE_RIGHT_DATA_READ
	case authoritypb.LeaseFamily_LEASE_FAMILY_ENUMERATION:
		right = authoritypb.LeaseRight_LEASE_RIGHT_ENUMERATION_READ
	default:
		return leaseKey{}, errors.New("fusev3: withdrawn lease has unknown family")
	}
	validated, err := validateLeaseGrants([]*authoritypb.LeaseGrant{{
		Coordinate: renewal.GetCoordinate(), Right: right, Epoch: renewal.GetEpoch(),
		ValidForNanos: 1, IssuedSequence: 1,
	}}, time.Now())
	if err != nil {
		return leaseKey{}, err
	}
	return validated[0].key(), nil
}

func (r *leaseRegistry) expireWithdrawal(renewal *authoritypb.LeaseRenewal) error {
	key, err := leaseKeyFromRenewal(renewal)
	if err != nil {
		return err
	}
	r.mu.Lock()
	held := r.leases[key]
	if held == nil || held.grant.epoch != renewal.GetEpoch() {
		r.mu.Unlock()
		return nil
	}
	held.revoking = true
	r.mu.Unlock()
	return r.expire(key)
}

func (r *leaseRegistry) expire(key leaseKey) error {
	if coordinate, ok := key.publicationCoordinate(); ok && r.mount.raw != nil {
		ctx, cancel := context.WithTimeout(context.Background(), r.mount.repairBudget)
		err := r.mount.raw.closeLeaseCoordinate(ctx, coordinate)
		cancel()
		if err != nil {
			return err
		}
		r.mu.Lock()
		remoteOwnsCut := r.pendingRecalls[key] != nil
		r.mu.Unlock()
		if remoteOwnsCut {
			return nil
		}
		if err := r.mount.raw.invalidateLease(key); err != nil {
			return err
		}
		r.mu.Lock()
		remoteOwnsCut = r.pendingRecalls[key] != nil
		if remoteOwnsCut {
			r.mu.Unlock()
			return nil
		}
		r.deleteLeaseLocked(key)
		// Keep the decision and gate transition atomic with respect to a remote
		// REVOKE taking ownership of the same coordinate.
		r.mount.raw.openLeaseCoordinate(coordinate)
		r.mu.Unlock()
		return nil
	}
	r.mu.Lock()
	r.deleteLeaseLocked(key)
	r.mu.Unlock()
	return nil
}

func (r *leaseRegistry) installRenewals(timed []authorityrpc.TimedLeaseGrant) error {
	now := time.Now()
	for _, timedGrant := range timed {
		if timedGrant.Grant == nil || !timedGrant.ValidUntil.After(now) {
			continue
		}
		started := timedGrant.ValidUntil.Add(-time.Duration(timedGrant.Grant.GetValidForNanos()))
		grants, err := validateLeaseGrants([]*authoritypb.LeaseGrant{timedGrant.Grant}, started)
		if err != nil {
			return err
		}
		grant := grants[0]
		grant.deadline = timedGrant.ValidUntil
		grant.cacheDeadline = grant.deadline.Add(-volumeserver.Protocol6LeaseWithdrawalBudget)
		if !grant.cacheDeadline.After(now) {
			continue
		}
		key := grant.key()
		r.mu.Lock()
		held := r.leases[key]
		// A renewal result belongs only to the exact in-flight token. Local
		// expiry or CONTROL may have started while its RPC was outstanding; a
		// late result must never resurrect that cache obligation.
		if held != nil && held.renewing && !held.revoking && held.grant.epoch == grant.epoch && grant.issuedSequence >= r.grantFloor {
			cacheFor := grant.cacheDeadline.Sub(now)
			held.grant = grant
			held.refreshAt = now.Add(cacheFor / 2)
			held.purgeAt = grant.cacheDeadline
			held.renewing = false
		}
		r.mu.Unlock()
	}
	return nil
}

func (r *leaseRegistry) hardDeadlineDue(now time.Time) (leaseKey, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for key, lease := range r.leases {
		if !lease.grant.deadline.After(now.Add(leaseHorizonAbortLead)) {
			return key, true
		}
	}
	return leaseKey{}, false
}

func validateLeaseCompletePostState(state *authoritypb.PostState) error {
	if state == nil {
		return nil
	}
	if err := validateMutationPostState(state); err != nil {
		return fmt.Errorf("fusev3: COMPLETE carried invalid post-state: %w", err)
	}
	return nil
}

func (m *Mount) runLeaseEvents(ctx context.Context) {
	defer m.wg.Done()
	cursor := m.rpc.InitialLeaseCursor()
	if cursor == nil {
		m.failAsync(errors.New("fusev3: authority omitted initial lease cursor"))
		return
	}
	for {
		event, err := m.rpc.NextLeaseEvent(ctx, cursor)
		if err != nil {
			if ctx.Err() == nil {
				m.failAsync(fmt.Errorf("fusev3: receive lease event: %w", err))
			}
			return
		}
		if event.GetCursor() == nil || event.GetCursor().GetSequence() == 0 {
			m.failAsync(errors.New("fusev3: malformed lease event cursor"))
			return
		}
		if bytes.Equal(event.GetInitiatorSessionId(), m.rpc.SessionID()) {
			m.failAsync(errors.New("fusev3: self-directed lease recall event"))
			return
		}
		switch event.GetCursor().GetPhase() {
		case authoritypb.LeaseEventPhase_LEASE_EVENT_PHASE_REVOKE:
			ackCtx, cancel := context.WithTimeout(ctx, m.repairBudget)
			if _, err := m.leases.beginRecalls(ackCtx, event.GetCursor().GetSequence(), event.GetRecalls()); err != nil {
				cancel()
				m.failAsync(err)
				return
			}
			err = m.rpc.AcknowledgeLeaseEvent(ackCtx, event.GetCursor(), nil)
			cancel()
		case authoritypb.LeaseEventPhase_LEASE_EVENT_PHASE_COMPLETE:
			if err := validateLeaseCompletePostState(event.GetPostState()); err != nil {
				m.failAsync(err)
				return
			}
			discharges, completeErr := m.leases.completeRecalls(event.GetRecalls())
			if completeErr != nil {
				m.failAsync(completeErr)
				return
			}
			ackCtx, cancel := context.WithTimeout(ctx, m.repairBudget)
			err = m.rpc.AcknowledgeLeaseEvent(ackCtx, event.GetCursor(), discharges)
			cancel()
			if err == nil {
				m.leases.finishRecalls(event.GetRecalls())
			}
		default:
			err = errors.New("fusev3: unknown lease event phase")
		}
		if err != nil {
			m.failAsync(fmt.Errorf("fusev3: acknowledge lease event: %w", err))
			return
		}
		cursor = event.GetCursor()
	}
}

func (m *Mount) runLeaseMaintenance(ctx context.Context) {
	defer m.wg.Done()
	ticker := time.NewTicker(leaseMaintenanceTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			expired := m.leases.dueExpirations(now)
			for _, key := range expired {
				select {
				case m.leaseExpiry <- key:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}

func (m *Mount) runLeaseExpiry(ctx context.Context) {
	defer m.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case key := <-m.leaseExpiry:
			if err := m.leases.expire(key); err != nil {
				m.failAsync(fmt.Errorf("fusev3: expire cache lease: %w", err))
				return
			}
		}
	}
}

func (m *Mount) runLeaseRenewals(ctx context.Context) {
	defer m.wg.Done()
	ticker := time.NewTicker(leaseMaintenanceTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			renewals := m.leases.dueRenewals(now, maxLeaseRenewalBatch)
			if len(renewals) == 0 {
				continue
			}
			renewCtx, cancel := context.WithTimeout(ctx, m.repairBudget)
			outcome, err := m.rpc.RenewLeases(renewCtx, renewals)
			cancel()
			if err != nil {
				m.failAsync(fmt.Errorf("fusev3: renew cache leases: %w", err))
				return
			}
			for _, withdrawn := range outcome.Withdrawn {
				if err := m.leases.expireWithdrawal(withdrawn); err != nil {
					m.failAsync(fmt.Errorf("fusev3: expire withdrawn cache lease: %w", err))
					return
				}
			}
			if err := m.leases.installRenewals(outcome.Grants); err != nil {
				m.failAsync(fmt.Errorf("fusev3: install renewed cache leases: %w", err))
				return
			}
		}
	}
}

func (m *Mount) runLeaseHardWatchdog(ctx context.Context) {
	defer m.wg.Done()
	ticker := time.NewTicker(leaseMaintenanceTick)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			key, due := m.leases.hardDeadlineDue(now)
			if !due {
				continue
			}
			m.abortAtLeaseHorizon(key)
			return
		}
	}
}

// abortAtLeaseHorizon is deliberately independent of reverse notifications.
// A kernel invalidation may be parked on a VFS reference indefinitely; when
// that happens, writing fusectl's abort file is the only operation that can
// stop new requests without joining the parked notifier. It does not purge a
// resident page already reachable through a preexisting fd or mapping. That
// post-fence state is reported as an unproved withdrawal by the ordinary
// revocation ladder instead of being mislabeled as repaired cache state.
func (m *Mount) abortAtLeaseHorizon(key leaseKey) {
	cause := fmt.Errorf("%w: cache lease family %s reached its authority horizon before local withdrawal completed", errRepairBudgetExceeded, key.family.String())
	m.revoked.Store(true)
	m.recordFatalCause(cause)
	if m.cancel != nil {
		m.cancel()
	}
	// Schedule detach/terminal bookkeeping before entering fusectl I/O. The
	// direct abort below is intentionally concurrent with that ladder: neither
	// path is allowed to wait for the other path's potentially parked notifier.
	m.scheduleAbort()
	if m.kernelMount.device == "" {
		m.recordFatalCause(errors.New("fusev3: lease horizon reached without an installed FUSE connection to abort"))
		return
	}
	abort := m.leaseHorizonAbort
	if abort == nil {
		abort = func(installed kernelMount) error { return installed.abortKernelConnection() }
	}
	if err := abort(m.kernelMount); err != nil {
		m.recordFatalCause(fmt.Errorf("fusev3: direct lease-horizon FUSE abort: %w", err))
	}
}

type validatedLeaseGrant struct {
	family         authoritypb.LeaseFamily
	right          authoritypb.LeaseRight
	identity       publicationIdentity
	parent         publicationIdentity
	name           string
	epoch          uint64
	issuedSequence uint64
	deadline       time.Time
	cacheDeadline  time.Time
}

func validateLeaseGrants(grants []*authoritypb.LeaseGrant, requestStart time.Time) ([]validatedLeaseGrant, error) {
	validated := make([]validatedLeaseGrant, 0, len(grants))
	seen := make(map[leaseKey]struct{}, len(grants))
	for _, grant := range grants {
		if grant == nil || grant.GetCoordinate() == nil || grant.GetEpoch() == 0 || grant.GetIssuedSequence() == 0 || grant.GetValidForNanos() == 0 || grant.GetValidForNanos() > math.MaxInt64 || time.Duration(grant.GetValidForNanos()) > volumeserver.Protocol6MaxLeaseTTL {
			return nil, errors.New("fusev3: authority returned a malformed lease grant")
		}
		coordinate := grant.GetCoordinate()
		entry := validatedLeaseGrant{family: coordinate.GetFamily(), right: grant.GetRight(), epoch: grant.GetEpoch(), issuedSequence: grant.GetIssuedSequence(), deadline: requestStart.Add(time.Duration(grant.GetValidForNanos()))}
		switch coordinate.GetFamily() {
		case authoritypb.LeaseFamily_LEASE_FAMILY_NAME:
			if grant.GetRight() != authoritypb.LeaseRight_LEASE_RIGHT_NAME_READ && grant.GetRight() != authoritypb.LeaseRight_LEASE_RIGHT_NAME_EXCLUSIVE ||
				len(coordinate.GetParentIdentity()) != len(entry.parent) || len(coordinate.GetIdentity()) != 0 || !validLeaseName(coordinate.GetName()) {
				return nil, errors.New("fusev3: authority returned an invalid name lease grant")
			}
			copy(entry.parent[:], coordinate.GetParentIdentity())
			entry.name = string(coordinate.GetName())
		case authoritypb.LeaseFamily_LEASE_FAMILY_ATTRIBUTES:
			if grant.GetRight() != authoritypb.LeaseRight_LEASE_RIGHT_ATTRIBUTES_READ && grant.GetRight() != authoritypb.LeaseRight_LEASE_RIGHT_ATTRIBUTES_EXCLUSIVE || !validObjectLeaseCoordinate(coordinate) {
				return nil, errors.New("fusev3: authority returned an invalid attribute lease grant")
			}
			copy(entry.identity[:], coordinate.GetIdentity())
		case authoritypb.LeaseFamily_LEASE_FAMILY_DATA:
			if grant.GetRight() != authoritypb.LeaseRight_LEASE_RIGHT_DATA_READ && grant.GetRight() != authoritypb.LeaseRight_LEASE_RIGHT_DATA_EXCLUSIVE || !validObjectLeaseCoordinate(coordinate) {
				return nil, errors.New("fusev3: authority returned an invalid data lease grant")
			}
			copy(entry.identity[:], coordinate.GetIdentity())
		case authoritypb.LeaseFamily_LEASE_FAMILY_ENUMERATION:
			if grant.GetRight() != authoritypb.LeaseRight_LEASE_RIGHT_ENUMERATION_READ || !validObjectLeaseCoordinate(coordinate) {
				return nil, errors.New("fusev3: authority returned an invalid enumeration lease grant")
			}
			copy(entry.identity[:], coordinate.GetIdentity())
		default:
			return nil, errors.New("fusev3: authority returned an unknown lease family")
		}
		if entry.identity == (publicationIdentity{}) && entry.parent == (publicationIdentity{}) {
			return nil, errors.New("fusev3: authority returned a zero lease identity")
		}
		if _, duplicate := seen[entry.key()]; duplicate {
			return nil, errors.New("fusev3: authority returned a duplicate lease coordinate")
		}
		seen[entry.key()] = struct{}{}
		validated = append(validated, entry)
	}
	return validated, nil
}

func validObjectLeaseCoordinate(coordinate *authoritypb.LeaseCoordinate) bool {
	return len(coordinate.GetIdentity()) == len(publicationIdentity{}) && len(coordinate.GetParentIdentity()) == 0 && len(coordinate.GetName()) == 0
}

func validLeaseName(name []byte) bool {
	return len(name) != 0 && len(name) <= 255 && bytes.IndexByte(name, 0) < 0 && bytes.IndexByte(name, '/') < 0 && !bytes.Equal(name, []byte(".")) && !bytes.Equal(name, []byte(".."))
}

func captureLeaseGrants(mount *Mount, ctxPublication *replyPublication, response *authoritypb.Response, requestStart time.Time) error {
	if response == nil {
		return nil
	}
	timedGrants, err := authorityrpc.TimedResponseLeaseGrants(response, requestStart)
	if err != nil {
		return err
	}
	grants := make([]validatedLeaseGrant, 0, len(timedGrants))
	for _, timed := range timedGrants {
		validated, validateErr := validateLeaseGrants([]*authoritypb.LeaseGrant{timed.Grant}, requestStart)
		if validateErr != nil {
			return validateErr
		}
		validated[0].deadline = timed.ValidUntil
		validated[0].cacheDeadline = timed.ValidUntil.Add(-volumeserver.Protocol6LeaseWithdrawalBudget)
		grants = append(grants, validated[0])
	}
	if mount == nil || mount.leases == nil {
		if ctxPublication != nil {
			ctxPublication.leaseGrants = append(ctxPublication.leaseGrants, grants...)
		}
		return nil
	}
	accepted := mount.leases.install(grants, time.Now())
	if ctxPublication != nil {
		ctxPublication.leaseGrants = append(ctxPublication.leaseGrants, accepted...)
	}
	return nil
}

func (p *replyPublication) leaseRemaining(family authoritypb.LeaseFamily, right authoritypb.LeaseRight, identity, parent publicationIdentity, name string, now time.Time) time.Duration {
	grant, ok := p.leaseGrant(family, right, identity, parent, name, now)
	if !ok {
		return 0
	}
	return grant.cacheDeadline.Sub(now)
}

func (p *replyPublication) leaseGrant(family authoritypb.LeaseFamily, right authoritypb.LeaseRight, identity, parent publicationIdentity, name string, now time.Time) (validatedLeaseGrant, bool) {
	if p == nil {
		return validatedLeaseGrant{}, false
	}
	var selected validatedLeaseGrant
	for _, grant := range p.leaseGrants {
		if grant.family != family || grant.right != right || grant.identity != identity || grant.parent != parent || grant.name != name {
			continue
		}
		if grant.cacheDeadline.After(now) && grant.cacheDeadline.After(selected.cacheDeadline) {
			selected = grant
		}
	}
	return selected, !selected.cacheDeadline.IsZero()
}

func (r *leaseRegistry) matches(key leaseKey, right authoritypb.LeaseRight, stamp leaseStamp, now time.Time) bool {
	if r == nil || stamp.epoch == 0 || stamp.issuedSequence == 0 {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	held := r.leases[key]
	// Renewal preserves the exact coordinate epoch but restamps its issue
	// generation. The epoch is the payload continuity token; issued_sequence is
	// only the cross-lane late-response admission filter.
	if held == nil || held.revoking || held.grant.right != right || held.grant.epoch != stamp.epoch || !held.purgeAt.After(now) {
		return false
	}
	return true
}

func leaseBound(policy, remaining time.Duration) time.Duration {
	if remaining <= 0 {
		return 0
	}
	if policy <= 0 || remaining < policy {
		return remaining
	}
	return policy
}

func (r *rawFileSystem) closeLeaseCoordinate(ctx context.Context, coordinate publicationCoordinate) error {
	r.mu.Lock()
	r.repairingCoordinates[coordinate] = true
	for reservation := range r.cacheReservations[coordinate] {
		reservation.revoked = true
	}
	pending := make([]<-chan struct{}, 0)
	for _, publication := range r.replyPublications {
		for index := range publication.data {
			if publication.data[index].coordinate == coordinate && !publication.originalFinalized {
				publication.data[index].revoked = true
			}
		}
		if publication.originalFinalized && !publication.originalWrote && publicationInstallsCoordinate(publication, coordinate) {
			pending = append(pending, publication.originalDone)
		}
	}
	r.signalSourceChangedLocked()
	r.mu.Unlock()
	for _, done := range pending {
		select {
		case <-done:
		case <-ctx.Done():
			return fmt.Errorf("fusev3: drain finalized cache reply for lease recall: %w", ctx.Err())
		}
	}
	return nil
}

func publicationInstallsCoordinate(publication *replyPublication, coordinate publicationCoordinate) bool {
	if publication == nil {
		return false
	}
	for _, name := range publication.names {
		if name.coordinate == coordinate {
			return true
		}
	}
	for _, attr := range publication.attrs {
		if attr.coordinate == coordinate {
			return true
		}
	}
	for _, data := range publication.data {
		if data.coordinate == coordinate {
			return true
		}
	}
	return false
}

func (r *rawFileSystem) openLeaseCoordinate(coordinate publicationCoordinate) {
	r.mu.Lock()
	delete(r.repairingCoordinates, coordinate)
	r.signalSourceChangedLocked()
	r.mu.Unlock()
}

func (r *rawFileSystem) invalidateLease(key leaseKey) error {
	switch key.family {
	case authoritypb.LeaseFamily_LEASE_FAMILY_NAME:
		_, err := r.invalidateDaemonNameLease(key)
		return err
	case authoritypb.LeaseFamily_LEASE_FAMILY_ATTRIBUTES:
		notifier := r.mount.notifier()
		if notifier == nil {
			return errors.New("fusev3: attribute lease invalidation has no kernel notification channel")
		}
		r.mu.Lock()
		record := r.cachedAttrs[key.identity]
		delete(r.cachedAttrs, key.identity)
		delete(r.cachedAttrPayloads, key.identity)
		r.mu.Unlock()
		if record != nil {
			if status := notifier.InodeNotify(record.id, -1, 0); !status.Ok() && status != fuse.ENOENT {
				return fmt.Errorf("fusev3: invalidate leased attributes for inode %d: %v", record.id, status)
			}
		}
	case authoritypb.LeaseFamily_LEASE_FAMILY_DATA:
		notifier := r.mount.notifier()
		if notifier == nil {
			return errors.New("fusev3: data lease invalidation has no kernel notification channel")
		}
		r.mu.Lock()
		record := r.byIdentityLocked(key.identity)
		if record != nil && r.cachedData[record.key.inode] == record {
			delete(r.cachedData, record.key.inode)
		} else {
			record = nil
		}
		r.mu.Unlock()
		if record != nil {
			if status := notifier.InodeNotify(record.id, 0, 0); !status.Ok() && status != fuse.ENOENT {
				return fmt.Errorf("fusev3: invalidate leased data for inode %d: %v", record.id, status)
			}
		}
	case authoritypb.LeaseFamily_LEASE_FAMILY_ENUMERATION:
		r.mu.Lock()
		handles := make([]*dirHandle, 0)
		for _, handle := range r.handles {
			if handle != nil && handle.dir != nil && handle.inode != nil && handle.inode.identity == key.identity {
				handles = append(handles, handle.dir)
			}
		}
		r.mu.Unlock()
		for _, handle := range handles {
			handle.invalidateEnumeration()
		}
	default:
		return errors.New("fusev3: invalidate unknown lease family")
	}
	return nil
}

func (r *rawFileSystem) invalidateDaemonNameLease(key leaseKey) (uint64, error) {
	if key.family != authoritypb.LeaseFamily_LEASE_FAMILY_NAME {
		return 0, errors.New("fusev3: daemon name invalidation used a non-name coordinate")
	}
	r.mu.Lock()
	parent := r.byIdentityLocked(key.parent)
	if parent == nil {
		r.mu.Unlock()
		return 0, nil
	}
	name := nameKey{parent: parent.key.inode, name: key.name}
	child := r.cachedNames[name]
	_, negative := r.cachedNegatives[name]
	if child != nil {
		r.dropCachedNameLocked(name)
	}
	if negative {
		r.dropCachedNegativeLocked(name)
	}
	reclaim := r.collectLocked(child)
	parentNode := parent.id
	r.mu.Unlock()
	r.mount.deferReclaim(reclaim)
	return parentNode, nil
}
