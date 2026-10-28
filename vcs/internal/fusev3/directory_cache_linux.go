//go:build linux

package fusev3

import (
	"bytes"
	"container/list"
	"context"
	"errors"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"google.golang.org/protobuf/proto"
)

const (
	directoryMetadataBytes   = 128 << 20
	directoryBackingCapacity = 8192
)

// All maps, payloads, references and LRU links belong to raw.mu. Payload
// eviction never removes a publication reservation or a live handle's rights.
// Session ownership is the raw owner; cold retirement advances session below
// before another incarnation can populate it, including across epoch recovery.
type directoryCache struct {
	metadataHits, metadataMisses, openHits, openMisses, withdrawals, withdrawalNanos uint64
	singleFlightWaits                                                                uint64
	pendingBytes, pendingNames                                                       int
	use                                                                              uint64
	session                                                                          uint64
	pages                                                                            map[directoryReadKey]*directoryPage
	fills                                                                            map[directoryReadKey]*directoryPageFill
	proofs                                                                           map[publicationIdentity]*directoryBacking
	opening                                                                          map[publicationIdentity]*replyPublication
	lru                                                                              *list.List
	bytes, names, overlap                                                            int
	nameRefs                                                                         map[publicationNamespace]int
	limit                                                                            int
	retired                                                                          []delegationClose
	hits, misses, capacityEvictions, invalidations                                   uint64
	missReasons                                                                      map[string]uint64
}

type directoryReadKey struct {
	session, incarnation, generation uint64
	directory                        publicationIdentity
	cookie                           string
}

type directoryRow struct {
	name, cookie             []byte
	identity                 publicationIdentity
	kind                     authoritypb.Attr_Kind
	inode, version, snapshot uint64
}

type directoryPage struct {
	metadataClock uint64
	key           directoryReadKey
	stamp         subscriptionStamp
	rows          []directoryRow
	eof           bool
	bytes         int
	lru           *list.Element
}

type directoryPageFill struct {
	revoked                    bool
	pendingBytes, pendingNames int
	key                        directoryReadKey
	owner                      *replyPublication
	done                       chan struct{}
	page                       *directoryPage
	reservation                *cacheInstallReservation
}

type directoryBacking struct {
	used     uint64
	stamp    subscriptionStamp
	identity publicationIdentity
	pending  delegationClose
	refs     int
	cached   bool
}

type directoryProofPublication struct {
	backing      *directoryBacking
	reservation  *cacheInstallReservation
	pendingBytes int
}

func newDirectoryCache() directoryCache {
	return directoryCache{session: 1, pages: make(map[directoryReadKey]*directoryPage), fills: make(map[directoryReadKey]*directoryPageFill),
		nameRefs: make(map[publicationNamespace]int), proofs: make(map[publicationIdentity]*directoryBacking), opening: make(map[publicationIdentity]*replyPublication),
		lru: list.New(), limit: directoryMetadataBytes, missReasons: make(map[string]uint64)}
}

func (r *rawFileSystem) rejectDirectoryReply(ctx context.Context) {
	p := replyPublicationFromContext(ctx)
	r.mu.Lock()
	if p != nil && r.replyPublications[p.requestUnique] == p {
		p.cacheRejected = true
	}
	r.mu.Unlock()
}

func (s *subscriptionRegistry) directoryGeneration(identity publicationIdentity) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return max(s.generationFloor, s.coordinates[publicationCoordinate{kind: publicationItemEnumeration, item: identity}].generation)
}

func (r *rawFileSystem) directoryKeyLocked(identity publicationIdentity, cookie []byte, stamp subscriptionStamp) directoryReadKey {
	return directoryReadKey{session: r.directories.session, incarnation: stamp.incarnation, directory: identity,
		generation: r.mount.subscription.directoryGeneration(identity), cookie: string(cookie)}
}

// These charges conservatively bound the fixed metadata payloads and their
// maximum raw-name allocation, including pending publication capacity. Page
// rows account their own slices and backing proofs their fixed ownership.
func (r *rawFileSystem) metadataBytesLocked() int {
	return 768*r.cachedNameTotalLocked() + 512*(len(r.cachedAttrs)+r.pendingAttrs) +
		8192*len(r.directoryPageHints) + 512*len(r.directories.proofs) + r.directories.bytes + r.directories.pendingBytes
}

func (r *rawFileSystem) evictDirectoryPageLocked(page *directoryPage, capacity bool) {
	if r.directories.pages[page.key] != page {
		return
	}
	delete(r.directories.pages, page.key)
	r.directories.lru.Remove(page.lru)
	r.directories.bytes -= page.bytes
	for _, row := range page.rows {
		ns := publicationNamespace{parent: page.key.directory, name: string(row.name)}
		r.directories.nameRefs[ns]--
		if r.directories.nameRefs[ns] == 0 {
			delete(r.directories.nameRefs, ns)
			r.directories.names--
			if r.cachedStableNames[ns] != nil {
				r.directories.overlap--
			}
		}
	}
	r.dropCompleteDirectoryLocked(page.key.directory)
	if capacity {
		r.directories.capacityEvictions++
	} else {
		r.directories.invalidations++
	}
}

func (r *rawFileSystem) trimDirectoryPagesLocked(extraBytes, extraNames int) bool {
	for r.metadataBytesLocked()+extraBytes > r.directories.limit || r.cachedNameTotalLocked()+extraNames > r.nameCapacity {
		oldest := r.directories.lru.Back()
		if oldest == nil {
			return false
		}
		r.evictDirectoryPageLocked(oldest.Value.(*directoryPage), true)
	}
	return true
}

func (r *rawFileSystem) dropDirectoryPagesLocked(identity publicationIdentity) {
	for key, fill := range r.directories.fills {
		if key.directory == identity {
			fill.revoked = true
			if fill.reservation != nil {
				fill.reservation.revoked = true
			}
		}
	}
	for key, page := range r.directories.pages {
		if key.directory == identity {
			r.evictDirectoryPageLocked(page, false)
		}
	}
}

func (r *rawFileSystem) retireDirectoryBackingLocked(backing *directoryBacking) {
	if backing == nil {
		return
	}
	if r.directories.proofs[backing.identity] == backing {
		delete(r.directories.proofs, backing.identity)
		if complete := r.completeDirectories[backing.identity]; complete != nil && complete.members != nil {
			r.dropCompleteDirectoryLocked(backing.identity)
		}
	}
	backing.cached = false
	if backing.refs == 0 && len(backing.pending.handle) != 0 {
		r.directories.retired = append(r.directories.retired, backing.pending)
		backing.pending = delegationClose{}
	}
}

// Queue outside raw.mu. The original session serial survives cold buffer
// replacement; epoch replacement cannot send an old token to a new session.
func (r *rawFileSystem) flushDirectoryRetirements(ctx context.Context) {
	r.mu.Lock()
	retired := r.directories.retired
	r.directories.retired = nil
	r.mu.Unlock()
	for _, pending := range retired {
		if err := r.mount.delegations.queueRetainedClose(ctx, pending); err != nil && r.mount.ctx.Err() == nil && !r.mount.revoked.Load() {
			r.mount.cleanupFailed("directory backing close", resourceCleanupError{cause: err}, func() {})
		}
	}
}

func (r *rawFileSystem) releaseDirectoryBacking(ctx context.Context, backing *directoryBacking) {
	r.mu.Lock()
	backing.refs--
	if !backing.cached {
		r.retireDirectoryBackingLocked(backing)
	}
	r.mu.Unlock()
	r.flushDirectoryRetirements(ctx)
}

func (r *rawFileSystem) coldDirectoryCacheLocked() {
	for _, page := range r.directories.pages {
		r.evictDirectoryPageLocked(page, false)
	}
	for _, backing := range r.directories.proofs {
		r.retireDirectoryBackingLocked(backing)
	}
	r.directories.session++
}

func (r *rawFileSystem) directoryMissLocked(reason string) {
	r.directories.misses++
	r.directories.missReasons[reason]++
}

func (r *rawFileSystem) directoryCoordinateAllowedLocked(p *replyPublication, coordinate publicationCoordinate, stamp subscriptionStamp) bool {
	for reservation := range r.cacheReservations[coordinate] {
		if reservation.publication != p {
			return false
		}
	}
	return !r.withdrawingCoordinates[coordinate] && r.sourcePublicationAllowedLocked(coordinate, nil) && r.mount.subscription.remainingAfterOwnershipCheck(coordinate, stamp, stamp.version) > 0
}

// Evict only the cache's idle reference. Live handles retain their description
// and access rights; counted cleanup retains the exact original session.
func (r *rawFileSystem) evictIdleDirectoryProofLocked() bool {
	var oldest *directoryBacking
	for _, backing := range r.directories.proofs {
		if backing.refs == 0 && (oldest == nil || backing.used < oldest.used) {
			oldest = backing
		}
	}
	if oldest == nil {
		return false
	}
	r.retireDirectoryBackingLocked(oldest)
	r.directories.capacityEvictions++
	return true
}

func (r *rawFileSystem) reclaimDirectoryCapacity(ctx context.Context) (bool, error) {
	r.mu.Lock()
	reclaimed := r.evictIdleDirectoryProofLocked()
	if !reclaimed {
		r.mu.Unlock()
		return false, nil
	}
	retired := r.directories.retired
	r.directories.retired = nil
	r.mu.Unlock()
	for start := 0; start < len(retired); start += 128 {
		batch := retired[start:min(start+128, len(retired))]
		owners := make([]*descriptorCleanup, 0, len(batch))
		for _, pending := range batch {
			owner, err := r.mount.delegations.reserveRetainedClose(pending)
			if err != nil {
				for _, prior := range owners {
					prior.dispatch(ctx)
				}
				r.mu.Lock()
				r.directories.retired = append(r.directories.retired, retired[start+len(owners):]...)
				r.mu.Unlock()
				return false, err
			}
			owners = append(owners, owner)
		}
		if err := r.mount.delegations.CloseHandles(ctx, batch); err != nil {
			for _, owner := range owners {
				owner.dispatch(ctx)
			}
			r.mu.Lock()
			r.directories.retired = append(r.directories.retired, retired[start+len(batch):]...)
			r.mu.Unlock()
			return false, err
		}
		for _, owner := range owners {
			owner.transfer()
		}
	}
	return true, nil
}

// A discarded PLUS response can mint cleanup debt without reaching intern.
// Reserve that capacity only on a real miss, outside the cursor/publication
// locks. A hit retains no new capability and needs no reclaim admission.
func (h *dirHandle) fetchDirectoryPage(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, syscall.Errno) {
	if request.GetReadDir().GetWantItems() {
		admit, cancel := context.WithTimeout(ctx, h.node.requestTimeout)
		err := h.node.mount.reclaim.admit(admit)
		cancel()
		if err != nil {
			return nil, contextErrno(err)
		}
	}
	return h.node.mutate(ctx, request)
}

// The fill's owner remains in the physical reply registry until settlement.
// Waiters share its result only after that edge; a withdrawn/unwritten fill
// wakes them to retry rather than manufacturing cache permission.
func (r *rawFileSystem) readDirectoryPage(ctx context.Context, h *dirHandle, request *authoritypb.Request, stamp subscriptionStamp) (*authoritypb.Response, subscriptionStamp, syscall.Errno) {
	p := replyPublicationFromContext(ctx)
	if p == nil || stamp.incarnation == 0 {
		response, errno := h.fetchDirectoryPage(ctx, request)
		return response, stamp, errno
	}
	identity := h.enumerationIdentity()
	coordinate := publicationCoordinate{kind: publicationItemEnumeration, item: identity}
	for {
		r.mu.Lock()
		key := r.directoryKeyLocked(identity, request.GetReadDir().GetCookie(), stamp)
		page := r.directories.pages[key]
		reason := "absent"
		if page != nil {
			if (!request.GetReadDir().GetWantItems() || page.metadataClock == p.metadataSample) && r.directoryCoordinateAllowedLocked(p, coordinate, page.stamp) {
				entries, valid := r.directoryEntriesLocked(page, request.GetReadDir().GetWantItems())
				if valid {
					p.stamp, p.servedVersion, p.retainedAnswer = page.stamp, page.stamp.version, true
					reservation, ok := r.reserveCacheSnapshotLocked(p, coordinate, page.stamp.version)
					if ok {
						p.directoryFills = append(p.directoryFills, &directoryPageFill{reservation: reservation})
						r.directories.lru.MoveToFront(page.lru)
						p.directoryHits++
						r.mu.Unlock()
						return &authoritypb.Response{VolumeVersion: page.stamp.version, Body: &authoritypb.Response_ReadDir{ReadDir: &authoritypb.ReadDirReply{Entries: entries, Eof: page.eof}}}, page.stamp, 0
					}
				} else {
					reason = "child-attributes"
				}
			} else {
				reason = "withdrawn"
				if request.GetReadDir().GetWantItems() && page.metadataClock != p.metadataSample {
					reason = "ownership"
				}
			}
		}
		if fill := r.directories.fills[key]; fill != nil && fill.owner != p {
			r.directories.singleFlightWaits++
			done := fill.done
			r.mu.Unlock()
			select {
			case <-done:
				continue
			case <-ctx.Done():
				return nil, stamp, contextErrno(ctx.Err())
			}
		}
		r.directoryMissLocked(reason)
		fill := &directoryPageFill{key: key, owner: p, done: make(chan struct{})}
		r.directories.fills[key] = fill
		p.directoryFills = append(p.directoryFills, fill)
		r.mu.Unlock()
		if request.GetReadDir().GetWantItems() {
			request.GetReadDir().HeldIdentities = r.heldDirectoryPageIdentities(identity, request.GetReadDir().GetCookie())
		}
		response, errno := h.fetchDirectoryPage(ctx, request)
		if errno != 0 {
			return response, stamp, errno
		}
		page = directoryPageFromReply(key, stamp.withVersion(response.GetVolumeVersion()), response.GetReadDir())
		if page != nil {
			page.metadataClock = p.metadataSample
		}
		r.mu.Lock()
		if page != nil && !fill.revoked && key == r.directoryKeyLocked(identity, request.GetReadDir().GetCookie(), stamp) && r.trimDirectoryPagesLocked(page.bytes+768*len(page.rows), len(page.rows)) {
			fill.pendingBytes, fill.pendingNames = page.bytes, len(page.rows)
			r.directories.pendingBytes += fill.pendingBytes
			r.directories.pendingNames += fill.pendingNames
			fill.page = page
			fill.reservation, _ = r.reserveCacheSnapshotLocked(p, coordinate, page.stamp.version)
		}
		r.mu.Unlock()
		return response, stamp, 0
	}
}

func directoryPageFromReply(key directoryReadKey, stamp subscriptionStamp, reply *authoritypb.ReadDirReply) *directoryPage {
	if reply == nil || len(reply.GetEntries()) == 0 && !reply.GetEof() {
		return nil
	}
	page := &directoryPage{key: key, stamp: stamp, eof: reply.GetEof(), bytes: 256}
	cookies := make(map[uint64]struct{}, len(reply.GetEntries()))
	for _, entry := range reply.GetEntries() {
		identity, ok := publicationIdentityFromBytes(entry.GetStableIdentity())
		cookie, validCookie := decodeCookie(entry.GetNextCookie())
		_, duplicate := cookies[cookie]
		if !ok || entry.GetAttr() == nil || !validSourceNamespaceName(string(entry.GetName())) || !validCookie || cookie&graftDirOffsetBase != 0 || duplicate || string(entry.GetNextCookie()) == key.cookie || entry.GetObjectVersion() == 0 || entry.GetObjectVersion() > entry.GetSnapshotSequence() || entry.GetSnapshotSequence() != stamp.version {
			return nil
		}
		if item := entry.GetItem(); item != nil && (!validItem(item) || !bytes.Equal(item.GetStableIdentity(), entry.GetStableIdentity()) || !proto.Equal(item.GetAttr(), entry.GetAttr()) || item.GetObjectVersion() != entry.GetObjectVersion() || item.GetSnapshotSequence() != entry.GetSnapshotSequence()) {
			return nil
		}
		cookies[cookie] = struct{}{}
		row := directoryRow{name: cloneBytes(entry.GetName()), cookie: cloneBytes(entry.GetNextCookie()), identity: identity,
			kind: entry.GetAttr().GetKind(), inode: entry.GetAttr().GetInode(), version: entry.GetObjectVersion(), snapshot: entry.GetSnapshotSequence()}
		page.rows = append(page.rows, row)
		page.bytes += 320 + 2*len(row.name) + len(row.cookie)
	}
	return page
}

// Pages hold names/types/cookies and attribute coordinates, never a capability
// or an attribute payload. PLUS requires the original, still-current fact for
// every row; otherwise the existing authority page refreshes those facts.
func (r *rawFileSystem) directoryEntriesLocked(page *directoryPage, plus bool) ([]*authoritypb.Dirent, bool) {
	entries := make([]*authoritypb.Dirent, 0, len(page.rows))
	for _, row := range page.rows {
		attr := &authoritypb.Attr{Kind: row.kind, Inode: row.inode}
		if plus {
			payload := r.cachedAttrPayloads[row.identity]
			coordinate := publicationCoordinate{kind: publicationItemAttributes, item: row.identity}
			if payload.attr == nil || payload.objectVersion != row.version || payload.snapshot != row.snapshot || !r.cachedCoordinateAllowedLocked(coordinate, payload.stamp) {
				return nil, false
			}
			attr = proto.Clone(payload.attr).(*authoritypb.Attr)
		}
		entries = append(entries, &authoritypb.Dirent{Name: cloneBytes(row.name), NextCookie: cloneBytes(row.cookie), StableIdentity: cloneBytes(row.identity[:]),
			Attr: attr, ObjectVersion: row.version, SnapshotSequence: row.snapshot})
	}
	return entries, true
}

func (r *rawFileSystem) settleDirectoryCacheLocked(p *replyPublication, successful bool) {
	successful = successful && !p.cacheRejected
	if !successful {
		p.directoryOrphan = p.directoryHandle
	}
	p.directoryHandle = 0
	if successful {
		r.directories.hits += p.directoryHits
		if p.directoryOpenHit {
			r.directories.openHits++
		}
		if p.metadataHit {
			r.directories.metadataHits++
		}
	} else {
		r.directories.missReasons["final-publication"] += p.directoryHits
	}
	if candidate := p.directoryProof; candidate != nil {
		backing := candidate.backing
		r.directories.pendingBytes -= candidate.pendingBytes
		candidate.pendingBytes = 0
		coordinate := publicationCoordinate{kind: publicationItemAttributes, item: backing.identity}
		valid := successful && !r.replyTerminalizing && !r.replyTerminal && !r.mount.revoked.Load() && candidate.reservation != nil && !candidate.reservation.revoked && !r.withdrawingCoordinates[coordinate] &&
			r.sourcePublicationAllowedLocked(coordinate, p.source) && r.publicationRemaining(p, coordinate) > 0
		if valid && len(r.directories.proofs) < min(r.nameCapacity, directoryBackingCapacity) && r.trimDirectoryPagesLocked(512, 0) {
			if old := r.directories.proofs[backing.identity]; old != nil {
				r.retireDirectoryBackingLocked(old)
			}
			backing.cached = true
			r.directories.use++
			backing.used = r.directories.use
			r.directories.proofs[backing.identity] = backing
		}
		backing.refs--
		if !backing.cached {
			r.retireDirectoryBackingLocked(backing)
		}
		r.removeCacheReservationLocked(candidate.reservation)
		p.directoryProof = nil
		if r.directories.opening[backing.identity] == p {
			delete(r.directories.opening, backing.identity)
		}
	}
	for _, fill := range p.directoryFills {
		r.directories.pendingBytes -= fill.pendingBytes
		r.directories.pendingNames -= fill.pendingNames
		fill.pendingBytes, fill.pendingNames = 0, 0
		page := fill.page
		if page != nil && successful && !r.replyTerminalizing && !r.replyTerminal && !r.mount.revoked.Load() && fill.reservation != nil && !fill.reservation.revoked &&
			page.key == r.directoryKeyLocked(page.key.directory, []byte(page.key.cookie), page.stamp) &&
			r.publicationRemaining(p, fill.reservation.coordinate) > 0 && r.sourcePublicationAllowedLocked(fill.reservation.coordinate, p.source) {
			if old := r.directories.pages[page.key]; old != nil {
				r.evictDirectoryPageLocked(old, true)
			}
			extra := 0
			for _, row := range page.rows {
				ns := publicationNamespace{parent: page.key.directory, name: string(row.name)}
				if r.directories.nameRefs[ns] == 0 && r.cachedStableNames[ns] == nil {
					extra++
				}
			}
			if r.trimDirectoryPagesLocked(page.bytes+768*extra, extra) {
				page.lru = r.directories.lru.PushFront(page)
				r.directories.pages[page.key] = page
				r.directories.bytes += page.bytes
				for _, row := range page.rows {
					ns := publicationNamespace{parent: page.key.directory, name: string(row.name)}
					if r.directories.nameRefs[ns] == 0 {
						r.directories.names++
						if r.cachedStableNames[ns] != nil {
							r.directories.overlap++
						}
					}
					r.directories.nameRefs[ns]++
				}
				r.completeDirectoryWalkLocked(page.key)
			}
		}
		r.removeCacheReservationLocked(fill.reservation)
		if fill.done != nil {
			if r.directories.fills[fill.key] == fill {
				delete(r.directories.fills, fill.key)
			}
			close(fill.done)
		}
	}
	p.directoryFills = nil
}

func (r *rawFileSystem) completeDirectoryWalkLocked(key directoryReadKey) {
	backing := r.directories.proofs[key.directory]
	if backing == nil || !r.cachedCoordinateAllowedLocked(publicationCoordinate{kind: publicationItemAttributes, item: key.directory}, backing.stamp) {
		return
	}
	key.cookie = ""
	members := make(map[string]struct{})
	stamp := subscriptionStamp{}
	for pages := 0; pages <= len(r.directories.pages); pages++ {
		page := r.directories.pages[key]
		if page == nil {
			return
		}
		stamp = page.stamp
		for _, row := range page.rows {
			members[string(row.name)] = struct{}{}
		}
		if page.eof {
			if r.cachedNameTotalLocked() < r.nameCapacity && r.metadataBytesLocked()+768 <= r.directories.limit {
				r.completeDirectories[key.directory] = &directoryCompleteness{stamp: stamp, permission: backing.stamp, valid: true, members: members}
			}
			return
		}
		if len(page.rows) == 0 {
			return
		}
		key.cookie = string(page.rows[len(page.rows)-1].cookie)
	}
}

func (n *node) openReusableDirectory(ctx context.Context) (*dirHandle, syscall.Errno) {
	r := n.mount.raw
	p := replyPublicationFromContext(ctx)
	stamp := n.mount.subscription.stamp()
	identity, ok := publicationIdentityFromItem(n.item)
	if !ok {
		return nil, syscall.EIO
	}
	coordinate := publicationCoordinate{kind: publicationItemAttributes, item: identity}
	if r != nil && p != nil && stamp.incarnation != 0 {
		for {
			r.mu.Lock()
			if backing := r.directories.proofs[identity]; backing != nil && r.cachedCoordinateAllowedLocked(coordinate, backing.stamp) {
				p.stamp, p.servedVersion, p.retainedAnswer = backing.stamp, backing.stamp.version, true
				if reservation, admitted := r.reserveCacheSnapshotLocked(p, coordinate, backing.stamp.version); admitted {
					p.directoryFills = append(p.directoryFills, &directoryPageFill{reservation: reservation})
					backing.refs++
					p.directoryOpenHit = true
					// A reusable OPEN grants retained application rights at
					// this cut. Like a metadata cache hit, it is finalized
					// here so permission withdrawal joins its physical reply.
					reservation.state = cacheReservationFinalized
					p.originalFinalized = true
					r.directories.use++
					backing.used = r.directories.use
					r.mu.Unlock()
					return n.localDirectoryHandle(backing), 0
				}
			}
			if prior := r.directories.opening[identity]; prior != nil && prior != p {
				done := prior.originalDoneLocked()
				r.mu.Unlock()
				select {
				case <-done:
					continue
				case <-ctx.Done():
					return nil, contextErrno(ctx.Err())
				}
			}
			r.directories.opening[identity] = p
			r.mu.Unlock()
			break
		}
		defer func() {
			r.mu.Lock()
			if p.directoryProof == nil && r.directories.opening[identity] == p {
				delete(r.directories.opening, identity)
			}
			r.mu.Unlock()
		}()
	}
	if err := n.mount.delegations.waitCloseCapacity(ctx); err != nil {
		return nil, bufferErrno(err)
	}
	wantProof := r != nil && p != nil && stamp.incarnation != 0
	if r != nil {
		r.mu.Lock()
		r.directories.openMisses++
		r.mu.Unlock()
	}
	if wantProof {
		r.mu.Lock()
		if len(r.directories.proofs) >= min(r.nameCapacity, directoryBackingCapacity) {
			r.evictIdleDirectoryProofLocked()
		}
		r.mu.Unlock()
		r.flushDirectoryRetirements(ctx)
	}
	requestedIncarnation := uint64(0)
	if wantProof {
		requestedIncarnation = stamp.incarnation
	}
	open := func() (*authoritypb.Response, syscall.Errno) {
		return n.mutate(ctx, &authoritypb.Request{Body: &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{Item: cloneBytes(n.item.GetToken()), Flags: &authoritypb.OpenFlags{Read: true}, ReusableDirectoryReadIncarnation: requestedIncarnation}}})
	}
	response, errno := open()
	if wantProof && (errno == syscall.ENFILE || errno == syscall.EMFILE) {
		reclaimed, err := r.reclaimDirectoryCapacity(ctx)
		if err != nil {
			return nil, bufferErrno(err)
		}
		if reclaimed {
			response, errno = open()
		}
	}
	if errno != 0 {
		return nil, errno
	}
	owner, err := n.mount.ownDescriptor(n.item.GetStableIdentity(), response.GetOpen().GetHandle())
	if err != nil {
		return nil, syscall.EIO
	}
	defer owner.dispatch(ctx)
	backing := &directoryBacking{identity: identity, stamp: stamp.withVersion(response.GetVolumeVersion()), pending: owner.pending, refs: 1}
	if wantProof {
		proof := response.GetOpen().GetDirectoryReadProof()
		if proof == nil || !bytes.Equal(proof.GetStableIdentity(), identity[:]) || proof.GetIncarnation() != stamp.incarnation ||
			proof.GetSnapshotSequence() != response.GetVolumeVersion() || proof.GetObjectVersion() == 0 || proof.GetObjectVersion() > proof.GetSnapshotSequence() {
			n.mount.revoke(errors.New("fusev3: reusable directory OPEN carried an invalid identity-bound proof"))
			return nil, syscall.ENOTCONN
		}
		if proof.GetReusable() {
			r.mu.Lock()
			if p.settlementClaimed || r.replyPublications[p.requestUnique] != p || r.replyTerminal || r.replyTerminalizing {
				r.mu.Unlock()
				return nil, syscall.ENOTCONN
			}
			candidate := &directoryProofPublication{backing: backing}
			if r.trimDirectoryPagesLocked(512, 0) {
				candidate.reservation, _ = r.reserveCacheSnapshotLocked(p, coordinate, proof.GetSnapshotSequence())
				if candidate.reservation != nil {
					candidate.pendingBytes = 512
					r.directories.pendingBytes += candidate.pendingBytes
				}
			}
			backing.refs++ // Publication owns a reference independently of the new handle.
			p.directoryProof = candidate
			r.mu.Unlock()
		}
	}
	owner.transfer()
	return n.localDirectoryHandle(backing), 0
}

func (n *node) localDirectoryHandle(backing *directoryBacking) *dirHandle {
	return &dirHandle{node: n, token: cloneBytes(backing.pending.handle), backing: backing,
		rootBarrier: bytes.Equal(n.item.GetStableIdentity(), n.mount.rpc.Root().GetStableIdentity()), barrierLoss: n.mount.delegations.LossSequence()}
}

// A refused or unwritten OPEN cannot hand its local reference to an application.
// Remove that exact handle outside raw.mu; cursor retirement and counted CLOSE
// may need their own locks. Successful physical delivery transfers the reference.
func (r *rawFileSystem) finishDirectoryOpen(p *replyPublication) {
	if p.directoryOrphan != 0 {
		r.discardDirectoryOpen(p.directoryOrphan)
		p.directoryOrphan = 0
	}
}

func (r *rawFileSystem) discardDirectoryOpen(id uint64) {
	handle, ok := r.takeHandle(id, handleAuthorityDir)
	if !ok {
		return
	}
	defer r.unpin(handle.inode)
	if outcome := handle.dir.closeForCleanup(context.Background()); outcome.failed() {
		r.mount.cleanupFailed("unpublished directory close", outcome, func() { handle.dir.stale.Store(true) })
	}
}
