//go:build linux

package fusev3

import (
	"bytes"
	"context"
	"errors"
	"sort"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

// A complete directory has no members outside cachedNames. MKDIR establishes
// the empty set; only physically committed local additions preserve it. Losing
// any member or observing a peer namespace change invalidates the whole proof.
// Each proof consumes one unit of the declared name-cache capacity.
type directoryCompleteness struct {
	stamp subscriptionStamp
	valid bool
}

type completeDirectoryPublication struct {
	identity    publicationIdentity
	prior       *directoryCompleteness
	member      nameKey
	child       publicationIdentity
	reservation *cacheInstallReservation
}

func (r *rawFileSystem) dropCompleteDirectoryLocked(identity publicationIdentity) {
	if proof := r.completeDirectories[identity]; proof != nil {
		proof.valid = false
		delete(r.completeDirectories, identity)
	}
}

func (r *rawFileSystem) dropDirectoryPageHintsLocked(identity publicationIdentity) {
	for key := range r.directoryPageHints {
		if key.directory == identity {
			delete(r.directoryPageHints, key)
		}
	}
}

func (r *rawFileSystem) heldDirectoryPageIdentities(directory publicationIdentity, cookie []byte) [][]byte {
	r.mu.RLock()
	hint, ok := r.directoryPageHints[directoryPageKey{directory: directory, cookie: string(cookie)}]
	if !ok || r.mount.subscription.remaining(
		publicationCoordinate{kind: publicationItemEnumeration, item: directory}, hint.stamp, hint.stamp.version, time.Now(),
	) <= 0 {
		r.mu.RUnlock()
		return nil
	}
	held := make([][]byte, 0, len(hint.identities))
	seen := make(map[publicationIdentity]struct{}, len(hint.identities))
	for _, identity := range hint.identities {
		record := r.nodesByIdentity[identity]
		if record == nil || record.reclaimed || record.stale.Load() || record.node == nil || record.node.stale.Load() {
			continue
		}
		if _, duplicate := seen[identity]; duplicate {
			continue
		}
		seen[identity] = struct{}{}
		held = append(held, append([]byte(nil), identity[:]...))
	}
	r.mu.RUnlock()
	sort.Slice(held, func(i, j int) bool { return bytes.Compare(held[i], held[j]) < 0 })
	return held
}

func (r *rawFileSystem) stageDirectoryPageHint(ctx context.Context, directory publicationIdentity, cookie []byte, stamp subscriptionStamp, entries []*authoritypb.Dirent) error {
	publication := replyPublicationFromContext(ctx)
	if publication == nil {
		return errors.New("fusev3: READDIRPLUS page hint escaped its reply lifecycle")
	}
	identities := make([]publicationIdentity, 0, len(entries))
	for _, entry := range entries {
		raw := entry.GetStableIdentity()
		if len(raw) == 0 {
			continue
		}
		if len(raw) != len(publicationIdentity{}) || (entry.GetItem() != nil && !bytes.Equal(raw, entry.GetItem().GetStableIdentity())) {
			return errors.New("fusev3: READDIRPLUS page carried an inconsistent stable identity")
		}
		var identity publicationIdentity
		copy(identity[:], raw)
		identities = append(identities, identity)
	}
	if len(identities) == 0 {
		return nil
	}
	key := directoryPageKey{directory: directory, cookie: string(cookie)}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.replyPublications[publication.requestUnique] != publication || publication.dirPlusLookups == nil || publication.dirPlusLookups.settled {
		return errors.New("fusev3: READDIRPLUS page hint lost its reply transaction")
	}
	if publication.dirPlusLookups.pageHints == nil {
		publication.dirPlusLookups.pageHints = make(map[directoryPageKey]directoryPageHint)
	}
	publication.dirPlusLookups.pageHints[key] = directoryPageHint{stamp: stamp, identities: identities}
	return nil
}

// The source gate owns the parent enumeration until the physical reply. The
// new child's proof remains only a candidate until that same edge; generation
// checks reject a peer change which overtakes its MKDIR response.
func (r *rawFileSystem) stageCompleteDirectoryAddition(ctx context.Context, parent, child *inodeRecord, name string, emptyChild bool) {
	p := replyPublicationFromContext(ctx)
	if p == nil || p.source == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	coordinate := publicationCoordinate{kind: publicationItemEnumeration, item: parent.identity}
	if proof := r.completeDirectories[parent.identity]; proof != nil && proof.valid && r.mount.subscription.remaining(coordinate, proof.stamp, p.servedVersion, time.Now()) > 0 && !r.repairingCoordinates[coordinate] {
		if reservation, ok := r.reserveCacheCandidateLocked(p, coordinate); ok {
			p.completeDirectories[p.completeDirectoryCount] = completeDirectoryPublication{identity: parent.identity, prior: proof, member: nameKey{parent: parent.key.inode, name: name}, child: child.identity, reservation: reservation}
			p.completeDirectoryCount++
			r.admitSourcePublicationLocked(coordinate)
			p.source.completeParent, p.source.completeProof = parent.identity, proof
		}
	}
	if emptyChild && child.key.kind == authoritypb.Attr_DIRECTORY {
		coordinate := publicationCoordinate{kind: publicationItemEnumeration, item: child.identity}
		if reservation, ok := r.reserveCacheCandidateLocked(p, coordinate); ok {
			p.completeDirectories[p.completeDirectoryCount] = completeDirectoryPublication{identity: child.identity, reservation: reservation}
			p.completeDirectoryCount++
			r.admitSourcePublicationLocked(coordinate)
		}
	}
}

func (r *rawFileSystem) settleCompleteDirectoriesLocked(p *replyPublication, successful bool) {
	for _, candidate := range p.completeDirectories[:p.completeDirectoryCount] {
		coordinate := publicationCoordinate{kind: publicationItemEnumeration, item: candidate.identity}
		valid := successful && candidate.reservation != nil && !candidate.reservation.revoked && !r.repairingCoordinates[coordinate] && r.sourcePublicationAllowedLocked(coordinate, p.source) && r.publicationRemaining(p, coordinate) > 0
		// The source-owned addition advances the old set to this exact reply
		// version; its prior generation still excludes every intervening peer cut.
		if candidate.prior != nil {
			member := r.cachedNames[candidate.member]
			valid = valid && candidate.prior.valid && r.completeDirectories[candidate.identity] == candidate.prior && member != nil && member.identity == candidate.child && r.mount.subscription.remaining(coordinate, candidate.prior.stamp, p.servedVersion, time.Now()) > 0
		} else {
			valid = valid && r.cachedNameTotalLocked() < r.nameCapacity
		}
		r.settleSourcePublicationLocked(coordinate)
		if !valid {
			r.dropCompleteDirectoryLocked(candidate.identity)
			continue
		}
		proof := candidate.prior
		if proof == nil {
			proof = &directoryCompleteness{valid: true}
			r.completeDirectories[candidate.identity] = proof
		}
		proof.stamp = p.subscriptionCacheStamp()
	}
}
