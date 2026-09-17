//go:build linux

package fusev3

import (
	"context"
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
