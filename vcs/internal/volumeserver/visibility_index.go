package volumeserver

import (
	"encoding/binary"
	"math"
)

// The resolved index answers one question for one strict mount: could this
// mount still be caching this name or this inode? Fan-out uses it to skip
// participants that provably cannot hold the affected state, which is what
// makes a metadata-heavy workload usable while a strict mount is attached.
//
// The question is asked in the unsafe direction, so a false negative is a
// correctness failure: saying "no" about a mount that does hold the name would
// let that mount keep serving it after the mutation returned, which is the
// exact failure the barrier exists to prevent. A false positive costs one
// no-op acknowledgment.
//
// Shape: one Bloom filter that is only ever added to. A Bloom filter has no
// false negatives by construction, and never clearing it means that property
// holds unconditionally - it depends on nothing the authority cannot see.
//
// Why not the obvious bounded variants:
//
//   - An exact hash set of the resolved coordinates also has no false
//     negatives, but its memory is the total size of every name the mount ever
//     resolved, which is unbounded for exactly the workload this optimisation
//     exists to serve.
//
//   - A rotating pair of filters, sized so the pair always retains the most
//     recent `capacity` distinct resolutions, looks bounded and safe and is
//     not. The argument for it is that a frontend cache bounded at `capacity`
//     entries must have evicted anything older than the last `capacity`
//     distinct resolutions. That argument silently assumes the frontend evicts
//     in resolution order. A real kernel cache is recency ordered: an entry
//     that keeps being hit is never re-resolved - a hit is precisely the
//     lookup that does not reach the authority - so it can stay cached
//     indefinitely while the index rotates it out from under itself. A hot
//     working set is the common case, not a corner one, and it is what
//     TestResolvedIndexCoversEveryEntryABoundedCacheCanHold reproduces.
//
// Never clearing removes the assumption instead of refining it. What it costs
// is precision rather than correctness: as a mount resolves more distinct
// coordinates than it declared its cache can hold, the filter fills and starts
// answering "yes" more often, and fan-out for that mount degrades toward the
// unscoped behaviour it had before. Memory does not move, and no mount is ever
// wrongly skipped. A mount's own declared capacity is what decides where that
// curve sits, and the authority never has to trust the number for anything
// except how much memory to spend.
type resolvedIndex struct {
	// words is the length of the filter; bits is words*64.
	words uint64
	bits  uint64
	// hashes is the number of bit positions one coordinate sets.
	hashes uint32
	seed   uint64

	filter []uint64
	// distinct counts coordinates that were not already present. It is
	// observability only - nothing about correctness reads it.
	distinct uint64
}

// resolvedIndexFalsePositive is the design point at the declared capacity. It
// only trades wasted acknowledgments against memory; correctness does not
// depend on it, and exceeding the capacity only moves along the same curve.
const resolvedIndexFalsePositive = 0.01

// maxResolvedIndexWords caps one filter at 8 MiB so a single admitted capacity
// can never be turned into an unbounded allocation by arithmetic.
const maxResolvedIndexWords = 1 << 20

func newResolvedIndex(capacity uint64, seed uint64) *resolvedIndex {
	if capacity == 0 {
		capacity = 1
	}
	// m = -n*ln(p) / (ln2)^2, k = (m/n)*ln2, both rounded up.
	bitsPerKey := -math.Log(resolvedIndexFalsePositive) / (math.Ln2 * math.Ln2)
	words := uint64(math.Ceil(float64(capacity)*bitsPerKey/64)) + 1
	if words > maxResolvedIndexWords {
		words = maxResolvedIndexWords
	}
	hashes := uint32(math.Ceil(float64(words*64) / float64(capacity) * math.Ln2))
	if hashes == 0 {
		hashes = 1
	}
	if hashes > 32 {
		hashes = 32
	}
	return &resolvedIndex{
		words: words, bits: words * 64, hashes: hashes, seed: seed,
		filter: make([]uint64, words),
	}
}

// nameKey and inodeKey are domain separated so a 16-byte inode identity can
// never be found under a namespace binding that happens to hash the same way.
func nameKey(parent [16]byte, name []byte) []byte {
	key := make([]byte, 0, 1+len(parent)+len(name))
	key = append(key, 'n')
	key = append(key, parent[:]...)
	return append(key, name...)
}

func inodeKey(identity [16]byte) []byte {
	key := make([]byte, 0, 1+len(identity))
	key = append(key, 'i')
	return append(key, identity[:]...)
}

func (r *resolvedIndex) add(key []byte) {
	h1, h2 := r.hash(key)
	present := true
	for i := uint32(0); i < r.hashes; i++ {
		word, mask := r.position(h1, h2, i)
		if r.filter[word]&mask == 0 {
			present = false
			r.filter[word] |= mask
		}
	}
	if !present {
		r.distinct++
	}
}

func (r *resolvedIndex) contains(key []byte) bool {
	h1, h2 := r.hash(key)
	for i := uint32(0); i < r.hashes; i++ {
		word, mask := r.position(h1, h2, i)
		if r.filter[word]&mask == 0 {
			return false
		}
	}
	return true
}

func (r *resolvedIndex) position(h1, h2 uint64, i uint32) (uint64, uint64) {
	// Kirsch-Mitzenmacher: k independent-enough positions from two hashes. h2
	// is forced odd so the stride never degenerates to zero and cannot share
	// the factor two with the 64-multiple bit count; the bit count is not a
	// power of two, so full coprimality is not guaranteed — that costs at most
	// some position overlap (precision), never a false negative.
	bit := (h1 + uint64(i)*h2) % r.bits
	return bit / 64, uint64(1) << (bit % 64)
}

// hash is FNV-1a over the seeded key with two different offset bases. The index
// is a local memory optimisation with no adversarial input path - a peer that
// wanted to be sent extra acknowledgments could simply resolve more names - so
// a non-cryptographic hash is the right cost. The per-session seed keeps two
// sessions from sharing a collision pattern.
func (r *resolvedIndex) hash(key []byte) (uint64, uint64) {
	const (
		offset1 = 14695981039346656037
		offset2 = 1099511628211
		prime   = 1099511628211
	)
	var seed [8]byte
	binary.LittleEndian.PutUint64(seed[:], r.seed)
	h1, h2 := uint64(offset1), uint64(offset2)
	for _, b := range seed {
		h1 = (h1 ^ uint64(b)) * prime
		h2 = (h2 ^ uint64(b)) * prime
	}
	for _, b := range key {
		h1 = (h1 ^ uint64(b)) * prime
		h2 = (h2 ^ uint64(b)) * prime
	}
	h2 = h2*2 + 1
	return h1, h2
}
