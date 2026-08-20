package archive

import "math/bits"

// XXH64 is implemented here rather than taken as a dependency. The format needs
// exactly one thing from it — the low 32 bits of the digest of a decompressed
// frame, which is also the zstd content checksum a frame carries — and the
// module deliberately holds a very small dependency set. The compression
// library vendors its own copy internally and exports none of it, so importing
// a hash module would add a whole second dependency for a hundred lines of
// fully specified arithmetic that is pinned by public test vectors.
const (
	xxhPrime1 uint64 = 11400714785074694791
	xxhPrime2 uint64 = 14029467366897019727
	xxhPrime3 uint64 = 1609587929392839161
	xxhPrime4 uint64 = 9650029242287828579
	xxhPrime5 uint64 = 2870177450012600261
)

// The initial accumulators are computed through wrap, not written as constant
// expressions. XXH64 defines them with wrapping arithmetic, and Go evaluates a
// constant expression in arbitrary precision and then refuses the result if it
// does not fit — so `xxhPrime1 + xxhPrime2` is a compile error rather than the
// value the algorithm calls for. Going through a function makes the addition a
// runtime one, where uint64 wraps as the specification intends.
var (
	xxhSeedV1 = wrapAdd64(xxhPrime1, xxhPrime2)
	xxhSeedV2 = xxhPrime2
	xxhSeedV4 = wrapNeg64(xxhPrime1)
)

func wrapAdd64(a, b uint64) uint64 { return a + b }
func wrapNeg64(a uint64) uint64    { return ^a + 1 }

// xxh64 is the streaming XXH64 state with seed zero. Frames are hashed as they
// are assembled, so no frame is ever held twice in memory to checksum it.
type xxh64 struct {
	v1, v2, v3, v4 uint64
	total          uint64
	buffer         [32]byte
	buffered       int
}

func newXXH64() *xxh64 {
	return &xxh64{v1: xxhSeedV1, v2: xxhSeedV2, v3: 0, v4: xxhSeedV4}
}

func (h *xxh64) Write(p []byte) (int, error) {
	written := len(p)
	h.total += uint64(written)
	if h.buffered > 0 {
		n := copy(h.buffer[h.buffered:], p)
		h.buffered += n
		p = p[n:]
		if h.buffered < 32 {
			return written, nil
		}
		h.consume(h.buffer[:])
		h.buffered = 0
	}
	for len(p) >= 32 {
		h.consume(p[:32])
		p = p[32:]
	}
	if len(p) > 0 {
		h.buffered = copy(h.buffer[:], p)
	}
	return written, nil
}

func (h *xxh64) consume(block []byte) {
	h.v1 = xxhRound(h.v1, leUint64(block[0:8]))
	h.v2 = xxhRound(h.v2, leUint64(block[8:16]))
	h.v3 = xxhRound(h.v3, leUint64(block[16:24]))
	h.v4 = xxhRound(h.v4, leUint64(block[24:32]))
}

func (h *xxh64) Sum64() uint64 {
	var acc uint64
	if h.total >= 32 {
		acc = bits.RotateLeft64(h.v1, 1) + bits.RotateLeft64(h.v2, 7) +
			bits.RotateLeft64(h.v3, 12) + bits.RotateLeft64(h.v4, 18)
		acc = xxhMerge(acc, h.v1)
		acc = xxhMerge(acc, h.v2)
		acc = xxhMerge(acc, h.v3)
		acc = xxhMerge(acc, h.v4)
	} else {
		acc = h.v3 + xxhPrime5
	}
	acc += h.total

	tail := h.buffer[:h.buffered]
	for len(tail) >= 8 {
		acc ^= xxhRound(0, leUint64(tail[:8]))
		acc = bits.RotateLeft64(acc, 27)*xxhPrime1 + xxhPrime4
		tail = tail[8:]
	}
	if len(tail) >= 4 {
		acc ^= uint64(leUint32(tail[:4])) * xxhPrime1
		acc = bits.RotateLeft64(acc, 23)*xxhPrime2 + xxhPrime3
		tail = tail[4:]
	}
	for _, b := range tail {
		acc ^= uint64(b) * xxhPrime5
		acc = bits.RotateLeft64(acc, 11) * xxhPrime1
	}
	acc ^= acc >> 33
	acc *= xxhPrime2
	acc ^= acc >> 29
	acc *= xxhPrime3
	acc ^= acc >> 32
	return acc
}

// Lo32 is the value the frame table records: the low 32 bits of the digest,
// identical to the four-byte content checksum a zstd frame carries when the
// checksum flag is set.
func (h *xxh64) Lo32() uint32 { return uint32(h.Sum64()) }

func xxhRound(acc, input uint64) uint64 {
	acc += input * xxhPrime2
	acc = bits.RotateLeft64(acc, 31)
	return acc * xxhPrime1
}

func xxhMerge(acc, value uint64) uint64 {
	return (acc^xxhRound(0, value))*xxhPrime1 + xxhPrime4
}

// XXH64Sum returns the full XXH64 digest of one buffer with seed zero.
func XXH64Sum(data []byte) uint64 {
	hash := newXXH64()
	_, _ = hash.Write(data)
	return hash.Sum64()
}

func leUint32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func leUint64(b []byte) uint64 {
	return uint64(b[0]) | uint64(b[1])<<8 | uint64(b[2])<<16 | uint64(b[3])<<24 |
		uint64(b[4])<<32 | uint64(b[5])<<40 | uint64(b[6])<<48 | uint64(b[7])<<56
}
