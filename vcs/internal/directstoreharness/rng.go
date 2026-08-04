package directstoreharness

// RNG is SplitMix64 with rejection sampling for bounded values. Its algorithm
// is part of the trace version: unlike math/rand, it cannot change underneath
// a saved seed when the Go toolchain changes.
type RNG struct {
	state uint64
}

func NewRNG(seed uint64) *RNG { return &RNG{state: seed} }

func (r *RNG) Uint64() uint64 {
	r.state += 0x9e3779b97f4a7c15
	z := r.state
	z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
	z = (z ^ (z >> 27)) * 0x94d049bb133111eb
	return z ^ (z >> 31)
}

func (r *RNG) Bounded(n uint64) uint64 {
	if n == 0 {
		panic("direct-store harness: zero RNG bound")
	}
	threshold := -n % n
	for {
		x := r.Uint64()
		if x >= threshold {
			return x % n
		}
	}
}
