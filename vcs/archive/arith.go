package archive

import "fmt"

// Every offset, length, and total in this package is computed through these
// helpers rather than with bare operators. A manifest arrives from an object
// store and its numbers are attacker-influenced until they are validated; an
// addition that wraps is how a bounds check gets passed by a value that is not
// in bounds. Wrapping is treated as a rejection, never as a value.

func checkedAdd(a, b uint64) (uint64, bool) {
	sum := a + b
	if sum < a {
		return 0, false
	}
	return sum, true
}

func checkedMul(a, b uint64) (uint64, bool) {
	if a == 0 || b == 0 {
		return 0, true
	}
	product := a * b
	if product/a != b {
		return 0, false
	}
	return product, true
}

// checkedRange reports the exclusive end of [offset, offset+length) and whether
// it fits inside limit without wrapping.
func checkedRange(offset, length, limit uint64) (uint64, bool) {
	end, ok := checkedAdd(offset, length)
	if !ok || end > limit {
		return 0, false
	}
	return end, true
}

func errOverflow(what string) error {
	return fmt.Errorf("%w: %s overflows a 64-bit total", ErrInvalid, what)
}
