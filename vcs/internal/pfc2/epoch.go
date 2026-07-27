package pfc2

// Checkout epochs are canonical positive PostgreSQL BIGINT values serialized
// as ASCII decimals: [1-9][0-9]{0,18}, additionally bounded to
// 9223372036854775807. They compare by digit length then lexicographically and
// are NEVER round-tripped through JavaScript numbers or floating point; this
// implementation never converts them to a binary integer at all, so there is
// no representation in which precision could be lost.

// EpochBound is the maximum epoch value (PostgreSQL BIGINT max).
const EpochBound = "9223372036854775807"

// FirstEpoch is the initial next-checkout-epoch of an empty control state.
const FirstEpoch Epoch = "1"

// Epoch is one canonical decimal checkout epoch.
type Epoch string

// Validate enforces the canonical decimal domain.
func (e Epoch) Validate() error {
	s := string(e)
	if len(s) == 0 || len(s) > len(EpochBound) {
		return malformedf("epoch %q is empty or exceeds %d digits", s, len(EpochBound))
	}
	if s[0] < '1' || s[0] > '9' {
		return malformedf("epoch %q must begin with a nonzero digit", s)
	}
	for i := 1; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return malformedf("epoch %q contains a non-digit", s)
		}
	}
	if len(s) == len(EpochBound) && s > EpochBound {
		return malformedf("epoch %q exceeds the BIGINT bound %s", s, EpochBound)
	}
	return nil
}

// Compare orders two valid epochs by digit length then lexicographically.
// It returns -1, 0, or 1.
func (e Epoch) Compare(other Epoch) int {
	switch {
	case len(e) != len(other):
		if len(e) < len(other) {
			return -1
		}
		return 1
	case e < other:
		return -1
	case e > other:
		return 1
	default:
		return 0
	}
}

// Next returns e+1 by exact decimal string increment. Exhaustion of the
// BIGINT domain is a typed capacity error; epochs never wrap or reuse.
func (e Epoch) Next() (Epoch, error) {
	if string(e) == EpochBound {
		return "", capacityf("checkout epoch domain exhausted at %s", EpochBound)
	}
	digits := []byte(e)
	for i := len(digits) - 1; i >= 0; i-- {
		if digits[i] != '9' {
			digits[i]++
			return Epoch(digits), nil
		}
		digits[i] = '0'
	}
	return Epoch("1" + string(digits)), nil
}

// Int64 converts a VALID epoch to its exact int64 value by decimal digit
// fold. The epoch domain is exactly the positive BIGINT domain, so the
// conversion is lossless — this is an exact integer mapping for durable
// binary storage (slot outcomes), never a floating-point or JavaScript
// round-trip.
func (e Epoch) Int64() (int64, error) {
	if err := e.Validate(); err != nil {
		return 0, err
	}
	var v int64
	for i := 0; i < len(e); i++ {
		v = v*10 + int64(e[i]-'0')
	}
	return v, nil
}

// EpochFromInt64 converts an exact stored epoch integer back to its canonical
// decimal form (the inverse of Int64 for the valid domain).
func EpochFromInt64(v int64) (Epoch, error) {
	if v <= 0 {
		return "", malformedf("epoch integer %d is outside the positive BIGINT domain", v)
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return Epoch(buf[i:]), nil
}
