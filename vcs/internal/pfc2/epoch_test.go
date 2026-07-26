package pfc2

import (
	"errors"
	"math/rand"
	"strconv"
	"testing"
)

func TestEpochValidate(t *testing.T) {
	valid := []Epoch{"1", "9", "10", "42", "999999999999999999", "9223372036854775807", "9000000000000000000"}
	for _, e := range valid {
		if err := e.Validate(); err != nil {
			t.Errorf("%q rejected: %v", e, err)
		}
	}
	invalid := []Epoch{"", "0", "01", "-1", "+1", "1.5", "1e3", " 1", "1 ", "٣", "9223372036854775808", "92233720368547758070", "abc"}
	for _, e := range invalid {
		if err := e.Validate(); err == nil {
			t.Errorf("%q accepted", e)
		} else if !errors.Is(err, ErrMalformed) {
			t.Errorf("%q: error root is not ErrMalformed: %v", e, err)
		}
	}
}

func TestEpochCompareAndNext(t *testing.T) {
	cases := []struct{ a, b Epoch }{
		{"1", "2"}, {"9", "10"}, {"19", "20"}, {"99", "100"},
		{"999999999999999999", "1000000000000000000"},
		{"9223372036854775806", "9223372036854775807"},
	}
	for _, c := range cases {
		if got, err := c.a.Next(); err != nil || got != c.b {
			t.Errorf("Next(%s) = %s, %v; want %s", c.a, got, err, c.b)
		}
		if c.a.Compare(c.b) != -1 || c.b.Compare(c.a) != 1 || c.a.Compare(c.a) != 0 {
			t.Errorf("compare(%s, %s) inconsistent", c.a, c.b)
		}
	}
	if _, err := Epoch(EpochBound).Next(); !errors.Is(err, ErrCapacity) {
		t.Fatalf("epoch exhaustion must be a typed capacity error, got %v", err)
	}
}

// TestEpochNoBinaryLoss cross-checks the pure-decimal implementation against
// exact integer arithmetic across the domain, including values that would be
// corrupted by any float64/JSON-number round trip (2^53+1 etc.).
func TestEpochNoBinaryLoss(t *testing.T) {
	check := func(v uint64) {
		e := Epoch(strconv.FormatUint(v, 10))
		if err := e.Validate(); err != nil {
			t.Fatalf("%d rejected: %v", v, err)
		}
		next, err := e.Next()
		if err != nil {
			t.Fatalf("%d: %v", v, err)
		}
		if want := strconv.FormatUint(v+1, 10); string(next) != want {
			t.Fatalf("Next(%d) = %s, want %s", v, next, want)
		}
		if e.Compare(next) != -1 {
			t.Fatalf("%d !< %d", v, v+1)
		}
	}
	check(1 << 53) // first float64-unrepresentable neighborhood
	check(1<<53 + 1)
	check(9007199254740993) // 2^53+1 spelled out
	check(1<<62 - 1)
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 20000; i++ {
		check(rng.Uint64()%(1<<63-2) + 1)
	}
}
