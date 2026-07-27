package pft2

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestComposeSplitIno(t *testing.T) {
	ino, err := ComposeIno(1, 1)
	if err != nil || ino != (1<<32)|1 {
		t.Fatalf("%d %v", ino, err)
	}
	ino, err = ComposeIno(MaxInodeNamespace, MaxInodeLocalCounter)
	if err != nil {
		t.Fatal(err)
	}
	if ino != MaxIno {
		t.Fatalf("max composition %d, want %d", ino, MaxIno)
	}
	namespace, local, err := SplitIno(ino)
	if err != nil || namespace != MaxInodeNamespace || local != MaxInodeLocalCounter {
		t.Fatalf("%d %d %v", namespace, local, err)
	}

	// Namespace 0 legacy domain.
	namespace, local, err = SplitIno(1)
	if err != nil || namespace != 0 || local != 1 {
		t.Fatalf("%d %d %v", namespace, local, err)
	}

	if _, err := ComposeIno(0, 1); !errors.Is(err, ErrInodeNamespaceExhausted) {
		t.Fatalf("namespace 0: %v", err)
	}
	if _, err := ComposeIno(MaxInodeNamespace+1, 1); !errors.Is(err, ErrInodeNamespaceExhausted) {
		t.Fatalf("namespace overflow: %v", err)
	}
	if _, err := ComposeIno(1, 0); !errors.Is(err, ErrInodeCounterExhausted) {
		t.Fatalf("counter 0: %v", err)
	}
	if _, err := ComposeIno(1, MaxInodeLocalCounter+1); !errors.Is(err, ErrInodeCounterExhausted) {
		t.Fatalf("counter overflow: %v", err)
	}
	if _, _, err := SplitIno(0); !errors.Is(err, ErrInvalidNode) {
		t.Fatalf("split 0: %v", err)
	}
	if _, _, err := SplitIno(MaxIno + 1); !errors.Is(err, ErrInvalidNode) {
		t.Fatalf("split beyond max: %v", err)
	}
	// namespace != 0 with local 0 is unreachable by composition.
	if _, _, err := SplitIno(uint64(5) << 32); !errors.Is(err, ErrInvalidNode) {
		t.Fatalf("split hole: %v", err)
	}
}

func TestInodeAllocator(t *testing.T) {
	alloc, err := NewInodeAllocator(9, 1)
	if err != nil {
		t.Fatal(err)
	}
	first, err := alloc.Allocate()
	if err != nil || first != (9<<32)|1 {
		t.Fatalf("%d %v", first, err)
	}
	second, err := alloc.Allocate()
	if err != nil || second != (9<<32)|2 {
		t.Fatalf("%d %v", second, err)
	}
	if alloc.NextLocal() != 3 {
		t.Fatalf("next local %d", alloc.NextLocal())
	}

	// Resume at the brink of exhaustion, then fail typed and never wrap.
	brink, err := NewInodeAllocator(9, MaxInodeLocalCounter)
	if err != nil {
		t.Fatal(err)
	}
	last, err := brink.Allocate()
	if err != nil || last != (9<<32)|MaxInodeLocalCounter {
		t.Fatalf("%d %v", last, err)
	}
	if _, err := brink.Allocate(); !errors.Is(err, ErrInodeCounterExhausted) {
		t.Fatalf("exhaustion: %v", err)
	}
	if _, err := brink.Allocate(); !errors.Is(err, ErrInodeCounterExhausted) {
		t.Fatalf("exhaustion is not terminal: %v", err)
	}
	if brink.NextLocal() != MaxInodeLocalCounter+1 {
		t.Fatalf("exhausted next local %d", brink.NextLocal())
	}
	// The exhausted marker round-trips through persistence.
	resumed, err := NewInodeAllocator(9, brink.NextLocal())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := resumed.Allocate(); !errors.Is(err, ErrInodeCounterExhausted) {
		t.Fatalf("resumed exhaustion: %v", err)
	}

	if _, err := NewInodeAllocator(0, 1); !errors.Is(err, ErrInodeNamespaceExhausted) {
		t.Fatalf("namespace 0 allocator: %v", err)
	}
	if _, err := NewInodeAllocator(1, 0); !errors.Is(err, ErrInvalidNode) {
		t.Fatalf("zero counter allocator: %v", err)
	}
	if _, err := NewInodeAllocator(1, MaxInodeLocalCounter+2); !errors.Is(err, ErrInvalidNode) {
		t.Fatalf("beyond-exhaustion counter allocator: %v", err)
	}
}

func TestUint64StringJSON(t *testing.T) {
	// 2^63-1 cannot round-trip through a float64; the string form must.
	value := Uint64String(MaxIno)
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `"9223372036854775807"` {
		t.Fatalf("marshaled %s", data)
	}
	var back Uint64String
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if back != value {
		t.Fatalf("round trip %d", back)
	}

	var zero Uint64String
	if err := json.Unmarshal([]byte(`"0"`), &zero); err != nil || zero != 0 {
		t.Fatalf("%d %v", zero, err)
	}

	for _, bad := range []string{`123`, `"01"`, `""`, `"-1"`, `"+1"`, `" 1"`, `"1.5"`,
		`"18446744073709551616"`, `"99999999999999999999999"`, `null`, `"0x10"`} {
		var v Uint64String
		if err := json.Unmarshal([]byte(bad), &v); err == nil {
			t.Fatalf("accepted %s", bad)
		}
	}

	max := Uint64String(1<<64 - 1)
	data, err = json.Marshal(max)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `"18446744073709551615"` {
		t.Fatalf("marshaled %s", data)
	}
	var backMax Uint64String
	if err := json.Unmarshal(data, &backMax); err != nil || backMax != max {
		t.Fatalf("%d %v", backMax, err)
	}
}

func TestParseUint64Decimal(t *testing.T) {
	cases := map[string]uint64{
		"0":                    0,
		"7":                    7,
		"4294967296":           1 << 32,
		"18446744073709551615": 1<<64 - 1,
	}
	for input, want := range cases {
		got, err := ParseUint64Decimal(input)
		if err != nil || got != want {
			t.Fatalf("%q: %d %v", input, got, err)
		}
		if FormatUint64Decimal(got) != input {
			t.Fatalf("%q does not round trip", input)
		}
	}
	for _, bad := range []string{"", "00", "01", "-1", "1 ", " 1", "1a", "18446744073709551616",
		"184467440737095516150"} {
		if _, err := ParseUint64Decimal(bad); err == nil {
			t.Fatalf("accepted %q", bad)
		}
	}
}
