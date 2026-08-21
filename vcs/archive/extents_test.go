package archive

import (
	"errors"
	"testing"
)

// TestNormalizeExtents proves the scanner's output is forced into the one
// canonical shape the format accepts, and that the two shapes that would be a
// lie rather than a formatting difference are rejected instead of repaired.
func TestNormalizeExtents(t *testing.T) {
	cases := []struct {
		name  string
		input []Extent
		size  uint64
		want  []Extent
	}{
		{name: "empty", input: nil, size: 100, want: nil},
		{
			name:  "adjacent runs merge",
			input: []Extent{{Offset: 0, Length: 10}, {Offset: 10, Length: 10}, {Offset: 20, Length: 5}},
			size:  100,
			want:  []Extent{{Offset: 0, Length: 25}},
		},
		{
			name:  "separated runs stay separate",
			input: []Extent{{Offset: 0, Length: 10}, {Offset: 20, Length: 10}},
			size:  100,
			want:  []Extent{{Offset: 0, Length: 10}, {Offset: 20, Length: 10}},
		},
		{
			name:  "zero-length runs disappear",
			input: []Extent{{Offset: 0, Length: 10}, {Offset: 30, Length: 0}, {Offset: 40, Length: 5}},
			size:  100,
			want:  []Extent{{Offset: 0, Length: 10}, {Offset: 40, Length: 5}},
		},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			got, err := normalizeExtents(testCase.input, testCase.size)
			if err != nil {
				t.Fatalf("normalize: %v", err)
			}
			if !equalExtents(got, testCase.want) {
				t.Fatalf("normalized to %v, want %v", got, testCase.want)
			}
		})
	}
	if _, err := normalizeExtents([]Extent{{Offset: 0, Length: 10}, {Offset: 5, Length: 10}}, 100); !errors.Is(err, ErrInvalid) {
		t.Fatalf("overlapping extents were normalized rather than refused")
	}
	if _, err := normalizeExtents([]Extent{{Offset: 90, Length: 20}}, 100); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an extent past the file size was accepted")
	}
	if _, err := normalizeExtents([]Extent{{Offset: 1 << 63, Length: 1 << 63}}, 100); !errors.Is(err, ErrInvalid) {
		t.Fatalf("an extent whose end wraps was accepted")
	}
}

// TestWholeFileExtents pins the portable fallback: it is always a legal answer,
// it never claims a hole, and it says nothing at all about an empty file.
func TestWholeFileExtents(t *testing.T) {
	got, err := WholeFileExtents(nil, 0)
	if err != nil || got != nil {
		t.Fatalf("empty file produced %v (%v)", got, err)
	}
	got, err = WholeFileExtents(nil, 4096)
	if err != nil {
		t.Fatalf("whole file: %v", err)
	}
	if !equalExtents(got, []Extent{{Offset: 0, Length: 4096}}) {
		t.Fatalf("whole file produced %v", got)
	}
	if _, err := WholeFileExtents(nil, -1); !errors.Is(err, ErrInvalid) {
		t.Fatalf("a negative size was accepted")
	}
}
