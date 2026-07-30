package clientcore

import "testing"

func TestUsableFallbackInoExcludesReservedValues(t *testing.T) {
	tests := []struct {
		input uint64
		want  uint64
	}{
		{input: 0, want: 2},
		{input: 1, want: 2},
		{input: 2, want: 2},
		{input: ^uint64(0), want: ^uint64(0) - 1},
		{input: ^uint64(0) - 1, want: ^uint64(0) - 1},
	}
	for _, test := range tests {
		if got := usableFallbackIno(test.input); got != test.want {
			t.Fatalf("usableFallbackIno(%d) = %d, want %d", test.input, got, test.want)
		}
	}
}
