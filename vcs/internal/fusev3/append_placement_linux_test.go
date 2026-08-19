//go:build linux

package fusev3

import "testing"

func TestResolveAppendPlacementCoversEveryKernelReading(t *testing.T) {
	for _, tc := range []struct {
		name       string
		appendFlag bool
		offset     uint64
		want       appendPlacement
	}{{
		name: "an append descriptor appends", appendFlag: true, offset: 4096,
		want: appendPlacement{append: true},
	}, {
		name: "an append descriptor appends whatever offset the kernel derived", appendFlag: true, offset: 0,
		want: appendPlacement{append: true},
	}, {
		name: "a plain descriptor is placed where the kernel asked", offset: 1024,
		want: appendPlacement{position: 1024},
	}, {
		name: "a plain descriptor writing at offset zero", offset: 0, want: appendPlacement{position: 0},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveAppendPlacement(tc.appendFlag, tc.offset)
			if got != tc.want {
				t.Fatalf("resolveAppendPlacement(%t, %d) = %+v, want %+v", tc.appendFlag, tc.offset, got, tc.want)
			}
			if got.append && got.position != 0 {
				t.Fatalf("an append must carry no position, got %+v", got)
			}
		})
	}
}
