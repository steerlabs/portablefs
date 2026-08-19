//go:build linux

package fusev3

import (
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

func TestResolveAppendPlacementCoversEveryKernelReading(t *testing.T) {
	for _, tc := range []struct {
		name        string
		appendFlag  bool
		offset      uint64
		shadow      uint64
		shadowKnown bool
		want        appendPlacement
	}{{
		name: "append descriptor writing at the kernel size", appendFlag: true, offset: 4096, shadow: 4096,
		shadowKnown: true, want: appendPlacement{append: true},
	}, {
		name: "append descriptor writing at a smaller offset is RWF_NOAPPEND", appendFlag: true, offset: 2048,
		shadow: 4096, shadowKnown: true, want: appendPlacement{position: 2048},
	}, {
		name: "append descriptor writing past the kernel size", appendFlag: true, offset: 8192,
		shadow: 4096, shadowKnown: true, want: appendPlacement{position: 8192},
	}, {
		name: "plain descriptor writing inside the object", appendFlag: false, offset: 1024, shadow: 4096,
		shadowKnown: true, want: appendPlacement{position: 1024},
	}, {
		name: "plain descriptor writing past the kernel size", appendFlag: false, offset: 8192, shadow: 4096,
		shadowKnown: true, want: appendPlacement{position: 8192},
	}, {
		name: "plain descriptor writing exactly at the kernel size may be a hidden append",
		appendFlag: false, offset: 4096, shadow: 4096, shadowKnown: true,
		want: appendPlacement{position: 4096, offsetMatchesClientSize: true},
	}, {
		name: "empty object appended to", appendFlag: true, offset: 0, shadow: 0, shadowKnown: true,
		want: appendPlacement{append: true},
	}, {
		name: "empty object written at zero", appendFlag: false, offset: 0, shadow: 0, shadowKnown: true,
		want: appendPlacement{position: 0, offsetMatchesClientSize: true},
	}, {
		name: "unknown shadow with an append descriptor", appendFlag: true, offset: 4096,
		want: appendPlacement{refuse: true},
	}, {
		name: "unknown shadow with a plain descriptor", appendFlag: false, offset: 4096,
		want: appendPlacement{refuse: true},
	}} {
		t.Run(tc.name, func(t *testing.T) {
			got := resolveAppendPlacement(tc.appendFlag, tc.offset, tc.shadow, tc.shadowKnown)
			if got != tc.want {
				t.Fatalf("resolveAppendPlacement(%t, %d, %d, %t) = %+v, want %+v",
					tc.appendFlag, tc.offset, tc.shadow, tc.shadowKnown, got, tc.want)
			}
			if got.append && got.position != 0 {
				t.Fatalf("an append must carry no position, got %+v", got)
			}
			if got.append && got.offsetMatchesClientSize {
				t.Fatalf("an append states its own placement and must not also flag the offset, got %+v", got)
			}
		})
	}
}

func TestKernelSizeShadowTransitions(t *testing.T) {
	requireShadow := func(t *testing.T, shadow *kernelSizeShadow, inode, want uint64) {
		t.Helper()
		got, known := shadow.lookup(inode)
		if !known || got != want {
			t.Fatalf("shadow of inode %d = (%d, %t), want (%d, true)", inode, got, known, want)
		}
	}
	requireUnknown := func(t *testing.T, shadow *kernelSizeShadow, inode uint64) {
		t.Helper()
		if got, known := shadow.lookup(inode); known {
			t.Fatalf("shadow of inode %d = %d, want unknown", inode, got)
		}
	}

	t.Run("an unseen inode is unknown", func(t *testing.T) {
		requireUnknown(t, newKernelSizeShadow(), 7)
	})

	t.Run("an attribute reply assigns the size", func(t *testing.T) {
		shadow := newKernelSizeShadow()
		shadow.observeAttr(7, 4096, shadow.begin())
		requireShadow(t, shadow, 7, 4096)
	})

	t.Run("an attribute reply with no provenance fails closed", func(t *testing.T) {
		shadow := newKernelSizeShadow()
		shadow.observeAttr(7, 4096, 0)
		requireUnknown(t, shadow, 7)
	})

	t.Run("a negative size fails closed", func(t *testing.T) {
		shadow := newKernelSizeShadow()
		shadow.observeAttr(7, -1, shadow.begin())
		requireUnknown(t, shadow, 7)
	})

	t.Run("a write raises the size and never lowers it", func(t *testing.T) {
		shadow := newKernelSizeShadow()
		shadow.observeAttr(7, 4096, shadow.begin())
		shadow.observeRaise(7, 8192)
		requireShadow(t, shadow, 7, 8192)
		shadow.observeRaise(7, 1024)
		requireShadow(t, shadow, 7, 8192)
	})

	t.Run("a write cannot repair an unknown shadow", func(t *testing.T) {
		shadow := newKernelSizeShadow()
		shadow.observeRaise(7, 8192)
		requireUnknown(t, shadow, 7)
	})

	t.Run("an attribute reply a write overtook fails closed", func(t *testing.T) {
		shadow := newKernelSizeShadow()
		shadow.observeAttr(7, 4096, shadow.begin())
		since := shadow.begin()
		shadow.observeRaise(7, 8192)
		shadow.observeAttr(7, 4096, since)
		requireUnknown(t, shadow, 7)
	})

	t.Run("a write to another inode does not poison this one", func(t *testing.T) {
		shadow := newKernelSizeShadow()
		shadow.observeAttr(7, 4096, shadow.begin())
		since := shadow.begin()
		shadow.observeRaise(9, 8192)
		shadow.observeAttr(7, 5000, since)
		requireShadow(t, shadow, 7, 5000)
	})

	t.Run("an attribute reply repairs an unknown shadow", func(t *testing.T) {
		shadow := newKernelSizeShadow()
		shadow.observeAttr(7, 4096, 0)
		requireUnknown(t, shadow, 7)
		shadow.observeAttr(7, 4096, shadow.begin())
		requireShadow(t, shadow, 7, 4096)
	})

	t.Run("an unconditional reply assigns any size", func(t *testing.T) {
		shadow := newKernelSizeShadow()
		shadow.observeAttr(7, 4096, shadow.begin())
		shadow.observeSet(7, 0)
		requireShadow(t, shadow, 7, 0)
	})

	t.Run("an unconditional reply poisons an attribute reply it overtook", func(t *testing.T) {
		shadow := newKernelSizeShadow()
		since := shadow.begin()
		shadow.observeSet(7, 0)
		shadow.observeAttr(7, 4096, since)
		requireUnknown(t, shadow, 7)
	})

	t.Run("forget drops the inode", func(t *testing.T) {
		shadow := newKernelSizeShadow()
		shadow.observeAttr(7, 4096, shadow.begin())
		shadow.forget(7)
		requireUnknown(t, shadow, 7)
		if shadow.len() != 0 {
			t.Fatalf("retained %d shadow entries after forget", shadow.len())
		}
	})

	t.Run("inode zero is never retained", func(t *testing.T) {
		shadow := newKernelSizeShadow()
		shadow.observeAttr(0, 4096, shadow.begin())
		shadow.observeRaise(0, 4096)
		shadow.observeSet(0, 4096)
		if shadow.len() != 0 {
			t.Fatalf("retained %d shadow entries for inode zero", shadow.len())
		}
	})
}

func TestNoteKernelAttrRetainsOnlyRegularFiles(t *testing.T) {
	r := &rawFileSystem{sizes: newKernelSizeShadow()}
	for _, kind := range []authoritypb.Attr_Kind{authoritypb.Attr_DIRECTORY, authoritypb.Attr_SYMLINK, authoritypb.Attr_KIND_UNSPECIFIED} {
		r.noteKernelAttr(nil, &authoritypb.Attr{Inode: 7, Kind: kind, Size: 4096})
		if r.sizes.len() != 0 {
			t.Fatalf("kind %v was retained in the kernel-size shadow", kind)
		}
	}
}
