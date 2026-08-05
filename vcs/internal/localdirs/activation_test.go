package localdirs

import (
	"context"
	"crypto/sha1"
	"encoding/binary"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
)

// fakeVolume is a read-only stand-in for the volume client that records every
// path activation touches, so the tests can assert not just what activation
// concludes but what it is allowed to look at.
type fakeVolume struct {
	files    map[string]string
	dirs     map[string][]string
	statuses map[string]clientcore.Status
	touched  []string
}

func (f *fakeVolume) note(p string) { f.touched = append(f.touched, p) }

func (f *fakeVolume) Lookup(_ context.Context, p string) (fsproto.Attr, clientcore.Status) {
	f.note(p)
	if st, ok := f.statuses[p]; ok {
		return fsproto.Attr{}, st
	}
	if data, ok := f.files[p]; ok {
		return fsproto.Attr{Kind: "file", Size: int64(len(data))}, fsproto.OK
	}
	if _, ok := f.dirs[p]; ok {
		return fsproto.Attr{Kind: "directory"}, fsproto.OK
	}
	return fsproto.Attr{}, fsproto.ENOENT
}

func (f *fakeVolume) Read(_ context.Context, p string, _ *clientcore.NodeState, off int64, length int) ([]byte, clientcore.Status) {
	f.note(p)
	data, ok := f.files[p]
	if !ok {
		return nil, fsproto.ENOENT
	}
	if off >= int64(len(data)) {
		return nil, fsproto.OK
	}
	end := int(off) + length
	if end > len(data) {
		end = len(data)
	}
	return []byte(data[off:end]), fsproto.OK
}

func (f *fakeVolume) Readdir(_ context.Context, p string) ([]clientcore.DirEntry, clientcore.Status) {
	f.note(p)
	names, ok := f.dirs[p]
	if !ok {
		return nil, fsproto.ENOENT
	}
	ents := make([]clientcore.DirEntry, 0, len(names))
	for _, n := range names {
		ents = append(ents, clientcore.DirEntry{Name: n})
	}
	return ents, fsproto.OK
}

func gitIndexV2(paths ...string) string {
	out := make([]byte, 12)
	copy(out, "DIRC")
	binary.BigEndian.PutUint32(out[4:8], 2)
	binary.BigEndian.PutUint32(out[8:12], uint32(len(paths)))
	for _, p := range paths {
		start := len(out)
		entry := make([]byte, 62)
		binary.BigEndian.PutUint16(entry[60:62], uint16(len(p)))
		out = append(out, entry...)
		out = append(out, p...)
		for (len(out)-start)%8 != 0 || len(out) == start+62+len(p) {
			out = append(out, 0)
		}
	}
	sum := sha1.Sum(out)
	out = append(out, sum[:]...)
	return string(out)
}

func TestReadRouteConfigFailsClosed(t *testing.T) {
	ctx := context.Background()
	// Absent declaration: no routes, not present, no error.
	empty := &fakeVolume{}
	if data, present, err := ReadRouteConfig(ctx, empty); err != nil || data != nil || present {
		t.Fatalf("absent declaration = (%q,%v,%v)", data, present, err)
	}
	// Present: read exactly, and reported as present.
	v := &fakeVolume{files: map[string]string{VolumeConfigPath: "node_modules/\n"}}
	data, present, err := ReadRouteConfig(ctx, v)
	if err != nil || string(data) != "node_modules/\n" || !present {
		t.Fatalf("declaration = (%q,%v,%v)", data, present, err)
	}
	// A declaration holding only comments is still the volume asserting that
	// IT owns routing, which is a different fact from "declares no rules".
	commented := &fakeVolume{files: map[string]string{VolumeConfigPath: "# nothing yet\n"}}
	if _, present, err := ReadRouteConfig(ctx, commented); err != nil || !present {
		t.Fatalf("commented declaration present=%v err=%v", present, err)
	}
	// Unreadable: an error, never a silent "no routes". A mount that
	// degraded here would serve the shared volume while reporting a revision
	// for a declaration it never read.
	broken := &fakeVolume{statuses: map[string]clientcore.Status{VolumeConfigPath: fsproto.EIO}}
	if _, _, err := ReadRouteConfig(ctx, broken); err == nil {
		t.Fatal("an unreadable declaration must fail the mount")
	}
}

func TestCheckGitTrackedRefusesActivation(t *testing.T) {
	ctx := context.Background()
	rules, err := localroutes.Parse([]byte("vendor/\nnode_modules/\n"))
	if err != nil {
		t.Fatal(err)
	}
	tracked := &fakeVolume{files: map[string]string{
		gitIndexPath: gitIndexV2("README.md", "vendor/dep/index.js"),
	}}
	if _, _, err := CheckGitTracked(ctx, tracked, rules); !errors.Is(err, ErrRoutesTrackedByGit) {
		t.Fatalf("a route over tracked content must refuse activation, got %v", err)
	}
	// Nothing the routes touch is tracked: proven clean.
	clean := &fakeVolume{files: map[string]string{
		gitIndexPath: gitIndexV2("README.md", "src/main.go"),
	}}
	proven, reason, err := CheckGitTracked(ctx, clean, rules)
	if err != nil || !proven || reason != "" {
		t.Fatalf("clean repository = (%v,%q,%v)", proven, reason, err)
	}
	// No repository at all is also a proof, not a gap.
	if proven, _, err := CheckGitTracked(ctx, &fakeVolume{}, rules); err != nil || !proven {
		t.Fatalf("absent index = (%v,%v)", proven, err)
	}
	// An index this parser cannot enumerate is reported honestly as
	// unprovable — never as "clean".
	v4 := &fakeVolume{files: map[string]string{gitIndexPath: "DIRC\x00\x00\x00\x04\x00\x00\x00\x00"}}
	proven, reason, err = CheckGitTracked(ctx, v4, rules)
	if err != nil || proven || !strings.Contains(reason, "unsupported git index version") {
		t.Fatalf("version 4 index = (%v,%q,%v)", proven, reason, err)
	}

	// Activation reads the declaration and the index, and nothing else — in
	// particular it never reads or writes .gitignore.
	seen := strings.Join(tracked.touched, " ")
	if strings.Contains(seen, ".gitignore") {
		t.Fatalf("activation touched .gitignore: %v", tracked.touched)
	}
	for _, p := range tracked.touched {
		if p != gitIndexPath {
			t.Fatalf("the tracked-file guard touched %q", p)
		}
	}
}

func TestShadowingWarnsAndNeverDeletes(t *testing.T) {
	ctx := context.Background()
	v := &fakeVolume{dirs: map[string][]string{
		"node_modules": {"react", "typescript", ".bin"},
		"empty":        {},
	}}
	names := ShadowedEntries(ctx, v, "node_modules", 16)
	sort.Strings(names)
	if strings.Join(names, ",") != ".bin,react,typescript" {
		t.Fatalf("shadowed entries = %v", names)
	}
	if got := ShadowedEntries(ctx, v, "empty", 16); len(got) != 0 {
		t.Fatalf("an empty shared directory hides nothing: %v", got)
	}
	if got := ShadowedEntries(ctx, v, "absent", 16); len(got) != 0 {
		t.Fatalf("an absent path hides nothing: %v", got)
	}
	if got := ShadowedEntries(ctx, v, "node_modules", 2); len(got) != 3 || !strings.Contains(got[2], "1 more") {
		t.Fatalf("long listings must be summarized, got %v", got)
	}

	rules, err := localroutes.Parse([]byte("/node_modules/\n**/target/\n"))
	if err != nil {
		t.Fatal(err)
	}
	var warned []string
	WarnAnchoredShadowing(ctx, v, rules, func(format string, args ...any) {
		warned = append(warned, format)
	})
	if len(warned) != 1 || !strings.Contains(warned[0], "never deleted") {
		t.Fatalf("anchored shadowing warnings = %v", warned)
	}
	// The volume's copy is untouched: warning is the whole action.
	if len(v.dirs["node_modules"]) != 3 {
		t.Fatal("shadowing must never remove the volume's content")
	}
}

// TestInstantiatedRootReportsShadowing pins the floating-pattern half: roots
// nobody could enumerate in advance report what they hide at the moment they
// come into existence.
func TestInstantiatedRootReportsShadowing(t *testing.T) {
	reported := make(chan string, 4)
	g, err := New(Config{
		BackingRoot: t.TempDir() + "/local/sid",
		Rules:       rulesFor(t, "node_modules/\n"),
		OnShadow:    func(root string) { reported <- root },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer g.Close()
	if eno := g.Mkdir("deep/app/node_modules", 0o755); eno != 0 {
		t.Fatalf("mkdir errno=%d", eno)
	}
	select {
	case got := <-reported:
		if got != "deep/app/node_modules" {
			t.Fatalf("reported %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("instantiating a route root must report what it shadows")
	}
	// Ordinary directories inside a graft report nothing: only ROOTS start
	// shadowing.
	if eno := g.Mkdir("deep/app/node_modules/react", 0o755); eno != 0 {
		t.Fatalf("mkdir errno=%d", eno)
	}
	select {
	case got := <-reported:
		t.Fatalf("a non-root mkdir reported shadowing of %q", got)
	default:
	}
}
