package localroutes

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func mustParse(t *testing.T, text string) RuleSet {
	t.Helper()
	rs, err := Parse([]byte(text))
	if err != nil {
		t.Fatalf("Parse(%q): %v", text, err)
	}
	return rs
}

// TestMatchShapes pins the four shapes of the language: anchored, floating,
// intra-component wildcards, and "**" spanning whole components.
func TestMatchShapes(t *testing.T) {
	rs := mustParse(t, `
# machine-local dependency trees
node_modules/
/target/
agent-app/.venv/
**/build/*.tmp.d/
services/**/dist/
`)
	cases := []struct {
		path string
		root string
	}{
		// Floating: any depth, and the topmost match owns the subtree.
		{"node_modules", "node_modules"},
		{"node_modules/react/index.js", "node_modules"},
		{"a/b/c/node_modules", "a/b/c/node_modules"},
		{"a/b/node_modules/pkg/node_modules/dep", "a/b/node_modules"},
		{"node_modules2", ""},
		{"anode_modules", ""},
		// Anchored: only at the volume root.
		{"target", "target"},
		{"target/debug/app", "target"},
		{"crates/target", ""},
		// Anchored multi-component (a '/' in the middle anchors it).
		{"agent-app/.venv/bin/python", "agent-app/.venv"},
		{"nested/agent-app/.venv", ""},
		// '*' within one component only.
		{"build/x.tmp.d", "build/x.tmp.d"},
		{"deep/build/y.tmp.d/obj", "deep/build/y.tmp.d"},
		{"build/x.tmp.d.other", ""},
		{"build/sub/x.tmp.d", ""},
		// '**' spans zero or more components.
		{"services/dist", "services/dist"},
		{"services/a/b/dist/assets", "services/a/b/dist"},
		{"other/services/dist", ""},
	}
	for _, tc := range cases {
		root, ok := rs.Match(tc.path)
		if tc.root == "" {
			if ok {
				t.Fatalf("Match(%q) = %q, want no match", tc.path, root)
			}
			continue
		}
		if !ok || root != tc.root {
			t.Fatalf("Match(%q) = (%q,%v), want %q", tc.path, root, ok, tc.root)
		}
	}
	// The volume root itself is never routed.
	if _, ok := rs.Match(""); ok {
		t.Fatal("the volume root must never match")
	}
}

// TestProtectedNamespaceIsUnmatchableByConstruction pins the language rule
// that makes the guard provable: no wildcard can expand to a protected
// component, so no rule can reach .git or .portablefs however it is written.
func TestProtectedNamespaceIsUnmatchableByConstruction(t *testing.T) {
	// Deliberately the most aggressive rule set the language can express:
	// every directory at every depth, plus a rule that names .git's own
	// children.
	rs := mustParse(t, "**/objects/\n**/*/\nsrc/**/\n")
	for _, p := range []string{
		".git",
		".git/objects",
		".git/objects/pack",
		".git/refs/heads/main",
		".portablefs",
		".portablefs/local-dirs",
	} {
		if root, rule, ok := rs.MatchRule(p); ok {
			t.Fatalf("Match(%q) = %q via %q; a protected component must stop matching dead", p, root, rule)
		}
	}
	// The same rules still route everything outside the protected namespace.
	if root, ok := rs.Match("src/objects"); !ok || root != "src" {
		t.Fatalf("Match(src/objects) = (%q,%v), want src", root, ok)
	}
	// Prefix closure is the invariant: a protected name BELOW a route root is
	// inside that root's subtree (a vendored repository inside a local
	// directory travels with it). The guarantee is about route ROOTS, and no
	// route root can ever be, or sit under, a protected name — which is what
	// keeps the volume's own .git and .portablefs shared, since their only
	// ancestor is the volume root and no rule may match that.
	if root, ok := rs.Match("src/.git/objects"); !ok || root != "src" {
		t.Fatalf("Match(src/.git/objects) = (%q,%v); routing must stay prefix-closed under src", root, ok)
	}
	// A nested repository is only ever local because an ANCESTOR of it is
	// routed; no rule can route into it by itself, however it wildcards.
	for _, rules := range []string{"**/objects/\n", "**/*/\n", "*/\n", "**/?it/\n", "/*/\n", "**/hooks/\n"} {
		nested := mustParse(t, rules)
		for _, p := range []string{".git/objects", ".git/hooks/pre-commit", ".portablefs/local-dirs"} {
			if root, ok := nested.Match(p); ok {
				t.Fatalf("rules %q routed %q as %q", rules, p, root)
			}
		}
		if root, ok := nested.Match("a/b/.git/objects"); ok && (root == "a/b/.git" || strings.HasPrefix(root, "a/b/.git/")) {
			t.Fatalf("rules %q made %q a route root", rules, root)
		}
	}
}

// TestValidationRejectsWholeRuleSet pins that a rule set which could route the
// wrong thing is refused with a precise error, rather than silently skipped at
// match time.
func TestValidationRejectsWholeRuleSet(t *testing.T) {
	cases := map[string]string{
		"explicit .git":          ".git/\n",
		"beneath .git":           "/.git/objects/\n",
		"floating beneath .git":  "**/.git/lfs/\n",
		"explicit .portablefs":   ".portablefs/\n",
		"declaration file":       "/.portablefs/local-dirs/\n",
		"volume root":            "/\n",
		"volume root globstar":   "**/\n",
		"volume root globstars":  "**/**/\n",
		"absolute host path":     "//abs/\n",
		"escape":                 "../up/\n",
		"escape in the middle":   "a/../../b/\n",
		"dot component":          "./x/\n",
		"negation":               "node_modules/\n!node_modules/keep/\n",
		"character class":        "node_[md]/\n",
		"backslash":              "node_modules\\.cache/\n",
		"glued globstar":         "a**b/\n",
		"empty component":        "a//b/\n",
		"nul component":          "a\x00b/\n",
		"one bad line fails all": "node_modules/\n.git/\ntarget/\n",
	}
	for name, text := range cases {
		if rs, err := Parse([]byte(text)); err == nil {
			t.Fatalf("%s: Parse(%q) accepted %v, want a precise error", name, text, rs.Patterns())
		} else if !strings.Contains(err.Error(), "line ") {
			t.Fatalf("%s: error %q must name the offending line", name, err)
		}
	}
	if rs, err := Parse([]byte{'a', 0xff, 'b', '/', '\n'}); err == nil {
		t.Fatalf("invalid UTF-8 was accepted as %v; JSON persistence would change its canonical bytes", rs.Patterns())
	}
}

// TestCanonicalRevision pins the hash contract the authority pins mounts to:
// textually different but semantically identical declarations hash equal, and
// a real routing difference always changes the hash.
func TestCanonicalRevision(t *testing.T) {
	equal := []string{
		"node_modules/\ntarget/\n",
		// reordered, re-spelled, commented, CRLF, blank lines, whitespace
		"# machine-local\r\n\r\n  target/  \r\n**/node_modules/   # deps\r\n",
		// a rule inside another rule's subtree is dead and drops out
		"node_modules/\nnode_modules/.cache/\ntarget/\na/b/node_modules/\n",
		// duplicates in any spelling
		"node_modules\nnode_modules/\n**/node_modules/\ntarget/\ntarget/\n",
	}
	want := mustParse(t, equal[0]).RevisionHex()
	for _, text := range equal[1:] {
		if got := mustParse(t, text).RevisionHex(); got != want {
			t.Fatalf("Parse(%q).Revision = %s, want %s (semantically identical)", text, got, want)
		}
	}
	if got := string(mustParse(t, equal[1]).Canonical()); got != "**/node_modules/\n**/target/\n" {
		t.Fatalf("canonical = %q", got)
	}
	// Anchoring is a routing difference and must not collapse.
	if mustParse(t, "/node_modules/\n").RevisionHex() == mustParse(t, "node_modules/\n").RevisionHex() {
		t.Fatal("anchored and floating rules must hash differently")
	}
	// The canonical form re-parses to itself.
	rs := mustParse(t, equal[2])
	again := mustParse(t, string(rs.Canonical()))
	if again.RevisionHex() != rs.RevisionHex() || string(again.Canonical()) != string(rs.Canonical()) {
		t.Fatalf("canonical form is not a fixed point: %q vs %q", again.Canonical(), rs.Canonical())
	}
	// The empty set is a legitimate revision, not an error.
	empty, err := Parse([]byte("# nothing declared\n"))
	if err != nil || !empty.Empty() {
		t.Fatalf("empty declaration: %v %v", empty.Patterns(), err)
	}
	if empty.RevisionHex() != (RuleSet{}).RevisionHex() {
		t.Fatal("an empty declaration and no declaration must be the same revision")
	}
}

// TestSubsumptionKeepsGlobRules pins the honest boundary of canonicalization:
// wildcard-free redundancy is removed, glob redundancy is not guessed at.
func TestSubsumptionKeepsGlobRules(t *testing.T) {
	// Two glob rules that clearly overlap are both kept: deciding containment
	// between glob patterns is not something this package guesses at.
	rs := mustParse(t, "node_*/\n*_modules/\n")
	if len(rs.Patterns()) != 2 {
		t.Fatalf("patterns = %v; a glob rule must never be dropped as redundant", rs.Patterns())
	}
	// A wildcard-free rule IS dropped when a glob already routes its root or
	// an ancestor of it — the decision is concrete in that direction.
	for text, want := range map[string]string{
		"node_*/\nnode_modules/":       "**/node_*/",
		"node_*/\nnode_modules/cache/": "**/node_*/",
		"/apps/*/\n/apps/web/dist/":    "/apps/*/",
	} {
		if got := strings.Join(mustParse(t, text).Patterns(), " "); got != want {
			t.Fatalf("Parse(%q) patterns = %q want %q", text, got, want)
		}
	}
}

// TestLiteralPattern pins how --local-dir values enter the same revision.
func TestLiteralPattern(t *testing.T) {
	for in, want := range map[string]string{
		"node_modules":            "/node_modules/",
		"/target":                 "/target/",
		"agent-app//node_modules": "",
	} {
		got, err := LiteralPattern(in)
		if want == "" {
			if err == nil {
				t.Fatalf("LiteralPattern(%q) = %q, want an error", in, got)
			}
			continue
		}
		if err != nil || got != want {
			t.Fatalf("LiteralPattern(%q) = (%q,%v), want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "  ", "..", "../up", "node_*", "a[b]", `a\b`, ".git", ".git/objects", ".portablefs"} {
		if got, err := LiteralPattern(bad); err == nil {
			t.Fatalf("LiteralPattern(%q) = %q, want an error", bad, got)
		}
	}
	// A literal rule is an ordinary rule of the same one language: however a
	// declaration spells its rules, and in whatever order, one routing has
	// one revision.
	lit, err := LiteralPattern("agent-app/.venv")
	if err != nil {
		t.Fatal(err)
	}
	a := mustParse(t, "node_modules/\n"+lit+"\n")
	b := mustParse(t, lit+"\nnode_modules/\n")
	if a.RevisionHex() != b.RevisionHex() {
		t.Fatal("a revision must not depend on the order rules are written in")
	}
	if a.RevisionHex() == mustParse(t, "node_modules/\n").RevisionHex() {
		t.Fatal("a different rule set must be a different revision")
	}
}

func TestLiteralPatternCannotChangeMeaningWhenReparsed(t *testing.T) {
	for name, path := range map[string]string{
		"comment":             "deps#private",
		"additional rule":     "deps\n/other",
		"nul component":       "deps\x00private",
		"leading whitespace":  " deps",
		"trailing whitespace": "deps ",
	} {
		t.Run(name, func(t *testing.T) {
			if rendered, err := LiteralPattern(path); err == nil {
				t.Fatalf("LiteralPattern(%q) = %q; want a refusal because Parse would change its meaning", path, rendered)
			}
		})
	}

	rendered, err := LiteralPattern("deps\rprivate")
	if err != nil {
		t.Fatalf("a representable embedded carriage return was refused: %v", err)
	}
	rules, err := Parse([]byte(rendered + "\n"))
	if err != nil || len(rules.Patterns()) != 1 || rules.Patterns()[0] != rendered {
		t.Fatalf("rendered literal did not round trip exactly: rendered=%q rules=%q err=%v", rendered, rules.Patterns(), err)
	}
}

// TestSubtreeKeyDetectsOwnershipFlips pins the static check that lets a rename
// of a shared directory be refused before it silently changes what is local.
func TestSubtreeKeyDetectsOwnershipFlips(t *testing.T) {
	// Floating rules route by name at any depth, so moving a shared ancestor
	// cannot change what its descendants are.
	floating := mustParse(t, "node_modules/\n")
	if floating.SubtreeKey("agent-app") != floating.SubtreeKey("agent-app-v2") {
		t.Fatal("a floating rule must not make an ancestor rename a routing change")
	}
	// An anchored rule does: src/node_modules is routed, src2/node_modules is
	// not, so renaming src flips ownership of a path inside it.
	anchored := mustParse(t, "/src/node_modules/\n")
	if anchored.SubtreeKey("src") == anchored.SubtreeKey("src2") {
		t.Fatal("an anchored rule must make the ancestor rename a routing change")
	}
	// Two shared names that are equally uninteresting to the rule set are
	// interchangeable, so ordinary renames stay allowed.
	if anchored.SubtreeKey("docs") != anchored.SubtreeKey("papers") {
		t.Fatal("unrelated shared directories must have the same subtree key")
	}
	// Moving into the protected namespace is its own state.
	if anchored.SubtreeKey(".git") == anchored.SubtreeKey("docs") {
		t.Fatal("the protected namespace must be a distinct subtree state")
	}
	// A wildcard ancestor discriminates exactly like a literal one.
	glob := mustParse(t, "/apps/*/dist/\n")
	if glob.SubtreeKey("apps/web") == glob.SubtreeKey("vendor") {
		t.Fatal("a matched wildcard ancestor must differ from an unrelated path")
	}
	if glob.SubtreeKey("apps/web") != glob.SubtreeKey("apps/api") {
		t.Fatal("two paths the same wildcard matches must be interchangeable")
	}
}

func TestParseGitIndexPaths(t *testing.T) {
	paths := []string{"README.md", "src/main.go", "vendor/dep/index.js"}
	for _, version := range []uint32{2, 3} {
		data := buildGitIndex(version, paths)
		got, err := ParseGitIndexPaths(data)
		if err != nil {
			t.Fatalf("v%d: %v", version, err)
		}
		if strings.Join(got, ",") != strings.Join(paths, ",") {
			t.Fatalf("v%d: paths = %v", version, got)
		}
	}
	if _, err := ParseGitIndexPaths(buildGitIndex(4, paths)); !errors.Is(err, ErrGitIndexUnsupported) {
		t.Fatalf("v4 must be reported as unprovable, got %v", err)
	}
	if _, err := ParseGitIndexPaths([]byte("nope")); err == nil {
		t.Fatal("a non-index must be an error")
	}
	if _, err := ParseGitIndexPaths(buildGitIndex(2, paths)[:40]); err == nil {
		t.Fatal("a truncated index must be an error")
	}
	if got, err := ParseGitIndexPaths(buildGitIndexWithHash(2, paths, sha256.Size)); err != nil || strings.Join(got, ",") != strings.Join(paths, ",") {
		t.Fatalf("SHA-256 index paths = %v, err %v", got, err)
	}
	corrupt := buildGitIndex(2, paths)
	corrupt[len(corrupt)-1] ^= 1
	if _, err := ParseGitIndexPaths(corrupt); err == nil {
		t.Fatal("an index with a corrupt checksum was accepted")
	}
	extended := buildGitIndex(2, paths)
	extended = extended[:len(extended)-sha1.Size]
	extended = append(extended, []byte("link\x00\x00\x00\x00")...)
	sum := sha1.Sum(extended)
	extended = append(extended, sum[:]...)
	if _, err := ParseGitIndexPaths(extended); !errors.Is(err, ErrGitIndexUnsupported) {
		t.Fatalf("an index extension must be an unproven format, got %v", err)
	}
	sparse := buildGitIndex(2, paths[:1])
	binary.BigEndian.PutUint32(sparse[12+24:12+28], 0o040000)
	sum = sha1.Sum(sparse[:len(sparse)-sha1.Size])
	copy(sparse[len(sparse)-sha1.Size:], sum[:])
	if _, err := ParseGitIndexPaths(sparse); !errors.Is(err, ErrGitIndexUnsupported) {
		t.Fatalf("a sparse-directory entry must be unproven, got %v", err)
	}

	rs := mustParse(t, "vendor/\n")
	p, root, rule, found := rs.FirstTrackedMatch(paths)
	if !found || p != "vendor/dep/index.js" || root != "vendor" || rule != "**/vendor/" {
		t.Fatalf("FirstTrackedMatch = (%q,%q,%q,%v)", p, root, rule, found)
	}
	if _, _, _, found := mustParse(t, "node_modules/\n").FirstTrackedMatch(paths); found {
		t.Fatal("untracked routes must not report a match")
	}
}

// buildGitIndex writes a minimal but format-exact index for the test paths.
func buildGitIndex(version uint32, paths []string) []byte {
	return buildGitIndexWithHash(version, paths, sha1.Size)
}

func buildGitIndexWithHash(version uint32, paths []string, hashLen int) []byte {
	out := make([]byte, 12)
	copy(out, "DIRC")
	binary.BigEndian.PutUint32(out[4:8], version)
	binary.BigEndian.PutUint32(out[8:12], uint32(len(paths)))
	for _, p := range paths {
		start := len(out)
		entry := make([]byte, 42+hashLen)
		binary.BigEndian.PutUint16(entry[len(entry)-2:], uint16(len(p)))
		out = append(out, entry...)
		out = append(out, p...)
		for (len(out)-start)%8 != 0 || len(out) == start+len(entry)+len(p) {
			out = append(out, 0)
		}
	}
	if hashLen == sha256.Size {
		sum := sha256.Sum256(out)
		out = append(out, sum[:]...)
	} else {
		sum := sha1.Sum(out)
		out = append(out, sum[:]...)
	}
	return out
}

// BenchmarkMatch measures the mkdir/lookup hot path: an npm install creates
// tens of thousands of directories, and every one of them is matched.
func BenchmarkMatch(b *testing.B) {
	names := mustParseB(b, "node_modules/\n.venv/\ntarget/\ndist/\n.next/\n/vendor/\n")
	globs := mustParseB(b, "node_modules/\n**/build/*.tmp.d/\nservices/**/dist/\n")
	deep := "services/api/internal/handlers/v2/objects/store/impl"
	hit := "services/api/internal/node_modules/@scope/pkg/dist/index.js"
	for _, bc := range []struct {
		name string
		rs   RuleSet
		path string
	}{
		{"names/miss", names, deep},
		{"names/hit", names, hit},
		{"globs/miss", globs, deep},
		{"globs/hit", globs, hit},
	} {
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				if _, ok := bc.rs.Match(bc.path); ok != strings.Contains(bc.path, "node_modules") {
					b.Fatal("unexpected match result")
				}
			}
		})
	}
}

func mustParseB(b *testing.B, text string) RuleSet {
	b.Helper()
	rs, err := Parse([]byte(text))
	if err != nil {
		b.Fatal(err)
	}
	return rs
}

// TestMatchRuleIsDeterministic pins that overlapping rules report a stable
// decision, since `portablefs route` prints it.
func TestMatchRuleIsDeterministic(t *testing.T) {
	rs := mustParse(t, "node_*/\n**/node_?odules/\n")
	root, rule, ok := rs.MatchRule("a/node_modules/pkg")
	if !ok || root != "a/node_modules" {
		t.Fatalf("MatchRule = (%q,%q,%v)", root, rule, ok)
	}
	for i := 0; i < 16; i++ {
		if _, again, _ := rs.MatchRule("a/node_modules/pkg"); again != rule {
			t.Fatalf("MatchRule reported %q then %q", rule, again)
		}
	}
	if rule != "**/node_*/" {
		t.Fatalf("rule = %q, want the first in canonical order", rule)
	}
}

func TestGlobMatchComponentScope(t *testing.T) {
	for _, tc := range []struct {
		pat, name string
		want      bool
	}{
		{"*", "anything", true},
		{"*", "", true},
		{"a*c", "abc", true},
		{"a*c", "ac", true},
		{"a*c", "abcd", false},
		{"?", "a", true},
		{"?", "ab", false},
		{"a?c", "abc", true},
		{"*.tmp.d", "x.tmp.d", true},
		{"*.tmp.d", "x.tmp.dd", false},
	} {
		if got := globMatch(tc.pat, tc.name); got != tc.want {
			t.Fatalf("globMatch(%q,%q) = %v", tc.pat, tc.name, got)
		}
	}
}

func TestPatternsAreStable(t *testing.T) {
	rs := mustParse(t, "target/\nnode_modules/\n/vendor/\n")
	want := "**/node_modules/ **/target/ /vendor/"
	if got := strings.Join(rs.Patterns(), " "); got != want {
		t.Fatalf("patterns = %q want %q", got, want)
	}
	if fmt.Sprintf("%x", rs.Revision()) != rs.RevisionHex() {
		t.Fatal("RevisionHex must render Revision")
	}
}
