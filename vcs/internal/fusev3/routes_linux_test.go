//go:build linux

package fusev3

import (
	"slices"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/localdirs"
)

// --- the rule set a mount activates, and the revision it declares ---

func TestActivateRoutesCompilesTheVolumeDeclarationAndNothingElse(t *testing.T) {
	rules, err := ActivateRoutes([]byte("node_modules/\n/target/\n"))
	if err != nil {
		t.Fatalf("ActivateRoutes = %v", err)
	}
	if root, matched := rules.Match("packages/app/node_modules/lodash"); !matched || root != "packages/app/node_modules" {
		t.Fatalf("Match under a floating rule = (%q, %v)", root, matched)
	}
	if root, matched := rules.Match("target/debug"); !matched || root != "target" {
		t.Fatalf("Match under an anchored rule = (%q, %v)", root, matched)
	}
	if root, matched := rules.Match("src/target"); matched {
		t.Fatalf("an anchored rule matched below the volume root at %q", root)
	}
}

func TestTheDeclaredRevisionDescribesTheRoutingAndNothingElse(t *testing.T) {
	plain, err := ActivateRoutes([]byte("node_modules/\n/target/\n"))
	if err != nil {
		t.Fatal(err)
	}
	// Comments, blank lines, order and duplication are all invisible to the
	// routing, so they must be invisible to the revision: two machines holding
	// the same declaration have to compute the same value, and the authority
	// recomputes it from the same file.
	noisy, err := ActivateRoutes([]byte("# machine-local\n\n/target/\nnode_modules/\nnode_modules/\n"))
	if err != nil {
		t.Fatal(err)
	}
	if plain.Revision() != noisy.Revision() {
		t.Fatalf("revision depends on the spelling of the declaration: %x vs %x", plain.Revision(), noisy.Revision())
	}
	empty, err := ActivateRoutes(nil)
	if err != nil {
		t.Fatal(err)
	}
	if !empty.Empty() {
		t.Fatal("a volume with no declaration compiled to a non-empty rule set")
	}
	if empty.Revision() == plain.Revision() {
		t.Fatal("routing nothing and routing something produced the same revision")
	}
}

// TestActivateRoutesAcceptsTheCanonicalFormExactly is what makes a fresh mount
// possible at all.
//
// A mount that has never seen a volume cannot read .portablefs/local-dirs
// without a session and cannot get a session without declaring the revision, so
// the authority breaks the circle by putting its ACTIVE CANONICAL RULES on the
// attach refusal. Adopting them is only sound if compiling those exact bytes
// reproduces the same routing and the same revision -- otherwise the mount would
// re-attach declaring a number it derived from something other than what it was
// handed, and the check that admits it would be checking nothing.
func TestActivateRoutesAcceptsTheCanonicalFormExactly(t *testing.T) {
	for name, declaration := range map[string]string{
		"nothing":  "",
		"one rule": "node_modules/\n",
		"several":  "node_modules/\n/target/\n**/build/\n",
		"noisy":    "# comment\n\n  /target/  \nnode_modules/\nnode_modules/\n",
		"subsumed": "node_modules/\nnode_modules/lodash/\n",
	} {
		t.Run(name, func(t *testing.T) {
			original, err := ActivateRoutes([]byte(declaration))
			if err != nil {
				t.Fatalf("compile %q: %v", declaration, err)
			}
			// This is the exact byte sequence an attach refusal carries.
			adopted, err := ActivateRoutes(original.Canonical())
			if err != nil {
				t.Fatalf("the canonical form of %q does not compile: %v", declaration, err)
			}
			if adopted.Revision() != original.Revision() {
				t.Fatalf("adopting the canonical form changed the revision: %x then %x", original.Revision(), adopted.Revision())
			}
			if !slices.Equal(adopted.Patterns(), original.Patterns()) {
				t.Fatalf("adopting the canonical form changed the routing: %v then %v", original.Patterns(), adopted.Patterns())
			}
			// And it is a fixed point, not merely equal once: a mount that
			// adopted twice would compute the same thing again.
			again, err := ActivateRoutes(adopted.Canonical())
			if err != nil || again.Revision() != original.Revision() {
				t.Fatalf("the canonical form is not a fixed point: %x, %v", again.Revision(), err)
			}
		})
	}
}

// --- the mount refuses to serve routes it has nowhere to put ---

func TestRoutesWithoutBackingAreRefusedRatherThanIgnored(t *testing.T) {
	rules, err := ActivateRoutes([]byte("node_modules/\n"))
	if err != nil {
		t.Fatal(err)
	}
	grafts, err := localdirs.New(localdirs.Config{Rules: rules})
	if err == nil {
		_ = grafts.Close()
		t.Fatal("routes with no machine-local backing were accepted; a route that cannot be served locally is not a route, and serving it from the authority writes per-machine content into shared storage")
	}
}

func TestNoRoutesMeansNoServingStateAtAll(t *testing.T) {
	grafts, err := localdirs.New(localdirs.Config{BackingRoot: t.TempDir()})
	if err != nil || grafts != nil {
		t.Fatalf("localdirs.New with no rules = (%v, %v), want (nil, nil) so the hot path stays a nil check", grafts, err)
	}
	if owner := grafts.Owner("anything"); owner != "" {
		t.Fatalf("a nil graft set claimed to own %q", owner)
	}
}
