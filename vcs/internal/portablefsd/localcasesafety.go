package portablefsd

// ── THE GRAFT BACKING MUST BE AS CASE-EXACT AS THE VOLUME IT SHADOWS ────────
//
// The shared namespace is byte-exact. The authority is XFS and its directory
// matching compares raw bytes, so `node_modules/React` and `node_modules/react`
// are two different names holding two different inodes.
//
// A macOS graft serves that same namespace from a machine-local directory
// (localdirs.go), and on a stock Mac that directory lives on APFS, which is
// case-INSENSITIVE by default and additionally normalization-insensitive: it
// matches NFC and NFD spellings of the same string as one name. Grafting a
// case-exact namespace onto a folding backing is not a degraded experience, it
// is silent data loss. Both names resolve, both are enumerated by whatever
// created them, and one file quietly holds the other's contents. Nothing above
// this layer can detect it: the daemon asked for two names and the host said
// yes twice.
//
// So this is an activation invariant rather than a doctor warning. Before any
// graft rule can route a single operation to machine-local backing, the backing
// is PROBED - two case-colliding names and two Unicode-colliding names are
// really created in a private directory inside the backing root and the result
// is observed - and activation is refused if the host folds either one.
//
// The probe creates names rather than reading volume attributes on purpose.
// `statfs`, `getattrlist(ATTR_VOL_CAPABILITIES)` and the APFS container's
// recorded case sensitivity all describe the volume the path started on. A
// backing root can sit under a bind/firmlink, a symlinked state dir, a network
// or FUSE mount, or a case-sensitive volume mounted inside a case-insensitive
// one, and in each of those the attribute answers for the wrong filesystem. The
// only thing that answers for the actual backing is the actual backing.
//
// ── WHY REFUSAL IS THE ROOT FIX ON macOS, NOT A WORKAROUND ──────────────────
//
// The backing location IS chosen by this code: attach.localRoot is
// <stateDir>/local/<storageID>, and stateDir is the daemon's `-state-dir`. So
// the preferred repair would be for the daemon to select a case-sensitive
// location itself. It cannot, without privileges or a workaround this project
// rejects:
//
//   - making an existing APFS volume case-sensitive is not an operation; case
//     sensitivity is fixed when the volume is formatted;
//   - adding a case-sensitive APFS volume to the running container
//     (`diskutil apfs addVolume ... -caseSensitive`) requires administrator
//     authorization, so a user-session daemon cannot do it;
//   - a case-sensitive sparse bundle / disk image would work and is explicitly
//     not acceptable: it introduces a second filesystem, its own fsync and
//     free-space semantics, an attach/detach lifecycle, and a failure mode
//     where the user's dependency tree lives inside a file the user does not
//     know exists.
//
// With no unprivileged case-sensitive location to select, the root fix IS the
// refusal: state the invariant, name the path that violated it, and tell the
// operator exactly what to provide. An operator who provides a case-sensitive
// APFS volume and points `-state-dir` at it gets grafts; nobody gets a mount
// that reports two names and stores one file.

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/confinedfs"
)

// ErrBackingCaseUnsafe means the machine-local backing filesystem folds names
// that the shared namespace keeps distinct. Graft activation refuses.
var ErrBackingCaseUnsafe = errors.New("portablefsd: machine-local backing filesystem is not case-exact")

// ErrBackingProbeIncomplete means the probe could not reach a verdict - the
// backing root vanished, the host refused the writes, or a probe step failed
// for a reason that says nothing about case behavior. It is deliberately NOT
// ErrBackingCaseUnsafe: an unfinished probe must never be reported as a
// case-folding backing, and it must never be reported as a safe one either.
var ErrBackingProbeIncomplete = errors.New("portablefsd: could not determine machine-local backing case behavior")

const (
	// caseProbePrefix names the private probe directory. It is dotted and
	// carries the product name so an operator who finds a leftover after a
	// crash knows what made it.
	caseProbePrefix = ".portablefs-case-probe-"
	// caseProbeNonceHex is the exact length of the random suffix. Sweeping
	// leftovers matches on the exact shape so a graft rule that merely starts
	// with the prefix can never be deleted by the probe.
	caseProbeNonceHex = 32
	caseProbeAttempts = 8
)

// The two colliding pairs. Each pair is one name in two spellings that the
// shared namespace keeps apart and a folding host does not.
const (
	// ASCII case: the exact collision that breaks `node_modules/React`.
	caseProbeUpper = "Probe"
	caseProbeLower = "probe"
	// Unicode composition: "café" precomposed (U+00E9) and decomposed
	// (e + U+0301). APFS matches these as one name; XFS does not.
	// Both are spelled with explicit \u escapes so that no editor, gofmt run,
	// or patch tool can normalize the two constants into identical bytes and
	// silently turn this half of the probe into a tautology.
	caseProbeNFC = "caf\u00e9"
	caseProbeNFD = "cafe\u0301"
)

const (
	caseProbeUpperBody = "upper"
	caseProbeLowerBody = "lower"
	caseProbeNFCBody   = "nfc"
	caseProbeNFDBody   = "nfd"
)

// verifyBackingCaseSafety is the activation gate. It returns nil only when the
// backing really distinguished every colliding pair the probe created.
//
// backingPath is the host path of the capability, used only to make the refusal
// name the directory an operator has to change. The probe itself never joins
// it: every step goes through the capability.
func verifyBackingCaseSafety(root *confinedfs.Root, backingPath string) error {
	if root == nil {
		return fmt.Errorf("%w: no backing capability", ErrBackingProbeIncomplete)
	}
	sweepStaleCaseProbes(root)
	dir, err := makeCaseProbeDir(root)
	if err != nil {
		return fmt.Errorf("%w: create a private probe directory under %s: %v",
			ErrBackingProbeIncomplete, backingPath, err)
	}
	// The probe cleans up after itself on every exit, including the refusal
	// path and the incomplete path. A mount that refused to activate must not
	// leave anything behind in a directory the user may still be using.
	defer removeCaseProbeDir(root, dir)

	if err := probeFoldingPair(root, dir, backingPath,
		caseProbeUpper, caseProbeLower, caseProbeUpperBody, caseProbeLowerBody,
		"case", "differ only in letter case"); err != nil {
		return err
	}
	return probeFoldingPair(root, dir, backingPath,
		caseProbeNFC, caseProbeNFD, caseProbeNFCBody, caseProbeNFDBody,
		"Unicode normalization", "are the precomposed and decomposed spellings of the same text")
}

// probeFoldingPair creates one colliding pair and observes four independent
// symptoms of folding. Any single one is conclusive, and they are all checked
// because a host can fold at lookup, at create, or only in enumeration.
func probeFoldingPair(
	root *confinedfs.Root,
	dir, backingPath string,
	first, second, firstBody, secondBody string,
	kind, why string,
) error {
	firstPath := dir + "/" + first
	secondPath := dir + "/" + second

	if err := root.WriteFile(firstPath, []byte(firstBody), 0o600); err != nil {
		return fmt.Errorf("%w: write the %s probe name %q under %s: %v",
			ErrBackingProbeIncomplete, kind, first, backingPath, err)
	}
	// The file just written must be findable under its own name. If it is not,
	// the backing changed underneath the probe (the root was deleted, the
	// volume went away) and no verdict is available. Reporting "case-folding"
	// here would refuse activation for the wrong reason.
	if _, err := root.Lstat(firstPath); err != nil {
		return fmt.Errorf("%w: the %s probe name %q disappeared immediately after it was created under %s: %v",
			ErrBackingProbeIncomplete, kind, first, backingPath, err)
	}

	// Symptom 1: the other spelling already resolves, though nothing created it.
	switch _, err := root.Lstat(secondPath); {
	case err == nil:
		return foldingRefusal(backingPath, kind, why,
			fmt.Sprintf("%q resolved to the file created as %q, though nothing created %q", second, first, second))
	case errors.Is(err, fs.ErrNotExist):
		// Distinct so far.
	default:
		return fmt.Errorf("%w: look up the %s probe name %q under %s: %v",
			ErrBackingProbeIncomplete, kind, second, backingPath, err)
	}

	if err := root.WriteFile(secondPath, []byte(secondBody), 0o600); err != nil {
		return fmt.Errorf("%w: write the %s probe name %q under %s: %v",
			ErrBackingProbeIncomplete, kind, second, backingPath, err)
	}

	// Symptom 2: creating the second spelling overwrote the first file.
	body, err := root.ReadFile(firstPath)
	if err != nil {
		return fmt.Errorf("%w: read back the %s probe name %q under %s: %v",
			ErrBackingProbeIncomplete, kind, first, backingPath, err)
	}
	if string(body) != firstBody {
		return foldingRefusal(backingPath, kind, why,
			fmt.Sprintf("creating %q overwrote the contents of %q", second, first))
	}

	// Symptom 3 and 4: the directory must enumerate both names, byte for byte.
	// A host that stores one spelling and answers for both fails here even when
	// it kept the two files apart on lookup.
	entries, err := root.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("%w: enumerate the %s probe directory under %s: %v",
			ErrBackingProbeIncomplete, kind, backingPath, err)
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		seen[entry.Name()] = true
	}
	var missing []string
	for _, want := range []string{first, second} {
		if !seen[want] {
			missing = append(missing, fmt.Sprintf("%q", want))
		}
	}
	if len(missing) != 0 {
		return foldingRefusal(backingPath, kind, why,
			fmt.Sprintf("the probe directory enumerated %d entries and did not return %s exactly as created",
				len(entries), strings.Join(missing, " and ")))
	}
	return nil
}

// foldingRefusal builds the refusal an operator actually has to act on: what
// was observed, why it is fatal rather than cosmetic, and the one change that
// fixes it.
func foldingRefusal(backingPath, kind, why, observed string) error {
	return fmt.Errorf(
		"%w: the machine-local graft backing at %s folds names by %s (%s). "+
			"The PortableFS shared namespace is byte-exact, so two names that %s are two files on the volume "+
			"but one file in this backing: the mount would report both as existing while one silently overwrote the other. "+
			"Machine-local dirs are refused for this attach. "+
			"Provide a case-sensitive backing volume and point the daemon at it with "+
			"`portablefsd -state-dir <directory-on-a-case-sensitive-volume>`. "+
			"On macOS that means a volume formatted APFS (Case-sensitive): an existing case-insensitive APFS volume "+
			"cannot be converted, creating a case-sensitive volume needs administrator authorization, "+
			"and a case-sensitive disk image is deliberately not accepted as a substitute",
		ErrBackingCaseUnsafe, backingPath, kind, observed, why)
}

// makeCaseProbeDir creates a private directory with an unpredictable name. A
// collision with something already present is retried rather than reused: the
// probe must never observe a name it did not create, because a pre-existing
// `probe` next to a pre-existing `Probe` would read as a case-sensitive backing
// for free.
func makeCaseProbeDir(root *confinedfs.Root) (string, error) {
	var lastErr error
	for range caseProbeAttempts {
		var nonce [caseProbeNonceHex / 2]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return "", err
		}
		name := caseProbePrefix + hex.EncodeToString(nonce[:])
		err := root.Mkdir(name, 0o700)
		if err == nil {
			return name, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", err
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("exhausted probe directory name attempts")
	}
	return "", lastErr
}

// removeCaseProbeDir deletes the probe directory and everything the probe put
// in it. Failures are ignored deliberately: the caller is already returning a
// verdict, and a backing that vanished mid-probe has nothing left to clean.
func removeCaseProbeDir(root *confinedfs.Root, dir string) {
	entries, err := root.ReadDir(dir)
	if err == nil {
		for _, entry := range entries {
			_ = root.Remove(dir + "/" + entry.Name())
		}
	}
	_ = root.Remove(dir)
}

// sweepStaleCaseProbes removes probe directories a previous crashed run left
// behind. The match is on the exact shape - prefix plus exactly
// caseProbeNonceHex lowercase hex digits - so no graft rule an operator could
// plausibly configure is ever deleted by this.
func sweepStaleCaseProbes(root *confinedfs.Root) {
	entries, err := root.ReadDir(".")
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() || !isCaseProbeDirName(entry.Name()) {
			continue
		}
		removeCaseProbeDir(root, entry.Name())
	}
}

func isCaseProbeDirName(name string) bool {
	if !strings.HasPrefix(name, caseProbePrefix) {
		return false
	}
	suffix := name[len(caseProbePrefix):]
	if len(suffix) != caseProbeNonceHex {
		return false
	}
	for i := range len(suffix) {
		c := suffix[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// openLocalBacking is the ONLY way this package acquires a graft backing
// capability. Opening and probing are one step on purpose: a *confinedfs.Root
// that exists but was never probed is exactly the object that would let a
// case-folding backing serve a byte-exact namespace, and keeping the two calls
// separate would make that a one-line mistake at any future call site.
//
// A refused probe closes the capability it opened, so a failed activation
// leaves no descriptor behind.
func openLocalBacking(backingPath string) (*confinedfs.Root, error) {
	root, err := confinedfs.Open(backingPath, 0o700)
	if err != nil {
		return nil, err
	}
	if err := verifyBackingCaseSafety(root, backingPath); err != nil {
		_ = root.Close()
		return nil, err
	}
	return root, nil
}
