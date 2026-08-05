// Package localroutes implements the directory-pattern language that declares
// machine-local directory routes: the directories (node_modules, .venv,
// target, …) a volume asks every client to serve from per-machine disk instead
// of from the shared authority volume. The declaration lives at
// ".portablefs/local-dirs" in the volume; localdirs turns the matched roots
// into grafts, and the authority pins a mount to the revision of the rule set
// it activated.
//
// # The language
//
// One rule per line. Blank lines are ignored; '#' begins a comment that runs
// to the end of the line. Every rule names a DIRECTORY — there are no file
// routes, and a rule never creates anything: it routes a name when the name is
// created or encountered.
//
//   - "/foo/" is ANCHORED: it matches only the volume-root directory foo.
//   - "foo/" is FLOATING: it matches a directory named foo at ANY depth.
//   - a rule with a '/' anywhere but at the end is anchored ("a/b/" is the
//     volume-root a's child b), exactly like .gitignore; a leading "**/" makes
//     a multi-component rule floating again ("**/a/b/").
//   - '*' matches any run of bytes within ONE component, '?' matches exactly
//     one byte within one component, and '**' — which must be a whole
//     component — matches zero or more complete components.
//   - matching is byte-exact and case-sensitive: no case folding, no Unicode
//     normalization, no locale.
//   - the TOPMOST matching directory owns its entire subtree, so rules are
//     order-independent and the set is a plain union.
//
// Deliberately absent, because routing must stay prefix-closed — a path is
// local if and only if some ancestor-or-self matches, with no exceptions
// carved out beneath it: '!' negation, character classes, and backslash
// escapes are refused rather than silently reinterpreted.
//
// # The protected namespace
//
// Two names are structurally unroutable, and the rule is a property of the
// LANGUAGE rather than a filter applied to results:
//
//	No route root ever has a component equal to ".git" or ".portablefs" —
//	matching stops dead at such a component instead of expanding a wildcard
//	over it — and no rule may name one of those components literally.
//
// The first half makes wildcards safe by construction: '*', '?' and '**'
// cannot expand to a protected component, so "**/objects/" can never route
// ".git/objects" no matter how deep the repository is, and no wildcard rule
// can shadow the volume's own declaration under ".portablefs". The volume's
// own ".git" and ".portablefs" sit at the volume root, whose only ancestor is
// the volume root itself — which no rule may match — so version control and
// the declaration are always served by the shared volume. (Routing stays
// prefix-closed, so a protected name BELOW a route root is inside that root's
// subtree and travels with it: a vendored repository inside node_modules is
// machine-local along with the rest of node_modules. Prefix closure is the
// invariant; carving a shared hole inside a local subtree is not an option.)
// The second half keeps the first from hiding mistakes: a rule that spells
// ".git" out could only ever be dead, so it is a parse error instead of a
// silent no-op.
// Everything else that could route the wrong thing is refused at parse time
// too — a rule matching the volume root (a rule made only of "**"), an
// absolute path, or a path escaping the volume (".", ".."). Validation
// rejects the WHOLE rule set: a mount either serves the declared routing or
// refuses to start, because a partially applied rule set has a revision that
// describes a file nobody is enforcing.
//
// # Canonical form and revision
//
// Canonical() renders the rule set as sorted, deduplicated, fully explicit
// lines, and Revision() is SHA-256 over exactly those bytes. Two textually
// different files that declare the same routing hash equal. Precisely, the
// canonical form:
//
//   - drops comments, blank lines, surrounding whitespace, and CR of CRLF;
//   - spells anchoring out: "/a/b/" for anchored rules, "**/a/b/" for
//     floating ones, so "node_modules", "node_modules/" and
//     "**/node_modules/" are one rule, and "/**/x/" is the floating "**/x/";
//   - always ends a rule with '/' (every rule is a directory rule);
//   - collapses consecutive "**" components;
//   - drops a wildcard-free rule whose root, or any proper ancestor of it, is
//     already routed by another rule (the topmost match owns the subtree, so
//     the inner rule can never be consulted);
//   - sorts the surviving lines bytewise and removes duplicates.
//
// Rules containing wildcards are never dropped as redundant: deciding
// subsumption between two glob patterns is not something this package will
// guess at, so it keeps both. That is the only way two semantically identical
// files can still hash differently, and it is deliberate.
//
// # Matching cost
//
// Match runs on the mkdir/lookup hot path — an npm install creates tens of
// thousands of directories — so rules are precompiled by shape: wildcard-free
// single-component floating rules into a name map, wildcard-free anchored
// rules into a full-path map, and only the remaining glob rules into a linear
// scan that is skipped entirely when there are none. A realistic rule set
// (all names, no globs) costs one map lookup per path component and allocates
// nothing.
package localroutes
