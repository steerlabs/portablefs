package localroutes

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"
)

// ConfigPath is the in-volume declaration file every client reads.
const ConfigPath = ".portablefs/local-dirs"

// Protected names are unroutable by construction; see the package doc for the
// exact language rule. ".git" keeps version control on the shared volume (a
// machine-local .git would fork history per machine); ".portablefs" keeps the
// declaration itself — and anything else the volume publishes to clients —
// out of reach of the rules it declares.
const (
	ProtectedGit        = ".git"
	ProtectedPortableFS = ".portablefs"
)

// Protected reports whether one path component is in the protected namespace.
// It is the single definition every other check defers to.
func Protected(name string) bool {
	return name == ProtectedGit || name == ProtectedPortableFS
}

// Error is one rejected line of a rule set. Parse fails on the first one: a
// rule set is accepted or refused as a whole, never partially applied.
type Error struct {
	Line   int    // 1-based line number in the parsed source
	Text   string // the offending line, whitespace-trimmed
	Reason string
}

func (e *Error) Error() string {
	return fmt.Sprintf("line %d: %s: %q", e.Line, e.Reason, e.Text)
}

// component is one compiled path component of a rule.
type component struct {
	globstar bool   // "**": matches zero or more complete components
	lit      string // literal component text (pat == "")
	pat      string // wildcard pattern, when the component holds '*' or '?'
}

func (c component) match(name string) bool {
	if c.pat == "" {
		return c.lit == name
	}
	return globMatch(c.pat, name)
}

// rule is one compiled directory rule. Floating rules carry a leading
// globstar component, so matching is uniformly "match the whole component
// sequence" and floating-ness is only a rendering and precompilation concern.
type rule struct {
	text     string      // canonical text
	comps    []component // including the leading globstar of a floating rule
	floating bool
	literal  []string // component names when the rule is wildcard-free; else nil
}

// core is the immutable compiled rule set. RuleSet is a one-word handle over
// it so callers can pass rule sets by value on hot paths.
type core struct {
	rules []rule
	// floatLit maps a directory NAME to the wildcard-free single-component
	// floating rule that routes it — the shape essentially every real
	// declaration uses ("node_modules/", ".venv/", "target/").
	floatLit map[string]int
	// anchoredLit maps a full volume-relative path to its wildcard-free
	// anchored rule.
	anchoredLit map[string]int
	// general lists the rules that need the component matcher (globs, and
	// floating rules with more than one component).
	general   []int
	canonical []byte
	revision  [32]byte
}

// RuleSet is a parsed, validated, precompiled rule set. The zero value is the
// empty rule set: it matches nothing, which is exactly what a volume with no
// declaration and no --local-dir flags gets.
type RuleSet struct {
	c *core
}

// Parse compiles a rule set. Sources may be concatenated before parsing (the
// canonical form is order-independent), which is how per-machine --local-dir
// additions join the volume's declaration in one revision.
func Parse(data []byte) (RuleSet, error) {
	var (
		byText = map[string]rule{}
		order  []string
	)
	for i, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSuffix(raw, "\r")
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		r, err := compileRule(line)
		if err != nil {
			err.Line = i + 1
			return RuleSet{}, err
		}
		if _, dup := byText[r.text]; !dup {
			byText[r.text] = r
			order = append(order, r.text)
		}
	}
	if len(order) == 0 {
		return RuleSet{}, nil
	}
	sort.Strings(order)
	kept := make([]rule, 0, len(order))
	for _, text := range order {
		r := byText[text]
		if subsumed(r, byText) {
			// The topmost match owns the whole subtree, so a rule whose root
			// already sits inside another rule's subtree can never be
			// consulted. Dropping it is what makes {a} and {a, a/b} one
			// revision.
			continue
		}
		kept = append(kept, r)
	}
	return newCore(kept), nil
}

// LiteralPattern renders one workspace-relative directory path as an anchored
// rule, for --local-dir flags and any other caller that means a literal path
// rather than a pattern. Metacharacters are refused rather than quoted: the
// language has no escape syntax (see the package doc), so a value containing
// one could only be read back as a pattern.
func LiteralPattern(p string) (string, error) {
	trimmed := strings.TrimSpace(p)
	if trimmed == "" {
		return "", fmt.Errorf("local dir must not be empty")
	}
	if trimmed != p {
		return "", fmt.Errorf("local dir %q cannot preserve leading or trailing whitespace in %s", p, ConfigPath)
	}
	if strings.ContainsAny(trimmed, "*?[]\\") {
		return "", fmt.Errorf("local dir %q must be a literal path; write patterns in %s", p, ConfigPath)
	}
	// '#' begins a rule-file comment and a newline would mint another rule.
	// NUL cannot name a host-filesystem component. The rule language has no
	// quoting or escaping, so accepting any of them here would make the literal
	// change meaning when its rendered form is parsed again.
	if strings.ContainsAny(trimmed, "#\n\x00") {
		return "", fmt.Errorf("local dir %q cannot be represented literally in %s", p, ConfigPath)
	}
	r, err := compileRule("/" + strings.Trim(trimmed, "/") + "/")
	if err != nil {
		return "", fmt.Errorf("local dir %q: %s", p, err.Reason)
	}
	return r.text, nil
}

// compileRule validates and compiles one non-blank, non-comment line.
func compileRule(line string) (rule, *Error) {
	fail := func(reason string) (rule, *Error) {
		return rule{}, &Error{Text: line, Reason: reason}
	}
	switch {
	case !utf8.ValidString(line):
		return fail("rule is not valid UTF-8 and cannot survive JSON state persistence")
	case strings.ContainsRune(line, '\x00'):
		return fail("NUL cannot occur in a filesystem path")
	case strings.HasPrefix(line, "!"):
		return fail("negation is not supported: a local subtree is served entirely from local disk, so routing must stay prefix-closed")
	case strings.ContainsAny(line, "[]"):
		return fail("character classes are not supported")
	case strings.Contains(line, `\`):
		return fail("backslash is not supported (no escapes, and paths use '/')")
	}
	body := line
	anchored := false
	if strings.HasPrefix(body, "/") {
		anchored = true
		body = body[1:]
	}
	body = strings.TrimSuffix(body, "/")
	if body == "" {
		return fail("rule would route the volume root")
	}
	if !anchored {
		// .gitignore's anchoring rule: a separator anywhere but at the end
		// pins the rule to the volume root, unless it is the "**/" prefix
		// that explicitly asks for any depth.
		anchored = strings.Contains(body, "/") && !strings.HasPrefix(body, "**/")
	}
	parts := strings.Split(body, "/")
	comps := make([]component, 0, len(parts)+1)
	for _, part := range parts {
		switch {
		case part == "":
			return fail("empty path component")
		case part == "." || part == "..":
			return fail("rule must not contain '.' or '..' components")
		case Protected(part):
			return fail(fmt.Sprintf("%q is a protected name and can never be routed", part))
		case part == "**":
			if len(comps) > 0 && comps[len(comps)-1].globstar {
				continue // consecutive "**" mean the same as one
			}
			comps = append(comps, component{globstar: true})
			continue
		case strings.Contains(part, "**"):
			return fail("'**' must be a whole path component")
		}
		if strings.ContainsAny(part, "*?") {
			comps = append(comps, component{pat: part})
			continue
		}
		comps = append(comps, component{lit: part})
	}
	// A leading "**" is exactly the floating form, whichever way the line was
	// written ("/**/x/" and "**/x/" and "x/" are one rule).
	if comps[0].globstar {
		anchored = false
		comps = comps[1:]
	}
	if len(comps) == 0 || allGlobstar(comps) {
		return fail("rule would route the volume root")
	}
	r := rule{floating: !anchored}
	// "Wildcard-free" is decided AFTER the floating prefix is stripped: an
	// interior "**" (services/**/dist/) is a wildcard like any other, while
	// the leading one is just how a floating rule is spelled.
	if literal, ok := literalComps(comps); ok {
		r.literal = literal
	}
	texts := make([]string, 0, len(comps))
	for _, c := range comps {
		switch {
		case c.globstar:
			texts = append(texts, "**")
		case c.pat != "":
			texts = append(texts, c.pat)
		default:
			texts = append(texts, c.lit)
		}
	}
	if r.floating {
		r.text = "**/" + strings.Join(texts, "/") + "/"
		r.comps = append([]component{{globstar: true}}, comps...)
	} else {
		r.text = "/" + strings.Join(texts, "/") + "/"
		r.comps = comps
	}
	return r, nil
}

// literalComps returns the component names when every component is a literal
// (no '*', '?' or '**'), which is what lets a rule be precompiled into a map
// and reasoned about for subsumption.
func literalComps(comps []component) ([]string, bool) {
	out := make([]string, 0, len(comps))
	for _, c := range comps {
		if c.globstar || c.pat != "" {
			return nil, false
		}
		out = append(out, c.lit)
	}
	return out, true
}

func allGlobstar(comps []component) bool {
	for _, c := range comps {
		if !c.globstar {
			return false
		}
	}
	return true
}

// subsumed reports whether r's root is already inside another rule's subtree,
// which makes r unreachable. Only wildcard-free rules are decided: their root
// path (or, for a floating rule, its component tail) is concrete, so the
// question is a finite check rather than a guess about glob containment.
func subsumed(r rule, all map[string]rule) bool {
	if r.literal == nil {
		return false
	}
	for text, other := range all {
		if text == r.text {
			continue
		}
		if matchesAncestorOf(other, r) {
			return true
		}
	}
	return false
}

// matchesAncestorOf reports whether other routes r's root or a proper
// ancestor of it. For an anchored r the candidates are its literal prefixes,
// which are concrete paths. For a floating r they are the prefixes of its
// component tail, and only a floating other can be trusted: a floating rule
// matches a SUFFIX of a path, so if it matches the tail's prefix it matches
// that prefix at every depth r can occur at, while an anchored rule says
// nothing about the depths r reaches.
func matchesAncestorOf(other, r rule) bool {
	if r.floating && !other.floating {
		return false
	}
	for i := 1; i <= len(r.literal); i++ {
		if matchComps(other.comps, r.literal[:i]) {
			return true
		}
	}
	return false
}

func newCore(rules []rule) RuleSet {
	c := &core{
		rules:       rules,
		floatLit:    make(map[string]int, len(rules)),
		anchoredLit: make(map[string]int, len(rules)),
	}
	var buf strings.Builder
	for i, r := range rules {
		buf.WriteString(r.text)
		buf.WriteByte('\n')
		switch {
		case r.literal != nil && r.floating && len(r.literal) == 1:
			c.floatLit[r.literal[0]] = i
		case r.literal != nil && !r.floating:
			c.anchoredLit[strings.Join(r.literal, "/")] = i
		default:
			c.general = append(c.general, i)
		}
	}
	c.canonical = []byte(buf.String())
	c.revision = sha256.Sum256(c.canonical)
	return RuleSet{c: c}
}

// Empty reports whether the set routes nothing.
func (rs RuleSet) Empty() bool { return rs.c == nil || len(rs.c.rules) == 0 }

// Patterns returns the canonical rule texts, sorted.
func (rs RuleSet) Patterns() []string {
	if rs.c == nil {
		return nil
	}
	out := make([]string, 0, len(rs.c.rules))
	for _, r := range rs.c.rules {
		out = append(out, r.text)
	}
	return out
}

// Canonical renders the rule set as the exact bytes Revision hashes.
func (rs RuleSet) Canonical() []byte {
	if rs.c == nil {
		return nil
	}
	return append([]byte(nil), rs.c.canonical...)
}

// Revision is SHA-256 over Canonical(). The authority compares it against the
// volume's active revision, so it must depend on the routing and on nothing
// else — not on line order, not on comments, not on which source contributed
// a rule.
func (rs RuleSet) Revision() [32]byte {
	if rs.c == nil {
		return sha256.Sum256(nil)
	}
	return rs.c.revision
}

// RevisionHex is Revision() as lowercase hex, the form state records and the
// authority handshake carry.
func (rs RuleSet) RevisionHex() string {
	rev := rs.Revision()
	return hex.EncodeToString(rev[:])
}

// Match returns the topmost route root that owns p ("" and false when p is
// served by the shared volume). p is a volume-relative, cleaned, slash
// separated path; "" (the volume root) never matches.
func (rs RuleSet) Match(p string) (string, bool) {
	root, _, ok := rs.MatchRule(p)
	return root, ok
}

// MatchRule is Match plus the canonical text of the rule that decided it, for
// diagnostics (`portablefs route`). When several rules match the same root the
// first in canonical order is reported, so the answer is deterministic.
func (rs RuleSet) MatchRule(p string) (root string, rule string, matched bool) {
	if rs.c == nil || len(rs.c.rules) == 0 || p == "" {
		return "", "", false
	}
	var comps []string
	if len(rs.c.general) > 0 {
		comps = make([]string, 0, 12)
	}
	start := 0
	for i := 0; i <= len(p); i++ {
		if i < len(p) && p[i] != '/' {
			continue
		}
		name := p[start:i]
		start = i + 1
		if name == "" || name == "." || name == ".." || Protected(name) {
			// Malformed or protected: unroutable by construction, and never
			// reachable through a wildcard either.
			return "", "", false
		}
		best := -1
		if idx, ok := rs.c.floatLit[name]; ok {
			best = idx
		}
		if idx, ok := rs.c.anchoredLit[p[:i]]; ok && (best < 0 || idx < best) {
			best = idx
		}
		if comps != nil {
			comps = append(comps, name)
			for _, idx := range rs.c.general {
				if best >= 0 && idx > best {
					break // rules are stored in canonical order
				}
				if matchComps(rs.c.rules[idx].comps, comps) {
					best = idx
					break
				}
			}
		}
		if best >= 0 {
			return p[:i], rs.c.rules[best].text, true
		}
	}
	return "", "", false
}

// SubtreeKey encodes what the rule set can still do BELOW p: the set of
// partially matched rule positions after consuming p's components. Two paths
// with the same key route every descendant identically, which is how a rename
// of a shared directory is checked for silently flipping ownership without
// enumerating the subtree. It is conservative in the safe direction: equal
// keys prove equal routing, unequal keys may still be equivalent, and the
// caller refuses the rename either way.
func (rs RuleSet) SubtreeKey(p string) string {
	if rs.c == nil || len(rs.c.rules) == 0 {
		return ""
	}
	state := make([]uint64, 0, len(rs.c.rules)*2)
	for i := range rs.c.rules {
		state = append(state, pos(i, 0))
	}
	state = rs.closure(state)
	for _, name := range splitPath(p) {
		if name == "" || name == "." || name == ".." || Protected(name) {
			// Nothing below a protected (or malformed) path is ever routed;
			// "dead" is a state of its own, distinct from "no rule pending".
			return "!"
		}
		state = rs.closure(rs.step(state, name))
		if len(state) == 0 {
			break
		}
	}
	parts := make([]string, 0, len(state))
	for _, s := range state {
		parts = append(parts, fmt.Sprintf("%d.%d", s>>32, uint32(s)))
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

func pos(rule, idx int) uint64 { return uint64(rule)<<32 | uint64(uint32(idx)) }

// closure adds the positions reachable by letting a "**" match zero
// components.
func (rs RuleSet) closure(state []uint64) []uint64 {
	out := make([]uint64, 0, len(state)*2)
	seen := make(map[uint64]bool, len(state)*2)
	var add func(uint64)
	add = func(s uint64) {
		if seen[s] {
			return
		}
		seen[s] = true
		out = append(out, s)
		ri, idx := int(s>>32), int(uint32(s))
		comps := rs.c.rules[ri].comps
		if idx < len(comps) && comps[idx].globstar {
			add(pos(ri, idx+1))
		}
	}
	for _, s := range state {
		add(s)
	}
	return out
}

// step consumes one path component.
func (rs RuleSet) step(state []uint64, name string) []uint64 {
	out := make([]uint64, 0, len(state))
	seen := make(map[uint64]bool, len(state))
	push := func(s uint64) {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	for _, s := range state {
		ri, idx := int(s>>32), int(uint32(s))
		comps := rs.c.rules[ri].comps
		if idx >= len(comps) {
			continue // already accepted; nothing deeper to track
		}
		if comps[idx].globstar {
			push(s)
			continue
		}
		if comps[idx].match(name) {
			push(pos(ri, idx+1))
		}
	}
	return out
}

func splitPath(p string) []string {
	if p == "" {
		return nil
	}
	return strings.Split(p, "/")
}

// matchComps reports whether a rule's component sequence matches comps
// exactly, with "**" spanning zero or more components. The greedy scan with
// one backtrack point is the standard globstar match; rule sequences hold at
// most one useful backtrack point in practice, and both sequences are short.
func matchComps(pat []component, comps []string) bool {
	var pi, ci int
	star, mark := -1, 0
	for ci < len(comps) {
		switch {
		case pi < len(pat) && pat[pi].globstar:
			star, mark = pi, ci
			pi++
		case pi < len(pat) && pat[pi].match(comps[ci]):
			pi++
			ci++
		case star >= 0:
			mark++
			pi = star + 1
			ci = mark
		default:
			return false
		}
	}
	for pi < len(pat) && pat[pi].globstar {
		pi++
	}
	return pi == len(pat)
}

// globMatch matches one path component against a '*'/'?' pattern. Bytes are
// compared exactly: '?' is one byte, and there is no case folding.
func globMatch(pat, name string) bool {
	var pi, ni int
	star, mark := -1, 0
	for ni < len(name) {
		switch {
		case pi < len(pat) && pat[pi] == '*':
			star, mark = pi, ni
			pi++
		case pi < len(pat) && (pat[pi] == '?' || pat[pi] == name[ni]):
			pi++
			ni++
		case star >= 0:
			mark++
			pi = star + 1
			ni = mark
		default:
			return false
		}
	}
	for pi < len(pat) && pat[pi] == '*' {
		pi++
	}
	return pi == len(pat)
}
