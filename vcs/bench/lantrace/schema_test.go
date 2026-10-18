package lantrace

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"
)

func parseEvent(line string, layer Layer) error {
	rec, err := parseLine([]byte(line), false)
	if err != nil {
		return err
	}
	if rec.Record != recordEvent {
		return nil
	}
	return rec.checkEvent(layer)
}

func TestParseRejectsOutsideTheGrammar(t *testing.T) {
	const base = `"record":"event","seq":1,"t_ns":5,"kind":"callback","phase":"entry","callback":7,"callback_kind":"lookup"`
	ev := func(extra string) string { return "{" + base + extra + "}" }
	cases := []struct {
		name  string
		line  string
		layer Layer
		want  string
	}{
		{"unknown key", ev(`,"path":"/Users/someone/secret"`), LayerFrontend, "unknown key"},
		{"case-folded key", `{"record":"event","seq":1,"t_ns":5,"Kind":"callback","phase":"entry","callback":7,"callback_kind":"lookup"}`, LayerFrontend, "unknown key"},
		{"duplicate key", ev(`,"callback_kind":"open"`), LayerFrontend, "duplicate key"},
		{"nested object", ev(`,"item":{"id":1}`), LayerFrontend, "strings, numbers or booleans"},
		{"array value", ev(`,"item":[1]`), LayerFrontend, "strings, numbers or booleans"},
		{"null value", ev(`,"item":null`), LayerFrontend, "strings, numbers or booleans"},
		{"free text in category", `{"record":"event","seq":1,"t_ns":5,"kind":"callback","phase":"entry","callback":7,"callback_kind":"lookup of /tmp/x token=abc"}`, LayerFrontend, "invalid value"},
		{"category case variant", `{"record":"event","seq":1,"t_ns":5,"kind":"callback","phase":"entry","callback":7,"callback_kind":"Lookup"}`, LayerFrontend, "invalid value"},
		{"label with space", ev(`,"mount":"my mount"`), LayerFrontend, "invalid value"},
		{"label with slash", ev(`,"mount":"a/b"`), LayerFrontend, "invalid value"},
		{"label leading digit", ev(`,"mount":"1a"`), LayerFrontend, "invalid value"},
		{"label too long", ev(`,"mount":"` + "m" + strings.Repeat("a", MaxLabelBytes) + `"`), LayerFrontend, "invalid value"},
		{"hex uppercase", ev(`,"name_hex":"AB"`), LayerFrontend, "invalid value"},
		{"hex odd length", ev(`,"name_hex":"abc"`), LayerFrontend, "invalid value"},
		{"hex not hex", ev(`,"name_hex":"zz"`), LayerFrontend, "invalid value"},
		{"hex oversized", ev(`,"name_hex":"` + strings.Repeat("ab", MaxNameBytes+1) + `"`), LayerFrontend, "invalid value"},
		{"explicit zero integer", ev(`,"conn":0`), LayerFrontend, "explicit zero"},
		{"explicit empty string", ev(`,"mount":""`), LayerFrontend, "explicit zero"},
		{"negative integer", ev(`,"item":-1`), LayerFrontend, "wrong type"},
		{"fractional integer", ev(`,"item":1.5`), LayerFrontend, "wrong type"},
		{"exponent integer", ev(`,"item":1e3`), LayerFrontend, "wrong type"},
		{"string integer", ev(`,"item":"1"`), LayerFrontend, "wrong type"},
		{"integer overflow", ev(`,"flags":4294967296`), LayerFrontend, "wrong type"},
		{"field not allowed for kind", ev(`,"syscall":"fsync"`), LayerFrontend, "does not allow field"},
		{"missing required field", `{"record":"event","seq":1,"t_ns":5,"kind":"callback","phase":"entry","callback":7}`, LayerFrontend, "missing field"},
		{"missing phase", `{"record":"event","seq":1,"t_ns":5,"kind":"callback","callback":7,"callback_kind":"lookup"}`, LayerFrontend, "missing field"},
		{"phase not allowed for kind", `{"record":"event","seq":1,"t_ns":5,"kind":"callback","phase":"send","callback":7,"callback_kind":"lookup"}`, LayerFrontend, "does not allow phase"},
		{"kind not allowed for layer", ev(""), LayerDaemon, "not allowed in a daemon stream"},
		{"unknown kind", `{"record":"event","seq":1,"t_ns":5,"kind":"note"}`, LayerFrontend, "invalid value"},
		{"errno over bound", ev(`,"errno":4096`), LayerFrontend, "invalid value"},
		{"duration over bound", `{"record":"event","seq":1,"t_ns":5,"kind":"wait","wait":"transport","dur_ns":9007199254740992}`, LayerDaemon, "invalid value"},
		{"t_ns over bound", `{"record":"event","seq":1,"t_ns":9007199254740992,"kind":"wait","wait":"transport","dur_ns":1}`, LayerDaemon, "t_ns exceeds"},
		{"zero seq", `{"record":"event","seq":0,"t_ns":5,"kind":"wait","wait":"transport","dur_ns":1}`, LayerDaemon, "seq must be positive"},
		{"missing seq", `{"record":"event","t_ns":5,"kind":"wait","wait":"transport","dur_ns":1}`, LayerDaemon, `missing key "seq"`},
		{"collection key in producer stream", `{"record":"event","stream":1,"seq":1,"t_ns":5,"kind":"wait","wait":"transport","dur_ns":1}`, LayerDaemon, "unknown key"},
		{"data after object", ev("") + ` {}`, LayerFrontend, "data after"},
		{"not an object", `["record","event"]`, LayerFrontend, "not a JSON object"},
		{"malformed", `{"record":"event",`, LayerFrontend, "malformed"},
		{"unknown record", `{"record":"note","text":"hello"}`, LayerFrontend, "unknown or missing record"},
		{"missing record", `{"kind":"callback"}`, LayerFrontend, "unknown or missing record"},
		{"event key in trailer", `{"record":"trailer","emitted":1,"lost":0,"kind":"callback"}`, LayerFrontend, "unknown key"},
		{"header bad schema", `{"record":"header","schema":"pfs-lan-trace-0","run":"r","layer":"daemon","process":"p","clock":"c"}`, LayerFrontend, "unsupported schema"},
		{"header bad layer", `{"record":"header","schema":"pfs-lan-trace-1","run":"r","layer":"kernel","process":"p","clock":"c"}`, LayerFrontend, "layer"},
		{"header bad run", `{"record":"header","schema":"pfs-lan-trace-1","run":"a run","layer":"daemon","process":"p","clock":"c"}`, LayerFrontend, "run"},
		{"header missing clock", `{"record":"header","schema":"pfs-lan-trace-1","run":"r","layer":"daemon","process":"p"}`, LayerFrontend, `missing key "clock"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := parseEvent(tc.line, tc.layer)
			if err == nil {
				t.Fatalf("accepted %s", tc.line)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not mention %q", err, tc.want)
			}
			// A rejection must never echo the offending text back.
			for _, secret := range []string{"/Users/someone", "token=abc", "my mount"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error leaks input text: %q", err)
				}
			}
		})
	}
}

// longestValues maps each category type to its longest legal value, so the
// maximal event for a kind is built from values the grammar accepts.
func longestValues() map[reflect.Type]string {
	m := map[reflect.Type]string{}
	reg := func(t reflect.Type, values []string) {
		for _, v := range values {
			if len(v) > len(m[t]) {
				m[t] = v
			}
		}
	}
	strs := func(e any) (reflect.Type, []string) {
		v := reflect.ValueOf(e).FieldByName("ordered")
		out := make([]string, v.Len())
		for i := range out {
			out[i] = v.Index(i).String()
		}
		return v.Type().Elem(), out
	}
	for _, e := range []any{callbackKinds, origins, localOps, authorityOps, dispatches, outcomes,
		lookupPolarities, publications, candidates, cacheResults, coordinates, missReasons, proofStates,
		sourceStates, certStates, certDrops, searchStates, exposures, openReasons, modes, liveModes, rpcs,
		releaseKinds, barriers, syscalls, waitKinds, resources, witnesses, seeds, renewalOrigins,
		renewalOutcomes, loads} {
		reg(strs(e))
	}
	reg(reflect.TypeOf(Label("")), []string{"L" + strings.Repeat("x", MaxLabelBytes-1)})
	reg(reflect.TypeOf(NameHex("")), []string{strings.Repeat("ff", MaxNameBytes)})
	return m
}

// maximalEvent fills every field the kind allows with its largest legal value.
func maximalEvent(t *testing.T, k Kind) Event {
	t.Helper()
	longest := longestValues()
	e := Event{Kind: k}
	v := reflect.ValueOf(&e).Elem()
	for _, f := range eventFields {
		if rules[k].allowed&f.bit == 0 || f.key == "kind" {
			continue
		}
		fv := v.Field(f.index)
		switch fv.Type() {
		case reflect.TypeOf(Phase("")):
			var best Phase
			for p := range rules[k].phases {
				if len(p) > len(best) {
					best = p
				}
			}
			fv.SetString(string(best))
		case reflect.TypeOf(Nanos(0)):
			fv.SetUint(uint64(MaxNanos))
		case reflect.TypeOf(Errno(0)):
			fv.SetUint(uint64(MaxErrno))
		default:
			switch fv.Kind() {
			case reflect.String:
				s, ok := longest[fv.Type()]
				if !ok {
					t.Fatalf("no longest value for %s", fv.Type())
				}
				fv.SetString(s)
			case reflect.Uint64:
				fv.SetUint(math.MaxUint64)
			case reflect.Uint32:
				fv.SetUint(math.MaxUint32)
			default:
				t.Fatalf("unhandled field type %s", fv.Type())
			}
		}
	}
	return e
}

func TestLargestEventFitsOneLine(t *testing.T) {
	for _, k := range kinds.ordered {
		t.Run(string(k), func(t *testing.T) {
			e := maximalEvent(t, k)
			layer := ruleSpecs[k].layers[0]
			if _, err := e.validate(layer); err != nil {
				t.Fatalf("maximal %s event rejected: %v", k, err)
			}
			body, err := json.Marshal(&e)
			if err != nil {
				t.Fatal(err)
			}
			line := appendEvent(nil, MaxStreams, math.MaxUint64, MaxNanos, body)
			if len(line) > MaxLineBytes {
				t.Fatalf("maximal %s line is %d bytes, bound %d", k, len(line), MaxLineBytes)
			}
			t.Logf("maximal %s line: %d bytes", k, len(line))
			rec, err := parseLine(line[:len(line)-1], true)
			if err != nil {
				t.Fatalf("maximal line does not parse: %v", err)
			}
			if err := rec.checkEvent(layer); err != nil {
				t.Fatalf("maximal line does not validate: %v", err)
			}
			if !reflect.DeepEqual(rec.Event, e) {
				t.Fatalf("round trip changed the event:\n got %+v\nwant %+v", rec.Event, e)
			}
		})
	}
}

func TestRulesNameEveryKindAndValidLayers(t *testing.T) {
	for _, k := range kinds.ordered {
		r := ruleSpecs[k]
		if len(r.layers) == 0 {
			t.Errorf("%s has no layers", k)
		}
		for _, p := range r.phases {
			if !p.valid() {
				t.Errorf("%s names unknown phase %s", k, p)
			}
		}
	}
}

func TestLabelsAndNames(t *testing.T) {
	cases := []struct {
		label Label
		valid bool
	}{
		{"s1", true},
		{"run-2026.10.18_a:b", true},
		{"L" + Label(strings.Repeat("x", MaxLabelBytes-1)), true},
		{"", false},
		{"-x", false},
		{"x y", false},
		{"x/y", false},
		{"xé", false},
		{"L" + Label(strings.Repeat("x", MaxLabelBytes)), false},
	}
	for _, tc := range cases {
		if got := tc.label.valid(); got != tc.valid {
			t.Errorf("Label(%q).valid() = %t, want %t", tc.label, got, tc.valid)
		}
	}
	if n, err := EncodeName([]byte("src01.txt")); err != nil || n != "73726330312e747874" {
		t.Errorf("EncodeName = %q, %v", n, err)
	}
	for _, raw := range [][]byte{nil, make([]byte, MaxNameBytes+1)} {
		if _, err := EncodeName(raw); err == nil {
			t.Errorf("EncodeName accepted %d bytes", len(raw))
		}
	}
}

func TestOpaqueLabelIsRunLocalAndDeterministic(t *testing.T) {
	id := []byte{0: 1, 15: 2}
	a, err := OpaqueLabel("s", "run-a", id)
	if err != nil {
		t.Fatal(err)
	}
	again, _ := OpaqueLabel("s", "run-a", id)
	other, _ := OpaqueLabel("s", "run-b", id)
	if a != again || a == other || !a.valid() || !strings.HasPrefix(string(a), "s-") || len(a) != 18 {
		t.Fatalf("labels: %q %q %q", a, again, other)
	}
	for _, tc := range []struct {
		prefix string
		run    Label
		id     []byte
	}{{"", "r", id}, {"toolongpre", "r", id}, {"s", "bad run", id}, {"s", "r", nil}} {
		if _, err := OpaqueLabel(tc.prefix, tc.run, tc.id); err == nil {
			t.Errorf("OpaqueLabel(%q, %q, %d bytes) accepted", tc.prefix, tc.run, len(tc.id))
		}
	}
}
