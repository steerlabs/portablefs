package daemonctl_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/daemonctl"
)

func TestProtocolConstants(t *testing.T) {
	if daemonctl.ControlProtocolVersion != 2 || daemonctl.LifecycleProtocolVersion != 1 || daemonctl.IdentitySchemaVersion != 1 {
		t.Fatal("control/lifecycle/identity versions must be exactly 2/1/1")
	}
	for _, test := range []struct{ got, want string }{
		{daemonctl.ControlProtocolHeader, "X-PortableFS-Control-Protocol"},
		{daemonctl.ControlPathPrefix, "/v2/"},
		{daemonctl.LifecycleIdentityPath, "/lifecycle/v1/identity"},
		{daemonctl.LifecycleInventoryPath, "/lifecycle/v1/inventory"},
		{daemonctl.LifecycleStopIfIdlePath, "/lifecycle/v1/stop-if-idle"},
		{daemonctl.LifecycleIdentityRoute, "GET /lifecycle/v1/identity"},
		{daemonctl.LifecycleInventoryRoute, "GET /lifecycle/v1/inventory"},
		{daemonctl.LifecycleStopIfIdleRoute, "POST /lifecycle/v1/stop-if-idle"},
	} {
		if test.got != test.want {
			t.Errorf("got %q, want %q", test.got, test.want)
		}
	}
}

func TestLifecycleInventoryRoundTrip(t *testing.T) {
	for _, count := range []int{0, 1, daemonctl.MaxLifecycleAttachmentCount} {
		t.Run(fmt.Sprint(count), func(t *testing.T) {
			want := daemonctl.LifecycleInventory{AttachmentCount: count}
			body, err := daemonctl.EncodeLifecycleInventory(want)
			if err != nil {
				t.Fatal(err)
			}
			if string(body) != fmt.Sprintf(`{"attachment_count":%d}`, count) {
				t.Fatalf("unexpected inventory body %q", body)
			}
			got, err := daemonctl.DecodeLifecycleInventory(body)
			if err != nil || got != want {
				t.Fatalf("decoded = %+v, %v; want %+v", got, err, want)
			}
		})
	}
	for _, count := range []int{-1, daemonctl.MaxLifecycleAttachmentCount + 1} {
		inventory := daemonctl.LifecycleInventory{AttachmentCount: count}
		if err := inventory.Validate(); err == nil {
			t.Errorf("validated count %d", count)
		}
		if body, err := daemonctl.EncodeLifecycleInventory(inventory); err == nil || body != nil {
			t.Errorf("encoded count %d: %q, %v", count, body, err)
		}
	}
}

func TestLifecycleInventoryStrictDecode(t *testing.T) {
	for _, test := range []struct{ name, body string }{
		{"empty", ""},
		{"missing count", `{}`},
		{"unknown", `{"attachment_count":0,"extra":0}`},
		{"case differs", `{"ATTACHMENT_COUNT":0}`},
		{"duplicate", `{"attachment_count":1,"attachment_count":0}`},
		{"escaped duplicate", `{"attachment_count":1,"attachment_\u0063ount":0}`},
		{"negative", `{"attachment_count":-1}`},
		{"above bound", fmt.Sprintf(`{"attachment_count":%d}`, daemonctl.MaxLifecycleAttachmentCount+1)},
		{"integer overflow", `{"attachment_count":18446744073709551616}`},
		{"fraction", `{"attachment_count":0.5}`},
		{"decimal integer", `{"attachment_count":1.0}`},
		{"exponent", `{"attachment_count":1e0}`},
		{"string", `{"attachment_count":"0"}`},
		{"bool", `{"attachment_count":false}`},
		{"null count", `{"attachment_count":null}`},
		{"array count", `{"attachment_count":[]}`},
		{"object count", `{"attachment_count":{}}`},
		{"null object", `null`},
		{"array object", `[]`},
		{"scalar object", `0`},
		{"trailing object", `{"attachment_count":0}{}`},
		{"trailing null", `{"attachment_count":0} null`},
		{"trailing junk", `{"attachment_count":0}junk`},
		{"truncated", `{"attachment_count":0`},
		{"wrong close", `{"attachment_count":0]`},
		{"trailing comma", `{"attachment_count":0,}`},
		{"invalid UTF-8", "{\"attachment_count\":0}\xff"},
		{"oversize", `{"attachment_count":0}` + strings.Repeat(" ", daemonctl.MaxLifecycleBodyBytes)},
	} {
		t.Run(test.name, func(t *testing.T) {
			got, err := daemonctl.DecodeLifecycleInventory([]byte(test.body))
			if err == nil || got != (daemonctl.LifecycleInventory{}) {
				t.Fatalf("decoded invalid inventory = %+v, %v", got, err)
			}
		})
	}
	for _, body := range []string{
		" \n{\"attachment_count\": 0}\t\r\n",
		`{"attachment_\u0063ount":0}`,
		`{"attachment_count":0}` + strings.Repeat(" ", daemonctl.MaxLifecycleBodyBytes-len(`{"attachment_count":0}`)),
	} {
		if _, err := daemonctl.DecodeLifecycleInventory([]byte(body)); err != nil {
			t.Fatalf("rejected valid JSON: %v", err)
		}
	}
}

func validIdentity() daemonctl.Identity {
	return daemonctl.Identity{
		SchemaVersion:    1,
		ControlProtocol:  2,
		DaemonVersion:    "0.4.1-dev+test",
		ExecutableSHA256: strings.Repeat("0123456789abcdef", 4),
		PFSLocalMajor:    2,
		PFSLocalMinor:    0,
	}
}

func TestIdentityRoundTripAcrossOperationalVersions(t *testing.T) {
	for _, test := range []struct {
		name              string
		control           int
		localMajor, minor uint32
	}{
		{"current", 2, 2, 0},
		{"distinct release", 37, 19, 23},
		{"independent older values", 1, 1, 16},
		{"uint32 limits", 3, 1<<32 - 1, 1<<32 - 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			want := validIdentity()
			want.ControlProtocol, want.PFSLocalMajor, want.PFSLocalMinor = test.control, test.localMajor, test.minor
			body, err := daemonctl.EncodeIdentity(want)
			if err != nil {
				t.Fatal(err)
			}
			got, err := daemonctl.DecodeIdentity(body)
			if err != nil || got != want {
				t.Fatalf("decoded identity = %+v, %v; want %+v", got, err, want)
			}
		})
	}
	want := validIdentity()
	body, err := daemonctl.EncodeIdentity(want)
	if err != nil {
		t.Fatal(err)
	}
	expected := `{"schemaVersion":1,"controlProtocol":2,"daemonVersion":"0.4.1-dev+test","executableSha256":"` + want.ExecutableSHA256 + `","pfslocalMajor":2,"pfslocalMinor":0}`
	if string(body) != expected {
		t.Fatalf("schema-1 body = %s, want %s", body, expected)
	}
	// A changed key order and JSON whitespace do not change the schema.
	reordered := ` {"pfslocalMinor":0,"pfslocalMajor":2,"executableSha256":"` + want.ExecutableSHA256 + `","daemonVersion":"0.4.1-dev+test","controlProtocol":2,"schemaVersion":1} `
	if got, err := daemonctl.DecodeIdentity([]byte(reordered)); err != nil || got != want {
		t.Fatalf("reordered identity = %+v, %v", got, err)
	}
}

func TestIdentityStrictDecode(t *testing.T) {
	body, err := daemonctl.EncodeIdentity(validIdentity())
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(body, &fields); err != nil {
		t.Fatal(err)
	}
	// Exercise every key so a default-valued missing/null minor cannot pass,
	// and every scalar gets the same duplicate and type protection.
	for key := range fields {
		for _, variant := range []string{"missing", "null", "wrong type", "duplicate", "escaped duplicate", "wrong case"} {
			t.Run(key+"/"+variant, func(t *testing.T) {
				copyFields := make(map[string]json.RawMessage, len(fields))
				for k, v := range fields {
					copyFields[k] = v
				}
				switch variant {
				case "missing":
					delete(copyFields, key)
				case "null":
					copyFields[key] = json.RawMessage(`null`)
				case "wrong type":
					copyFields[key] = json.RawMessage(`[]`)
				case "wrong case":
					copyFields[strings.ToUpper(key)] = copyFields[key]
					delete(copyFields, key)
				}
				input, err := json.Marshal(copyFields)
				if err != nil {
					t.Fatal(err)
				}
				if variant == "duplicate" || variant == "escaped duplicate" {
					duplicateKey := key
					if variant == "escaped duplicate" {
						duplicateKey = fmt.Sprintf(`\u%04x%s`, key[0], key[1:])
					}
					input = append(input[:len(input)-1], []byte(`,"`+duplicateKey+`":`+string(fields[key])+`}`)...)
				}
				if got, err := daemonctl.DecodeIdentity(input); err == nil || got != (daemonctl.Identity{}) {
					t.Fatalf("decoded invalid identity = %+v, %v", got, err)
				}
			})
		}
	}
	for _, test := range []struct{ name, input string }{
		{"unknown key", strings.TrimSuffix(string(body), "}") + `,"pid":123}`},
		{"trailing value", string(body) + ` null`},
		{"trailing junk", string(body) + `!`},
		{"null", `null`},
		{"array", `[]`},
		{"empty", ""},
		{"truncated", string(body[:len(body)-1])},
		{"oversize", string(body) + strings.Repeat(" ", daemonctl.MaxLifecycleBodyBytes)},
		{"invalid UTF-8", strings.Replace(string(body), "dev", "\xff", 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got, err := daemonctl.DecodeIdentity([]byte(test.input)); err == nil || got != (daemonctl.Identity{}) {
				t.Fatalf("decoded invalid identity = %+v, %v", got, err)
			}
		})
	}
}

func TestIdentityValidation(t *testing.T) {
	for _, test := range []struct{ key, raw string }{
		{"schemaVersion", `0`}, {"schemaVersion", `2`},
		{"schemaVersion", `9223372036854775808`},
		{"controlProtocol", `0`}, {"controlProtocol", `-1`},
		{"controlProtocol", `9223372036854775808`},
		{"controlProtocol", `2.0`}, {"controlProtocol", `2e0`}, {"controlProtocol", `"2"`},
		{"pfslocalMajor", `0`}, {"pfslocalMajor", `-1`}, {"pfslocalMajor", `4294967296`},
		{"pfslocalMinor", `-1`}, {"pfslocalMinor", `4294967296`}, {"pfslocalMinor", `0.0`},
		{"daemonVersion", `""`}, {"daemonVersion", `"bad version"`},
		{"daemonVersion", `"bad\nversion"`}, {"daemonVersion", `"bad\u007fversion"`},
		{"daemonVersion", `"\u00e9"`}, {"daemonVersion", `"\ud800"`},
		{"daemonVersion", `"` + strings.Repeat("v", 129) + `"`},
		{"executableSha256", `""`}, {"executableSha256", `"` + strings.Repeat("a", 63) + `"`},
		{"executableSha256", `"` + strings.Repeat("a", 65) + `"`},
		{"executableSha256", `"` + strings.Repeat("A", 64) + `"`},
		{"executableSha256", `"` + strings.Repeat("g", 64) + `"`},
	} {
		t.Run(test.key+"/"+test.raw, func(t *testing.T) {
			body, err := daemonctl.EncodeIdentity(validIdentity())
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(body, &fields); err != nil {
				t.Fatal(err)
			}
			fields[test.key] = json.RawMessage(test.raw)
			input, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := daemonctl.DecodeIdentity(input); err == nil {
				t.Fatalf("decoded invalid field %s=%s", test.key, test.raw)
			}
			var identity daemonctl.Identity
			// Values representable by the Go DTO must also fail validation and
			// encoding. Overflow/type errors are already refused by the decoder.
			if err := json.Unmarshal(input, &identity); err == nil {
				if err := identity.Validate(); err == nil {
					t.Fatal("invalid identity passed validation")
				}
				if encoded, err := daemonctl.EncodeIdentity(identity); err == nil || encoded != nil {
					t.Fatalf("encoded invalid identity: %q, %v", encoded, err)
				}
			}
		})
	}
	identity := validIdentity()
	identity.DaemonVersion = strings.Repeat("v", 128)
	if _, err := daemonctl.EncodeIdentity(identity); err != nil {
		t.Fatalf("rejected maximum-length daemon version: %v", err)
	}
}

func TestStopIfIdleEmptyRequest(t *testing.T) {
	if body := daemonctl.EncodeStopIfIdleRequest(); len(body) != 0 {
		t.Fatalf("request body = %q, want no bytes", body)
	}
	for _, body := range [][]byte{nil, {}} {
		if err := daemonctl.DecodeStopIfIdleRequest(body); err != nil {
			t.Fatal(err)
		}
	}
	for _, body := range []string{" ", "\n", "{}", "null", `{"force":true}`, "\x00"} {
		if err := daemonctl.DecodeStopIfIdleRequest([]byte(body)); err == nil {
			t.Errorf("accepted request body %q", body)
		}
	}
}

func TestStopIfIdleResponse(t *testing.T) {
	for _, test := range []struct {
		name    string
		status  int
		body    string
		success bool
		busy    bool
	}{
		{"quiescent", 204, "", true, false},
		{"whitespace is a body", 204, "\n", false, false},
		{"object is a body", 204, "{}", false, false},
		{"busy without diagnostic", 409, "", false, true},
		{"busy with diagnostic", 409, `{"error":"busy"}`, false, true},
		{"busy ignores diagnostic grammar", 409, "arbitrary diagnostic", false, true},
		{"wrong success", 200, "", false, false},
		{"redirect", 302, "", false, false},
		{"missing endpoint", 404, "", false, false},
		{"wrong method", 405, "", false, false},
		{"operational mismatch", 426, "", false, false},
		{"failure", 500, "", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := daemonctl.ValidateStopIfIdleResponse(test.status, []byte(test.body))
			if (err == nil) != test.success || errors.Is(err, daemonctl.ErrLifecycleBusy) != test.busy {
				t.Fatalf("response error = %v; want success %v, busy %v", err, test.success, test.busy)
			}
		})
	}
	// No other HTTP status, including other 2xx statuses, proves quiescence.
	for status := 100; status <= 599; status++ {
		if status == 204 {
			continue
		}
		if err := daemonctl.ValidateStopIfIdleResponse(status, nil); err == nil {
			t.Errorf("accepted HTTP %d", status)
		}
	}
}
