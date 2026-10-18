package daemonctl

import (
	"fmt"
	"strings"
	"testing"
)

func TestSealedProtocolsRoundTripAcrossReleases(t *testing.T) {
	for _, p := range []SealedProtocols{{1, 2, 2, 0}, {1, 77, 91, 18}, {1, 1, ^uint32(0), ^uint32(0)}} {
		data, err := EncodeSealedProtocols(p)
		if err != nil {
			t.Fatal(err)
		}
		got, err := DecodeSealedProtocols(data)
		if err != nil || got != p {
			t.Fatalf("roundtrip = %+v, %v", got, err)
		}
	}
}

func TestSealedProtocolsStrictGrammar(t *testing.T) {
	valid := `{"identitySchema":1,"controlProtocol":2,"pfslocalMajor":2,"pfslocalMinor":0}`
	invalid := []string{"", `null`, `[]`, valid + `{}`, strings.Repeat(" ", MaxLifecycleBodyBytes) + valid,
		`{"identitySchema":2,"controlProtocol":2,"pfslocalMajor":2,"pfslocalMinor":0}`,
		`{"identitySchema":1,"controlProtocol":0,"pfslocalMajor":2,"pfslocalMinor":0}`,
		`{"identitySchema":1,"controlProtocol":2,"pfslocalMajor":0,"pfslocalMinor":0}`,
		`{"identitySchema":1,"controlProtocol":2,"pfslocalMajor":4294967296,"pfslocalMinor":0}`,
	}
	for _, key := range []string{"identitySchema", "controlProtocol", "pfslocalMajor", "pfslocalMinor"} {
		needle := fmt.Sprintf(`"%s":`, key)
		invalid = append(invalid, strings.Replace(valid, needle, `"unknown":`, 1), strings.Replace(valid, needle, fmt.Sprintf(`"%s":null,"%s":`, key, key), 1))
	}
	for _, data := range invalid {
		if got, err := DecodeSealedProtocols([]byte(data)); err == nil || got != (SealedProtocols{}) {
			t.Fatalf("accepted %q: %+v, %v", data, got, err)
		}
	}
}
