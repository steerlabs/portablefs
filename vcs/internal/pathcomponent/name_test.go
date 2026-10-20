package pathcomponent

import (
	"bytes"
	"testing"
)

func TestValidName(t *testing.T) {
	for _, test := range []struct {
		name  []byte
		valid bool
	}{
		{nil, false}, {[]byte("."), false}, {[]byte(".."), false}, {[]byte("a/b"), false}, {[]byte{'a', 0}, false},
		{[]byte("..."), true}, {[]byte{255}, true}, {bytes.Repeat([]byte{'a'}, 255), true}, {bytes.Repeat([]byte{'a'}, 256), false},
	} {
		if got := ValidName(test.name); got != test.valid {
			t.Errorf("ValidName(%q)=%t, want %t", test.name, got, test.valid)
		}
	}
}
