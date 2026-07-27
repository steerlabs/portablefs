package fencing

import (
	"encoding/json"
	"errors"
	"math"
	"testing"
)

func TestTokenJSONIsExactQuotedDecimal(t *testing.T) {
	for _, value := range []Token{1, Token(1<<53 + 1), Token(math.MaxInt64)} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		var decoded Token
		if err := json.Unmarshal(encoded, &decoded); err != nil {
			t.Fatal(err)
		}
		if decoded != value {
			t.Fatalf("round trip = %v, want %v", decoded, value)
		}
	}
}

func TestTokenRejectsNumbersNoncanonicalAndOverflow(t *testing.T) {
	for _, input := range []string{`1`, `"0"`, `"01"`, `"+1"`, `"-1"`, `"9223372036854775808"`} {
		var token Token
		err := json.Unmarshal([]byte(input), &token)
		if !errors.Is(err, ErrInvalid) {
			t.Errorf("Unmarshal(%s) error = %v, want ErrInvalid", input, err)
		}
	}
}
