// Package fencing defines the exact branch-writer fencing-token domain.
// Tokens are positive PostgreSQL BIGINT values. Go keeps them as an exact
// signed integer internally, but JSON always carries a quoted canonical
// decimal string so TypeScript can never round a value above 2^53.
package fencing

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// Token is a positive, monotonic branch-writer fence.
type Token int64

var ErrInvalid = errors.New("invalid fencing token")

// Parse accepts exactly [1-9][0-9]* within signed int64.
func Parse(value string) (Token, error) {
	if value == "" || value[0] < '1' || value[0] > '9' {
		return 0, fmt.Errorf("%w: must be a canonical positive decimal", ErrInvalid)
	}
	for i := 1; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return 0, fmt.Errorf("%w: must be a canonical positive decimal", ErrInvalid)
		}
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("%w: exceeds signed int64", ErrInvalid)
	}
	return Token(parsed), nil
}

func (t Token) String() string { return strconv.FormatInt(int64(t), 10) }

func (t Token) Valid() bool { return t > 0 }

func (t Token) MarshalJSON() ([]byte, error) {
	if !t.Valid() {
		return nil, fmt.Errorf("%w: token must be positive", ErrInvalid)
	}
	return json.Marshal(t.String())
}

func (t *Token) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("%w: JSON value must be a quoted decimal string", ErrInvalid)
	}
	parsed, err := Parse(value)
	if err != nil {
		return err
	}
	*t = parsed
	return nil
}
