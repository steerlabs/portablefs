package remotejournal

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
)

// PostgreSQL BIGINT values cross JSON boundaries as canonical decimal
// strings. Requiring a quoted value here prevents an accidental float64
// round-trip in any intermediary and makes values above 2^53 unambiguous.
type decimalUint64 uint64

func (d decimalUint64) MarshalJSON() ([]byte, error) {
	return json.Marshal(strconv.FormatUint(uint64(d), 10))
}

func (d *decimalUint64) UnmarshalJSON(raw []byte) error {
	value, err := decodeCanonicalDecimal(raw)
	if err != nil {
		return err
	}
	parsed, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return fmt.Errorf("remotejournal: decimal uint64 %q: %w", value, err)
	}
	*d = decimalUint64(parsed)
	return nil
}

type decimalInt64 int64

func (d decimalInt64) MarshalJSON() ([]byte, error) {
	if d < 0 {
		return nil, fmt.Errorf("remotejournal: exact integer must be non-negative")
	}
	return json.Marshal(strconv.FormatInt(int64(d), 10))
}

func (d *decimalInt64) UnmarshalJSON(raw []byte) error {
	value, err := decodeCanonicalDecimal(raw)
	if err != nil {
		return err
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return fmt.Errorf("remotejournal: decimal int64 %q: %w", value, err)
	}
	*d = decimalInt64(parsed)
	return nil
}

func decodeCanonicalDecimal(raw []byte) (string, error) {
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return "", fmt.Errorf("remotejournal: exact integer must be a JSON decimal string: %w", err)
	}
	if value == "0" {
		return value, nil
	}
	if len(value) == 0 || value[0] < '1' || value[0] > '9' {
		return "", fmt.Errorf("remotejournal: %q is not a canonical non-negative decimal", value)
	}
	for i := 1; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return "", fmt.Errorf("remotejournal: %q is not a canonical non-negative decimal", value)
		}
	}
	return value, nil
}

func parsePositiveSQLBigint(name, value string) (int64, error) {
	if value == "" {
		return 0, fmt.Errorf("remotejournal: %s is required", name)
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return 0, fmt.Errorf("remotejournal: encode %s: %w", name, err)
	}
	canonical, err := decodeCanonicalDecimal(raw)
	if err != nil {
		return 0, fmt.Errorf("remotejournal: %s: %w", name, err)
	}
	parsed, err := strconv.ParseInt(canonical, 10, 64)
	if err != nil || parsed <= 0 {
		return 0, fmt.Errorf("remotejournal: %s %q must be a canonical positive PostgreSQL BIGINT", name, value)
	}
	return parsed, nil
}

func checkedSQLBigint(name string, value uint64) (int64, error) {
	if value > math.MaxInt64 {
		return 0, fmt.Errorf("remotejournal: %s %d exceeds PostgreSQL BIGINT", name, value)
	}
	return int64(value), nil
}

// addNonnegativeInt64 adds database/accounting quantities without allowing a
// signed wrap to turn an over-capacity journal into apparent free space.
func addNonnegativeInt64(left, right int64) (int64, bool) {
	if left < 0 || right < 0 || left > math.MaxInt64-right {
		return 0, false
	}
	return left + right, true
}

// canonicalFingerprint is the shared injective operation fingerprint shape:
// sha256 over UTF-8 byte-length-delimited parts. Delimiters inside values can
// never smear two different requests into the same canonical byte stream.
func canonicalFingerprint(parts ...string) string {
	hash := sha256.New()
	for _, part := range parts {
		bytes := []byte(part)
		_, _ = hash.Write([]byte(strconv.Itoa(len(bytes))))
		_, _ = hash.Write([]byte{':'})
		_, _ = hash.Write(bytes)
	}
	return hex.EncodeToString(hash.Sum(nil))
}
