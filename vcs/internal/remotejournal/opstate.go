package remotejournal

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/opstate"
)

// OpStateDocument returns the opstate.RemoteDocument bound to this claimed
// generation: the versioned lifecycle/checkpoint-intent JSON document stored
// in pfj.opstate, fenced by the same database-time writer facts as appends.
// Managed production opens its OperationStore through this document and never
// creates a local opstate file.
func (l *Log) OpStateDocument() opstate.RemoteDocument {
	return &opStateDocument{log: l}
}

type opStateDocument struct {
	log *Log
}

type opstateGetJSON struct {
	Doc     json.RawMessage `json:"doc"`
	Version *decimalInt64   `json:"version"`
}

type opstatePutJSON struct {
	Version *decimalInt64 `json:"version"`
}

func (d *opStateDocument) Load() ([]byte, int64, bool, error) {
	l := d.log
	raw, err := l.callIdempotent(
		`SELECT pfj.opstate_get($1,$2,$3,$4,$5,$6,$7,$8)`,
		l.generationID, int64(l.epoch), l.capability, l.cfg.LeaseID, l.cfg.FencingToken,
		l.managerEpoch, l.runtimeSeq, l.cfg.AuthorityRuntimeID,
	)
	if err != nil {
		return nil, 0, false, fmt.Errorf("remotejournal: opstate get: %w", err)
	}
	if len(raw) == 0 || string(raw) == "null" {
		return nil, 0, false, nil
	}
	var got opstateGetJSON
	if err := json.Unmarshal(raw, &got); err != nil {
		return nil, 0, false, fmt.Errorf("remotejournal: decode opstate get: %w", err)
	}
	if got.Version == nil || int64(*got.Version) <= 0 || len(got.Doc) == 0 || string(got.Doc) == "null" {
		return nil, 0, false, fmt.Errorf("%w: opstate get response is missing its exact document/version", ErrAccounting)
	}
	return got.Doc, int64(*got.Version), true, nil
}

// Store performs the fenced copy-on-write replace. Its outcome must be exact:
//   - typed success → new version
//   - PF002 version conflict → resolved by re-reading: if the stored document
//     semantically equals our candidate at expectedVersion+1, OUR earlier
//     attempt landed and the response was lost — adopt it. Anything else is a
//     foreign writer and fails (the opstate store then poisons, fail closed).
//   - PF001 → this writer is fenced; the log is poisoned too.
//   - non-typed failures (lost response) → retry; on retry the CAS either
//     applies, or conflicts and is resolved exactly as above.
func (d *opStateDocument) Store(raw []byte, expectedVersion int64) (int64, error) {
	l := d.log
	if l.readOnly {
		return 0, errReadOnly
	}
	if expectedVersion < 0 || expectedVersion == math.MaxInt64 || !json.Valid(raw) {
		return 0, fmt.Errorf("%w: opstate store requires valid JSON and an incrementable non-negative version", ErrInvalid)
	}
	backoff := retryBackoffFloor
	invalidSuccesses := 0
	for {
		mustRetry := false
		res, err := l.callJSONB(l.life,
			`SELECT pfj.opstate_put($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
			l.generationID, int64(l.epoch), l.capability, l.cfg.LeaseID, l.cfg.FencingToken,
			l.managerEpoch, l.runtimeSeq, l.cfg.AuthorityRuntimeID,
			expectedVersion, raw,
		)
		if err == nil {
			var put opstatePutJSON
			if derr := json.Unmarshal(res, &put); derr != nil {
				err = fmt.Errorf("remotejournal: decode opstate put: %w", derr)
				mustRetry = true
			} else if put.Version == nil || int64(*put.Version) != expectedVersion+1 {
				err = fmt.Errorf("%w: opstate put returned version %v, want %d",
					ErrAccounting, put.Version, expectedVersion+1)
				mustRetry = true
			} else {
				return int64(*put.Version), nil
			}
			invalidSuccesses++
			if invalidSuccesses >= maxInvalidSuccessBodies {
				cause := fmt.Errorf("%w: opstate put at version %d returned %d invalid success bodies (last: %v)",
					ErrProtocolIntegrity, expectedVersion, invalidSuccesses, err)
				l.poison(cause)
				return 0, cause
			}
			// A malformed success may still mean the CAS committed. Reissue the
			// same CAS; it either returns a valid response or conflicts and is
			// resolved by exact stored-document equality below.
		}
		if typed := typedError(err); typed != nil {
			if errors.Is(typed, ErrFenced) {
				l.poison(typed)
				return 0, typed
			}
			if errors.Is(typed, ErrConflict) {
				return d.resolveConflict(raw, expectedVersion, typed)
			}
			return 0, typed
		}
		if !mustRetry && !retryableSQLFailure(err) {
			return 0, fmt.Errorf("remotejournal: opstate put at version %d: %w", expectedVersion, err)
		}
		select {
		case <-l.life.Done():
			return 0, fmt.Errorf("%w: opstate put at version %d: %v (last attempt: %v)",
				ErrUnknownOutcome, expectedVersion, l.life.Err(), err)
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > retryBackoffCeil {
			backoff = retryBackoffCeil
		}
	}
}

// resolveConflict decides whether a CAS conflict is our own lost success.
func (d *opStateDocument) resolveConflict(raw []byte, expectedVersion int64, conflict error) (int64, error) {
	stored, version, found, err := d.Load()
	if err != nil {
		return 0, fmt.Errorf("remotejournal: resolve opstate conflict: %w", err)
	}
	if found && version == expectedVersion+1 && jsonEqual(stored, raw) {
		return version, nil
	}
	return 0, fmt.Errorf("remotejournal: opstate moved to version %d under us (foreign writer?): %w", version, conflict)
}

// jsonEqual compares JSON with PostgreSQL-jsonb-compatible number semantics:
// objects are unordered, arrays remain ordered, and JSON numbers compare by
// exact rational value (so 1 equals 1.0 while adjacent integers above 2^53 do
// not collapse through float64). RemoteDocument accepts arbitrary valid JSON,
// so this exactness is required before treating a CAS conflict as our own lost
// success.
func jsonEqual(a, b []byte) bool {
	va, okA := decodeExactJSON(a)
	vb, okB := decodeExactJSON(b)
	if !okA || !okB {
		return false
	}
	return equalExactJSON(va, vb)
}

func decodeExactJSON(raw []byte) (any, bool) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, false
	}
	return value, true
}

func equalExactJSON(left, right any) bool {
	switch leftValue := left.(type) {
	case nil:
		return right == nil
	case bool:
		rightValue, ok := right.(bool)
		return ok && leftValue == rightValue
	case string:
		rightValue, ok := right.(string)
		return ok && leftValue == rightValue
	case json.Number:
		rightValue, ok := right.(json.Number)
		if !ok {
			return false
		}
		leftRat, leftOK := new(big.Rat).SetString(string(leftValue))
		rightRat, rightOK := new(big.Rat).SetString(string(rightValue))
		return leftOK && rightOK && leftRat.Cmp(rightRat) == 0
	case []any:
		rightValue, ok := right.([]any)
		if !ok || len(leftValue) != len(rightValue) {
			return false
		}
		for i := range leftValue {
			if !equalExactJSON(leftValue[i], rightValue[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		rightValue, ok := right.(map[string]any)
		if !ok || len(leftValue) != len(rightValue) {
			return false
		}
		for key, leftElement := range leftValue {
			rightElement, found := rightValue[key]
			if !found || !equalExactJSON(leftElement, rightElement) {
				return false
			}
		}
		return true
	default:
		return false
	}
}
