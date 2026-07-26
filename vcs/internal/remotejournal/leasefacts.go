package remotejournal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// AuthorityLeaseFacts is the capability/runtime-bound manager-claim truth
// answered by pfj.authority_lease_facts: the LIVE claim's database clock and
// expiry plus the exact binding echo. Current=false reports a PROVEN
// superseded/expired/fenced binding (SQLSTATE PF001) — a definitive database
// answer, not an ambiguity.
type AuthorityLeaseFacts struct {
	Current             bool
	DBTimeMs            int64
	ExpiresAtDbMs       int64
	ManagerEpoch        string
	ManagerRuntimeID    string
	AuthorityRuntimeSeq string
	AuthorityRuntimeID  string
	AuthorityInstanceID string
}

type authorityLeaseFactsJSON struct {
	Managed             bool          `json:"managed"`
	Current             *bool         `json:"current"`
	TenantKey           string        `json:"tenantKey"`
	ManagerEpoch        *decimalInt64 `json:"managerEpoch"`
	ManagerRuntimeID    string        `json:"managerRuntimeId"`
	AuthorityRuntimeSeq *decimalInt64 `json:"authorityRuntimeSeq"`
	AuthorityRuntimeID  string        `json:"authorityRuntimeId"`
	AuthorityInstanceID string        `json:"authorityInstanceId"`
	DBTimeMs            *decimalInt64 `json:"dbTimeMs"`
	ExpiresAtDbMs       *decimalInt64 `json:"expiresAtDbMs"`
}

// AuthorityLeaseFacts performs ONE bounded capability/runtime-bound
// lease-facts read on the already-open fenced pool. The database verifies
// the exact manager epoch + live runtime row + raw authority capability
// under the same locks every journal mutation takes, and answers the live
// claim's dbTimeMs/expiresAtDbMs. A PF001 (superseded, expired, revoked, or
// mismatched binding) returns Current=false with a NIL error — a definitive
// fact; every other failure is an error (ambiguous: the caller must not
// extend anything from it).
func (l *Log) AuthorityLeaseFacts(ctx context.Context) (AuthorityLeaseFacts, error) {
	if l.readOnly {
		return AuthorityLeaseFacts{}, errReadOnly
	}
	raw, err := l.callJSONB(ctx,
		`SELECT pfj.authority_lease_facts($1,$2,$3,$4,$5,$6,$7)`,
		l.cfg.TenantID, l.cfg.VolumeID, l.cfg.Branch,
		l.managerEpoch, l.runtimeSeq, l.cfg.AuthorityRuntimeID, l.capability,
	)
	if err != nil {
		if typed := typedError(err); typed != nil && errors.Is(typed, ErrFenced) {
			// The database PROVED the binding is not the live one.
			return AuthorityLeaseFacts{Current: false}, nil
		}
		return AuthorityLeaseFacts{}, fmt.Errorf("remotejournal: authority lease facts: %w", err)
	}
	var wire authorityLeaseFactsJSON
	if err := json.Unmarshal(raw, &wire); err != nil {
		return AuthorityLeaseFacts{}, fmt.Errorf("remotejournal: decode authority lease facts: %w", err)
	}
	if !wire.Managed || wire.Current == nil || !*wire.Current ||
		wire.ManagerEpoch == nil || wire.AuthorityRuntimeSeq == nil ||
		wire.DBTimeMs == nil || wire.ExpiresAtDbMs == nil {
		return AuthorityLeaseFacts{}, fmt.Errorf("%w: authority lease facts response is missing its exact binding/claim facts", ErrConflict)
	}
	return AuthorityLeaseFacts{
		Current:             true,
		DBTimeMs:            int64(*wire.DBTimeMs),
		ExpiresAtDbMs:       int64(*wire.ExpiresAtDbMs),
		ManagerEpoch:        fmt.Sprintf("%d", int64(*wire.ManagerEpoch)),
		ManagerRuntimeID:    wire.ManagerRuntimeID,
		AuthorityRuntimeSeq: fmt.Sprintf("%d", int64(*wire.AuthorityRuntimeSeq)),
		AuthorityRuntimeID:  wire.AuthorityRuntimeID,
		AuthorityInstanceID: wire.AuthorityInstanceID,
	}, nil
}
