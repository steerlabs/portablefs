package backend

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// HTTPError is a non-2xx response from volume-api, carrying the status code so
// callers can classify it (e.g. a busy write lease) rather than string-match.
type HTTPError struct {
	Method string
	Path   string
	Status int
	Body   string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("%s %s: http %d: %s", e.Method, e.Path, e.Status, e.Body)
}

// IsLeaseBusy reports whether err is the backend refusing a write attach because
// another VCS still holds the volume's exclusive lease (HTTP 423 Locked /
// VOLUME_WRITE_LEASE_BUSY). A standby polls on this: busy means the primary is
// still alive, so keep waiting; any other error is fatal.
func IsLeaseBusy(err error) bool {
	var he *HTTPError
	if errors.As(err, &he) {
		return he.Status == http.StatusLocked || strings.Contains(he.Body, "VOLUME_WRITE_LEASE_BUSY")
	}
	return false
}

// IsDefinitiveRejection reports whether err is a response the backend actually
// produced and that definitively REJECTS the request (4xx): the operation did
// not and will not land, so a retry with the same body is pointless. Transport
// failures, timeouts, and 5xx responses are NOT definitive — the request may
// have landed with its response lost — and must be reconciled by operation id
// instead of assumed failed.
func IsDefinitiveRejection(err error) bool {
	var he *HTTPError
	if errors.As(err, &he) {
		return he.Status >= 400 && he.Status < 500
	}
	return false
}

// IsLeaseLost reports whether err means this VCS's write lease is no longer valid:
// it was superseded by a promoted standby (the fencing token advanced) or it
// expired and was reclaimed. A primary that sees this on renew/commit must stop
// serving immediately — it can no longer prove it is the single authority, so any
// further read it serves may be stale and any write it acks can never commit.
// Signalled by VOLUME_LEASE_STALE / a missing or expired lease / 409 / 412 / 410.
func IsLeaseLost(err error) bool {
	var he *HTTPError
	if errors.As(err, &he) {
		if strings.Contains(he.Body, "VOLUME_LEASE_STALE") ||
			strings.Contains(he.Body, "VOLUME_LEASE_NOT_FOUND") ||
			strings.Contains(he.Body, "VOLUME_LEASE_EXPIRED") {
			return true
		}
		switch he.Status {
		case http.StatusConflict, http.StatusGone, http.StatusPreconditionFailed:
			return true
		}
	}
	return false
}
