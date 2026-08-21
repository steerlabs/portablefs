package archivestore

import (
	"errors"
	"fmt"
	"time"
)

// Sentinels for errors.Is. They are never returned directly by the operations;
// operations return *Error, whose Is reports the sentinel matching its Kind.
var (
	// ErrInvalid marks a caller or configuration fault detected locally. It is
	// never the result of a store response.
	ErrInvalid = errors.New("archivestore: invalid")
	// ErrNotFound is a 404 / NoSuchKey / NoSuchUpload from the store.
	ErrNotFound = errors.New("archivestore: object not found")
	// ErrPreconditionFailed is a lost conditional create (If-None-Match: *).
	ErrPreconditionFailed = errors.New("archivestore: precondition failed")
	// ErrAccessDenied is a 401/403 or an AccessDenied-class S3 code.
	ErrAccessDenied = errors.New("archivestore: access denied")
	// ErrThrottled is a 429 / SlowDown / RequestLimitExceeded.
	ErrThrottled = errors.New("archivestore: throttled")
	// ErrRetryable covers every transient condition after retries are spent:
	// throttling, 5xx, and network faults all match it.
	ErrRetryable = errors.New("archivestore: retryable store failure")
	// ErrResponse marks a syntactically or semantically unusable success
	// response (malformed XML, wrong root element, short or long body).
	ErrResponse = errors.New("archivestore: malformed store response")
)

// Kind is the closed taxonomy of archive-store failures. Callers switch on it
// exhaustively; a new kind is an additive change reviewed with its callers.
type Kind uint8

const (
	// KindOther is a store failure with no more specific classification. It is
	// deliberately the zero value so an unclassified error is never retryable
	// and never mistaken for success.
	KindOther Kind = iota
	KindNotFound
	KindPreconditionFailed
	KindAccessDenied
	KindThrottled
	KindServer
	KindNetwork
	KindResponse
)

func (k Kind) String() string {
	switch k {
	case KindOther:
		return "other"
	case KindNotFound:
		return "not_found"
	case KindPreconditionFailed:
		return "precondition_failed"
	case KindAccessDenied:
		return "access_denied"
	case KindThrottled:
		return "throttled"
	case KindServer:
		return "server"
	case KindNetwork:
		return "network"
	case KindResponse:
		return "response"
	default:
		return "unknown"
	}
}

// Error is the single error type every operation returns for store-side and
// transport-side failures. Code and Message come from the bounded S3 XML error
// body when the store supplied one; StatusCode is zero for a network fault.
type Error struct {
	Op         string
	Key        string
	StatusCode int
	Code       string
	Message    string
	RequestID  string
	Kind       Kind
	Attempts   int

	retryable  bool
	retryAfter time.Duration
	cause      error
}

func (e *Error) Error() string {
	message := fmt.Sprintf("archivestore: %s", e.Op)
	if e.Key != "" {
		message += fmt.Sprintf(" %q", e.Key)
	}
	message += fmt.Sprintf(": %s", e.Kind)
	if e.StatusCode != 0 {
		message += fmt.Sprintf(" (http %d", e.StatusCode)
		if e.Code != "" {
			message += ", " + e.Code
		}
		message += ")"
	} else if e.Code != "" {
		message += " (" + e.Code + ")"
	}
	if e.Message != "" {
		message += ": " + e.Message
	}
	if e.cause != nil {
		message += ": " + e.cause.Error()
	}
	if e.Attempts > 1 {
		message += fmt.Sprintf(" [after %d attempts]", e.Attempts)
	}
	return message
}

func (e *Error) Unwrap() error { return e.cause }

// Retryable reports whether the loop would have retried this error had attempts
// remained. Callers driving their own outer backoff (the manager's verifying
// cursor, the hydrator's RESTORE_BLOCKED retry) consult it.
func (e *Error) Retryable() bool { return e.retryable }

func (e *Error) Is(target error) bool {
	switch target {
	case ErrNotFound:
		return e.Kind == KindNotFound
	case ErrPreconditionFailed:
		return e.Kind == KindPreconditionFailed
	case ErrAccessDenied:
		return e.Kind == KindAccessDenied
	case ErrThrottled:
		return e.Kind == KindThrottled
	case ErrResponse:
		return e.Kind == KindResponse
	case ErrRetryable:
		return e.retryable
	default:
		return false
	}
}

func retryable(err error) bool {
	var storeError *Error
	return errors.As(err, &storeError) && storeError.retryable
}

// classifyStatus maps an HTTP status and an S3 error code onto the taxonomy.
// Retryability is decided here and nowhere else: every call site consults the
// resulting *Error rather than re-deriving the rule from a status code.
func classifyStatus(status int, code string) (Kind, bool) {
	switch code {
	case "NoSuchKey", "NoSuchBucket", "NoSuchUpload", "NotFound":
		return KindNotFound, false
	case "PreconditionFailed", "ConditionalRequestConflict":
		return KindPreconditionFailed, false
	case "AccessDenied", "InvalidAccessKeyId", "SignatureDoesNotMatch", "ExpiredToken",
		"InvalidToken", "AccountProblem", "AllAccessDisabled":
		return KindAccessDenied, false
	case "SlowDown", "RequestLimitExceeded", "TooManyRequests", "Throttling", "ThrottlingException":
		return KindThrottled, true
	case "RequestTimeout", "RequestTimeTooSkewed", "InternalError", "ServiceUnavailable":
		// RequestTimeTooSkewed is retryable only in the sense that each attempt
		// re-signs with a fresh clock reading; a persistently wrong clock burns
		// the attempt budget and then fails visibly, which is the intent.
		return KindServer, true
	}
	switch {
	case status == 404:
		return KindNotFound, false
	case status == 412 || status == 409:
		return KindPreconditionFailed, false
	case status == 401 || status == 403:
		return KindAccessDenied, false
	case status == 429:
		return KindThrottled, true
	case status >= 500:
		return KindServer, true
	default:
		return KindOther, false
	}
}
