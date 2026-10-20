package daemonctl

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"unicode/utf8"
)

const (
	// Lifecycle routes retain socket peer/owner authentication, independently
	// of operational version-equality middleware. Unknown paths/versions fail.
	LifecycleProtocolVersion = 1

	LifecycleIdentityPath   = "/lifecycle/v1/identity"
	LifecycleInventoryPath  = "/lifecycle/v1/inventory"
	LifecycleStopIfIdlePath = "/lifecycle/v1/stop-if-idle"

	// Method-qualified ServeMux patterns. GET patterns also match HEAD in
	// net/http; servers must reject HEAD explicitly to keep these methods exact.
	LifecycleIdentityRoute   = "GET " + LifecycleIdentityPath
	LifecycleInventoryRoute  = "GET " + LifecycleInventoryPath
	LifecycleStopIfIdleRoute = "POST " + LifecycleStopIfIdlePath

	// These fixed bounds keep lifecycle v1 resource use and integer ranges
	// independent of the serving release and host word size. HTTP readers must
	// detect oversized bodies before decoding, rather than silently truncate.
	MaxLifecycleBodyBytes       = 4096
	MaxLifecycleAttachmentCount = 1 << 20
)

// LifecycleInventory is an HTTP-200 snapshot of all active or persisted
// registered attachments, including terminal/revivable records, counting each
// registered attach identity once. An empty snapshot is not a stop/removal proof.
type LifecycleInventory struct {
	AttachmentCount int `json:"attachment_count"`
}

func (inventory LifecycleInventory) Validate() error {
	if inventory.AttachmentCount < 0 || inventory.AttachmentCount > MaxLifecycleAttachmentCount {
		return fmt.Errorf("lifecycle inventory: attachment_count must be between 0 and %d", MaxLifecycleAttachmentCount)
	}
	return nil
}

func EncodeLifecycleInventory(inventory LifecycleInventory) ([]byte, error) {
	if err := inventory.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(inventory)
}

// DecodeLifecycleInventory requires exactly attachment_count as an integer.
// The caller must require HTTP 200; a failure body never proves idle inventory.
func DecodeLifecycleInventory(body []byte) (LifecycleInventory, error) {
	var inventory LifecycleInventory
	if err := decodeLifecycleObject(body, map[string]any{
		"attachment_count": &inventory.AttachmentCount,
	}); err != nil {
		return LifecycleInventory{}, fmt.Errorf("decode lifecycle inventory: %w", err)
	}
	if err := inventory.Validate(); err != nil {
		return LifecycleInventory{}, err
	}
	return inventory, nil
}

// EncodeStopIfIdleRequest returns the entire empty request body. There is no
// JSON request DTO: even an empty object or whitespace is malformed.
func EncodeStopIfIdleRequest() []byte { return nil }

func DecodeStopIfIdleRequest(body []byte) error {
	if len(body) != 0 {
		return fmt.Errorf("lifecycle stop-if-idle: request body must be empty")
	}
	return nil
}

// ErrLifecycleBusy denotes HTTP 409: attach admission, serving state and
// registration are unchanged. Clients must not depend on diagnostic body text.
var ErrLifecycleBusy = errors.New("lifecycle stop-if-idle: daemon has registered attachments")

// ValidateStopIfIdleResponse accepts only HTTP 204 with zero body bytes. The
// server must close attach admission and atomically prove its complete inventory
// empty under the same guard before returning success. Success is quiescence,
// not process termination, kernel absence or permission to unregister by itself.
func ValidateStopIfIdleResponse(statusCode int, body []byte) error {
	switch statusCode {
	case http.StatusNoContent:
		if len(body) != 0 {
			return fmt.Errorf("lifecycle stop-if-idle: HTTP 204 body must be empty")
		}
		return nil
	case http.StatusConflict:
		return ErrLifecycleBusy
	default:
		return fmt.Errorf("lifecycle stop-if-idle: unexpected HTTP status %d", statusCode)
	}
}

// Lifecycle objects are flat and closed. Tokenizing keys before decoding values
// preserves duplicate detection and exact case matching that struct unmarshaling
// would otherwise lose; null must not masquerade as a valid zero count/minor.
func decodeLifecycleObject(body []byte, fields map[string]any) error {
	if len(body) > MaxLifecycleBodyBytes {
		return fmt.Errorf("body exceeds %d bytes", MaxLifecycleBodyBytes)
	}
	if !utf8.Valid(body) {
		return fmt.Errorf("body is not UTF-8")
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("read object: %w", err)
	}
	if token != json.Delim('{') {
		return fmt.Errorf("body must be an object")
	}
	seen := make(map[string]bool, len(fields))
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return fmt.Errorf("read field name: %w", err)
		}
		key, ok := token.(string)
		if !ok {
			return fmt.Errorf("field name must be a string")
		}
		destination, ok := fields[key]
		if !ok {
			return fmt.Errorf("unknown field %q", key)
		}
		if seen[key] {
			return fmt.Errorf("duplicate field %q", key)
		}
		seen[key] = true
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return fmt.Errorf("read field %q: %w", key, err)
		}
		if bytes.Equal(value, []byte("null")) {
			return fmt.Errorf("field %q must not be null", key)
		}
		if err := json.Unmarshal(value, destination); err != nil {
			return fmt.Errorf("decode field %q: %w", key, err)
		}
	}
	if _, err := decoder.Token(); err != nil {
		return fmt.Errorf("close object: %w", err)
	}
	for key := range fields {
		if !seen[key] {
			return fmt.Errorf("missing field %q", key)
		}
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err != nil {
			return fmt.Errorf("trailing data: %w", err)
		}
		return fmt.Errorf("trailing data")
	}
	return nil
}
