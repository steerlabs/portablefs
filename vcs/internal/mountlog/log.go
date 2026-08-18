// Package mountlog writes the private per-mount operational event stream.
// Event records are observational: lifecycle decisions are carried by typed
// results and are never reconstructed from log contents.
package mountlog

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"

	"github.com/steerlabs/portablefs/vcs/internal/mountenrollment"
	"github.com/steerlabs/portablefs/vcs/internal/mountrecord"
	"github.com/steerlabs/portablefs/vcs/internal/privatepath"
)

const (
	recordSchemaVersion = 1
	maxRecordBytes      = 4096
)

// Writer emits one complete JSON object per write. A macOS mount has two
// process owners writing the same file (the wrapper and portablefsd), so the
// backing descriptor must be O_APPEND and a record must never be split across
// writes.
type Writer struct {
	mu            sync.Mutex
	writer        io.Writer
	closer        io.Closer
	component     string
	mountIdentity string
}

func New(writer io.Writer, component, mountIdentity string) (*Writer, error) {
	if writer == nil {
		return nil, fmt.Errorf("mount event writer is nil")
	}
	if !validLabel(component) || !validLabel(mountIdentity) {
		return nil, fmt.Errorf("mount event writer has an invalid component or mount identity")
	}
	return &Writer{writer: writer, component: component, mountIdentity: mountIdentity}, nil
}

// OpenAppend opens the exact path-derived private log. Callers supply only a
// trusted directory and canonical mount path; no control request can choose an
// arbitrary output file.
func OpenAppend(dir, mountPath, component, mountIdentity string) (*Writer, error) {
	file, err := privatepath.OpenFileAppend(mountrecord.LogPath(dir, mountPath))
	if err != nil {
		return nil, fmt.Errorf("open per-mount event log: %w", err)
	}
	writer, err := New(file, component, mountIdentity)
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	writer.closer = file
	return writer, nil
}

type renewalRecord struct {
	SchemaVersion           int    `json:"schemaVersion"`
	Kind                    string `json:"kind"`
	Component               string `json:"component"`
	MountIdentity           string `json:"mountIdentity"`
	ObservedAtMs            int64  `json:"observedAtMs"`
	Sequence                uint64 `json:"sequence"`
	AuthorizationDeadlineMs int64  `json:"authorizationDeadlineMs"`
	LastSuccessMs           int64  `json:"lastSuccessMs,omitempty"`
	NextAttemptMs           int64  `json:"nextAttemptMs,omitempty"`
	ConsecutiveFailures     uint64 `json:"consecutiveFailures,omitempty"`
	Error                   string `json:"error,omitempty"`
}

func (writer *Writer) WriteRenewal(event mountenrollment.RenewalEvent) error {
	if writer == nil {
		return fmt.Errorf("mount event writer is closed")
	}
	if !validRenewalKind(event.Kind) || event.ObservedAt.IsZero() || event.Status.Sequence == 0 || event.Status.AuthorizationDeadline.IsZero() {
		return fmt.Errorf("renewal event is incomplete")
	}
	record := renewalRecord{
		SchemaVersion:           recordSchemaVersion,
		Kind:                    "renewal." + string(event.Kind),
		Component:               writer.component,
		MountIdentity:           writer.mountIdentity,
		ObservedAtMs:            event.ObservedAt.UnixMilli(),
		Sequence:                event.Status.Sequence,
		AuthorizationDeadlineMs: event.Status.AuthorizationDeadline.UnixMilli(),
		ConsecutiveFailures:     event.Status.ConsecutiveFailures,
		Error:                   event.Status.LastError,
	}
	if !event.Status.LastSuccess.IsZero() {
		record.LastSuccessMs = event.Status.LastSuccess.UnixMilli()
	}
	if !event.Status.NextAttempt.IsZero() {
		record.NextAttemptMs = event.Status.NextAttempt.UnixMilli()
	}
	line, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("encode renewal event: %w", err)
	}
	line = append(line, '\n')
	if len(line) > maxRecordBytes {
		return fmt.Errorf("renewal event exceeds the %d-byte log record bound", maxRecordBytes)
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.writer == nil {
		return fmt.Errorf("mount event writer is closed")
	}
	n, err := writer.writer.Write(line)
	if err != nil {
		return fmt.Errorf("append renewal event: %w", err)
	}
	if n != len(line) {
		return fmt.Errorf("append renewal event: %w", io.ErrShortWrite)
	}
	return nil
}

func (writer *Writer) Close() error {
	if writer == nil {
		return nil
	}
	writer.mu.Lock()
	defer writer.mu.Unlock()
	if writer.closer == nil {
		writer.writer = nil
		return nil
	}
	err := writer.closer.Close()
	writer.closer = nil
	writer.writer = nil
	return err
}

func validRenewalKind(kind mountenrollment.RenewalEventKind) bool {
	switch kind {
	case mountenrollment.RenewalScheduled,
		mountenrollment.RenewalSucceeded,
		mountenrollment.RenewalRetrying,
		mountenrollment.RenewalDenied,
		mountenrollment.RenewalCutoff,
		mountenrollment.RenewalStopped:
		return true
	default:
		return false
	}
}

func validLabel(value string) bool {
	return value != "" && len(value) <= 128 && strings.IndexFunc(value, func(r rune) bool {
		return r < 0x20 || r == 0x7f
	}) == -1
}
