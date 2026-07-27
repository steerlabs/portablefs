package histworker

import (
	"encoding/json"
	"io"
	"sync"
	"time"
)

// Logger emits redacted structured JSON lines. Fields are caller-chosen and
// must never include secrets: the worker logs identities (cut ids, digests,
// domains, key names) and outcomes, never DSNs, credentials, or payloads.
type Logger struct {
	mu   *sync.Mutex
	out  io.Writer
	base map[string]any
	now  func() time.Time
}

// NewLogger writes JSON lines to out (nil discards).
func NewLogger(out io.Writer) *Logger {
	if out == nil {
		out = io.Discard
	}
	return &Logger{mu: &sync.Mutex{}, out: out, now: time.Now}
}

// With returns a child logger carrying additional fields.
func (l *Logger) With(fields map[string]any) *Logger {
	merged := make(map[string]any, len(l.base)+len(fields))
	for k, v := range l.base {
		merged[k] = v
	}
	for k, v := range fields {
		merged[k] = v
	}
	return &Logger{mu: l.mu, out: l.out, base: merged, now: l.now}
}

func (l *Logger) emit(level, event string, err error, fields map[string]any) {
	entry := make(map[string]any, len(l.base)+len(fields)+4)
	for k, v := range l.base {
		entry[k] = v
	}
	for k, v := range fields {
		entry[k] = v
	}
	entry["ts"] = l.now().UTC().Format(time.RFC3339Nano)
	entry["level"] = level
	entry["event"] = event
	if err != nil {
		message := err.Error()
		if len(message) > 2048 {
			message = message[:2048]
		}
		entry["error"] = message
	}
	line, marshalErr := json.Marshal(entry)
	if marshalErr != nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.out.Write(append(line, '\n'))
}

// Info logs one informational event.
func (l *Logger) Info(event string, fields map[string]any) { l.emit("info", event, nil, fields) }

// Warn logs one degraded-but-continuing event: work that was bounded away, a
// budget that ran out, an adaptive limit that had to shrink. It is deliberately
// distinct from Error, which means the pass could not do what it was asked.
func (l *Logger) Warn(event string, fields map[string]any) { l.emit("warn", event, nil, fields) }

// Error logs one failure event.
func (l *Logger) Error(event string, err error, fields map[string]any) {
	l.emit("error", event, err, fields)
}
