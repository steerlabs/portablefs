package powerloss

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// MarkChannel is a workload driver's half of the mark protocol.
//
// A driver runs as the unprivileged volume identity and cannot take a
// device-mapper mark itself, so it asks the root harness: one "mark <label>"
// line goes out on requests, and the harness answers one line on acks. The
// driver blocks on that answer before it issues anything else, which is the
// whole ordering guarantee: the mark lands in the write log after the
// durability claim it belongs to and before the next operation can reach the
// device. Both workload drivers share this one implementation so the harness
// services exactly one protocol.
type MarkChannel struct {
	requests io.Writer
	acks     *bufio.Reader
}

// NewMarkChannel binds the protocol to the driver's request and answer
// streams, normally its stdout and stdin.
func NewMarkChannel(requests io.Writer, acks io.Reader) *MarkChannel {
	return &MarkChannel{requests: requests, acks: bufio.NewReader(acks)}
}

// Take asks the harness for a mark and blocks until it confirms. A refusal or a
// broken stream is fatal to the run rather than skippable: continuing without
// the mark would leave every later claim asserted at the wrong cut.
func (c *MarkChannel) Take(label string) error {
	if !markPattern.MatchString(label) {
		return fmt.Errorf("powerloss: %q is not a safe mark name", label)
	}
	if _, err := fmt.Fprintf(c.requests, "mark %s\n", label); err != nil {
		return fmt.Errorf("requesting mark %q: %w", label, err)
	}
	reply, err := c.acks.ReadString('\n')
	if err != nil {
		return fmt.Errorf("waiting for mark %q to be taken: %w", label, err)
	}
	if reply = strings.TrimSpace(reply); reply != "ok" {
		return fmt.Errorf("the harness could not take mark %q: %s", label, reply)
	}
	return nil
}
