// Command pfs-powerloss-driver writes the workload the power-loss harness
// makes claims about, through a real PortableFS mount, and records exactly
// what it is entitled to claim.
//
// It is a separate process from the harness for a reason that is not
// stylistic: the harness runs as root because it drives loop devices, a
// device-mapper target and mounts, while the data plane must never run as
// root, and a kernel FUSE mount is reachable only by the identity that mounted
// it. So the harness spawns this driver as the unprivileged volume identity.
//
// The driver cannot take device-mapper marks itself - that needs root - so it
// asks. Every mark request goes out on stdout as one line, and the harness
// replies on stdin. That ordering is the whole point: the mark must land in
// the write log after the fsync returned and before the next write starts, or
// a later replay would cut in the wrong place. Human-readable progress goes to
// stderr, which is never part of the protocol.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/steerlabs/portablefs/vcs/test/powerloss"
)

// markPattern also constrains --prefix. The prefix becomes a path element
// inside the volume and appears in ledger paths the verifier joins, so it is
// held to the same narrow shape a mark is.
var markPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,62}$`)

func main() {
	if err := run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "pfs-powerloss-driver: %v\n", err)
		os.Exit(1)
	}
}

type options struct {
	mount       string
	volume      string
	ledger      string
	label       string
	instrument  string
	prefix      string
	checkpoints int
	size        int64
	subdirs     int
	duration    time.Duration
}

func run(arguments []string, acks io.Reader, requests io.Writer, progress io.Writer) error {
	flags := flag.NewFlagSet("pfs-powerloss-driver", flag.ContinueOnError)
	flags.SetOutput(progress)
	var opts options
	flags.StringVar(&opts.mount, "mount", "", "mountpoint of the PortableFS volume to drive")
	flags.StringVar(&opts.volume, "volume", "", "volume directory name inside the XFS cell, recorded in the ledger")
	flags.StringVar(&opts.ledger, "ledger", "", "path the ledger of checkpoints is written to")
	flags.StringVar(&opts.label, "label", "", "prose description of this run, echoed in every report")
	flags.StringVar(&opts.instrument, "instrument", string(powerloss.InstrumentDevice),
		"which harness is driving: device (dm-log-writes marks over the request channel) or process (no marks)")
	flags.StringVar(&opts.prefix, "prefix", "checkpoints", "subtree of the volume this run writes into; every run needs its own, because checkpoint files are write-once")
	flags.IntVar(&opts.checkpoints, "checkpoints", 16, "number of fsynced checkpoints to write")
	flags.Int64Var(&opts.size, "size", 64*1024, "bytes per checkpoint file")
	flags.IntVar(&opts.subdirs, "subdirs", 4, "spread checkpoints over this many directories so directory metadata is exercised too")
	flags.DurationVar(&opts.duration, "duration", 0, "stop early after this long; zero runs every checkpoint")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected positional arguments: %v", flags.Args())
	}
	if opts.mount == "" || opts.volume == "" || opts.ledger == "" {
		return errors.New("--mount, --volume and --ledger are required")
	}
	if opts.checkpoints < 1 || opts.size < 1 || opts.subdirs < 1 {
		return errors.New("--checkpoints, --size and --subdirs must all be positive")
	}
	if !markPattern.MatchString(opts.prefix) {
		return fmt.Errorf("--prefix %q must be a single lowercase path element", opts.prefix)
	}
	instrument := powerloss.Instrument(opts.instrument)
	switch instrument {
	case powerloss.InstrumentDevice, powerloss.InstrumentProcess:
	default:
		return fmt.Errorf("--instrument must be %q or %q", powerloss.InstrumentDevice, powerloss.InstrumentProcess)
	}
	channel := &markChannel{requests: requests, acks: bufio.NewReader(acks), enabled: instrument == powerloss.InstrumentDevice}
	return drive(opts, instrument, channel, progress)
}

// markChannel is the driver's half of the mark protocol.
type markChannel struct {
	requests io.Writer
	acks     *bufio.Reader
	enabled  bool
}

// take asks the harness to insert a mark and blocks until it confirms. A
// failure here is fatal to the run rather than skippable: continuing without
// the mark would leave every later checkpoint asserted at the wrong cut.
func (c *markChannel) take(label string) error {
	if !c.enabled {
		return nil
	}
	if _, err := fmt.Fprintf(c.requests, "mark %s\n", label); err != nil {
		return fmt.Errorf("requesting mark %q: %w", label, err)
	}
	reply, err := c.acks.ReadString('\n')
	if err != nil {
		return fmt.Errorf("waiting for mark %q to be taken: %w", label, err)
	}
	reply = strings.TrimSpace(reply)
	if reply != "ok" {
		return fmt.Errorf("the harness could not take mark %q: %s", label, reply)
	}
	return nil
}

// drive writes the workload. Each round writes two files:
//
//   - one that is written, fsynced, and only then marked. That is the file the
//     product contract covers, and the only one presence is ever demanded of.
//   - one that is written and closed but never fsynced. The authority
//     acknowledges its write transaction once the bytes are applied to the XFS
//     inode, so it is in the page cache and nowhere else. It exists so that a
//     replayed cut has something the contract deliberately promises nothing
//     about, and so the stale-data check has material to work on.
//
// The fsynced file is written first and the un-fsynced one second, so at every
// mark there is always at least one write in flight that the cut may discard.
func drive(opts options, instrument powerloss.Instrument, channel *markChannel, progress io.Writer) error {
	ledger := &powerloss.Ledger{Volume: opts.volume, Instrument: instrument, Label: opts.label}
	deadline := time.Time{}
	if opts.duration > 0 {
		deadline = time.Now().Add(opts.duration)
	}
	for round := range opts.checkpoints {
		if !deadline.IsZero() && time.Now().After(deadline) {
			fmt.Fprintf(progress, "pfs-powerloss-driver: stopping after %d checkpoints, the duration bound was reached\n", round)
			break
		}
		directory := fmt.Sprintf("%s/dir-%02d", opts.prefix, round%opts.subdirs)
		if err := os.MkdirAll(filepath.Join(opts.mount, directory), 0o700); err != nil {
			return fmt.Errorf("creating %s: %w", directory, err)
		}
		index := len(ledger.Checkpoints)
		durable := fmt.Sprintf("%s/durable-%04d", directory, round)
		content := powerloss.GenerateContent(index, opts.size)
		if err := writeFile(filepath.Join(opts.mount, durable), content, true); err != nil {
			return fmt.Errorf("writing durable checkpoint %d: %w", round, err)
		}
		// The directory entry needs its own durability barrier: fsyncing the
		// file makes its bytes durable, not the name that reaches them. This is
		// exactly the directory-fsync assumption the harness exists to test, so
		// the claim is only recorded once both have returned success.
		if err := syncDirectory(filepath.Join(opts.mount, directory)); err != nil {
			return fmt.Errorf("syncing the directory of checkpoint %d: %w", round, err)
		}
		mark := ""
		if instrument == powerloss.InstrumentDevice {
			mark = fmt.Sprintf("ckpt-%04d", round)
		}
		if err := channel.take(mark); err != nil {
			return err
		}
		ledger.Add(durable, content, mark, powerloss.Fsynced)

		index = len(ledger.Checkpoints)
		acknowledged := fmt.Sprintf("%s/acknowledged-%04d", directory, round)
		content = powerloss.GenerateContent(index, opts.size)
		if err := writeFile(filepath.Join(opts.mount, acknowledged), content, false); err != nil {
			return fmt.Errorf("writing acknowledged checkpoint %d: %w", round, err)
		}
		ledger.Add(acknowledged, content, "", powerloss.Acknowledged)

		// The ledger is republished after every round and is fsynced by Save.
		// The harness kills the authority at a moment this driver does not
		// choose, so the ledger on disk has to be correct at every instant, not
		// only at a clean exit.
		if err := ledger.Save(opts.ledger); err != nil {
			return err
		}
		fmt.Fprintf(progress, "pfs-powerloss-driver: checkpoint %d durable (%s), %s acknowledged only\n", round, durable, acknowledged)
	}
	if len(ledger.Checkpoints) == 0 {
		return errors.New("no checkpoint completed; a run that recorded nothing must fail rather than report a vacuous pass")
	}
	return ledger.Save(opts.ledger)
}

// writeFile writes content and, when durable is set, fsyncs before closing.
// The fsync is what the whole harness turns on, so its error is never folded
// into the close error: a failed fsync must not be recorded as a durable
// checkpoint under any circumstances.
func writeFile(pathname string, content []byte, durable bool) error {
	file, err := os.OpenFile(pathname, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(content); err != nil {
		_ = file.Close()
		return err
	}
	if durable {
		if err := file.Sync(); err != nil {
			_ = file.Close()
			return fmt.Errorf("fsync did not return success: %w", err)
		}
	}
	return file.Close()
}

func syncDirectory(pathname string) error {
	directory, err := os.Open(pathname)
	if err != nil {
		return err
	}
	if err := directory.Sync(); err != nil {
		_ = directory.Close()
		return err
	}
	return directory.Close()
}
