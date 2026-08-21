//go:build linux

package powerloss

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// This file is the harness testing itself, and the kernel underneath it.
//
// Neither test here involves the authority. They exist because every claim the
// authority-level instrument makes rests on two things being true first: that
// this package's replayer reconstructs what the kernel actually wrote, and
// that XFS's own fsync is honest on this machine. If either is false, a green
// authority run means nothing. Running these separately also means a failure
// says which layer broke.

// devicePlayground stacks dm-log-writes under a fresh XFS and mounts it.
type devicePlayground struct {
	gate       hostGate
	device     *LogWrites
	mountpoint string
	options    string
	imageSize  int64
	unmount    func() error
}

func newDevicePlayground(t *testing.T, gate hostGate, imageSize int64) *devicePlayground {
	t.Helper()
	// The device-mapper namespace is kernel-global and shared with every other
	// job on this runner, so the name carries the pid rather than colliding
	// with a concurrent run.
	name := fmt.Sprintf("pfs-powerloss-%d", os.Getpid())
	device, err := CreateLogWrites(gate.runner, gate.workDir, name, imageSize, 2*imageSize)
	if err != nil {
		t.Fatalf("stacking dm-log-writes: %v", err)
	}
	playground := &devicePlayground{
		gate:       gate,
		device:     device,
		mountpoint: filepath.Join(gate.workDir, "cell"),
		// The replayed images are mounted with exactly these options too. XFS
		// rebuilds quota metadata during recovery only when quotas are enabled,
		// so a replay mounted without prjquota leaves quota blocks xfs_repair
		// would correct - a difference caused by the harness, not by the cut.
		options:   "prjquota,nodev,nosuid,noexec,noatime",
		imageSize: imageSize,
	}
	t.Cleanup(func() {
		if err := playground.device.Remove(); err != nil {
			// A leaked target breaks the NEXT run rather than this one, which
			// is the worst way for a harness to fail, so it fails this one.
			t.Errorf("tearing the device-mapper stack down: %v", err)
		}
	})
	if _, err := gate.runner.Run("mkfs.xfs", "-q", "-f", device.Path); err != nil {
		t.Fatalf("making the filesystem: %v", err)
	}
	unmount, err := MountXFS(gate.runner, device.Path, playground.mountpoint, playground.options)
	if err != nil {
		t.Fatalf("mounting the filesystem: %v", err)
	}
	playground.unmount = unmount
	// Registered AFTER the target teardown so cleanup runs it FIRST. A failure
	// anywhere in a test leaves the cell mounted, and dmsetup cannot remove a
	// target a mounted filesystem is holding - which would leak the target and
	// both loop devices into the next run on this machine.
	t.Cleanup(func() {
		if err := playground.unmount(); err != nil {
			t.Errorf("unmounting the cell during teardown: %v", err)
		}
	})
	return playground
}

// cut ends the recorded run: it takes the mark that stands for the instant
// power was lost, then unmounts and releases the device so the log can be
// read. Everything the unmount writes lands after that mark and is truncated
// away by Through.
func (p *devicePlayground) cut(t *testing.T, label string) (*Log, func() error) {
	t.Helper()
	if err := p.device.Mark(label); err != nil {
		t.Fatalf("taking the %s mark: %v", label, err)
	}
	if err := p.unmount(); err != nil {
		t.Fatalf("unmounting: %v", err)
	}
	p.unmount = func() error { return nil }
	// The target's destructor is what flushes the tail of the log, so it has to
	// run before the log is read. The loop devices stay attached.
	if err := p.device.Release(); err != nil {
		t.Fatalf("releasing the device-mapper target: %v", err)
	}
	log, closeLog, err := p.device.ParseLogDevice()
	if err != nil {
		t.Fatalf("reading the write log: %v", err)
	}
	return log, closeLog
}

// writeWorkload lays down the same shape the real driver does, but directly on
// XFS, so the engine test does not depend on the authority being correct.
func (p *devicePlayground) writeWorkload(t *testing.T, volume string, rounds int, size int64) *Ledger {
	t.Helper()
	ledger := &Ledger{Volume: volume, Instrument: InstrumentDevice, Label: "direct XFS workload, no authority in the path"}
	root := filepath.Join(p.mountpoint, volume)
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatalf("creating the volume directory: %v", err)
	}
	for round := range rounds {
		durable := fmt.Sprintf("durable-%04d", round)
		content := GenerateContent(len(ledger.Checkpoints), size)
		writeThrough(t, filepath.Join(root, durable), content, true)
		syncDir(t, root)
		mark := fmt.Sprintf("ckpt-%04d", round)
		if err := p.device.Mark(mark); err != nil {
			t.Fatalf("taking mark %s: %v", mark, err)
		}
		ledger.Add(durable, content, mark, Fsynced)

		acknowledged := fmt.Sprintf("acknowledged-%04d", round)
		content = GenerateContent(len(ledger.Checkpoints), size)
		writeThrough(t, filepath.Join(root, acknowledged), content, false)
		ledger.Add(acknowledged, content, "", Acknowledged)
	}
	if err := ledger.Validate(); err != nil {
		t.Fatalf("the workload recorded an unusable ledger: %v", err)
	}
	return ledger
}

func writeThrough(t *testing.T, pathname string, content []byte, durable bool) {
	t.Helper()
	file, err := os.OpenFile(pathname, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatalf("creating %s: %v", pathname, err)
	}
	if _, err := file.Write(content); err != nil {
		t.Fatalf("writing %s: %v", pathname, err)
	}
	if durable {
		if err := file.Sync(); err != nil {
			t.Fatalf("fsync of %s did not return success: %v", pathname, err)
		}
	}
	if err := file.Close(); err != nil {
		t.Fatalf("closing %s: %v", pathname, err)
	}
}

func syncDir(t *testing.T, pathname string) {
	t.Helper()
	directory, err := os.Open(pathname)
	if err != nil {
		t.Fatalf("opening %s: %v", pathname, err)
	}
	if err := directory.Sync(); err != nil {
		t.Fatalf("directory fsync of %s did not return success: %v", pathname, err)
	}
	if err := directory.Close(); err != nil {
		t.Fatalf("closing %s: %v", pathname, err)
	}
}

// TestReplayReproducesTheDeviceTheKernelWrote is the calibration for every
// other claim in this package.
//
// It replays the ENTIRE log - including the writes the unmount performed -
// onto a zeroed image and requires the result to be byte-identical to the
// image the kernel was writing to all along. Nothing about the filesystem is
// examined. If this passes, the log format transcription, the sector-unit
// arithmetic and the discard handling in logwrites.go all agree with the
// running kernel, and a cut taken from that log is a real device state rather
// than this harness's opinion of one.
func TestReplayReproducesTheDeviceTheKernelWrote(t *testing.T) {
	gate := requireDeviceGate(t)
	// A small device keeps the byte comparison cheap; this test measures the
	// replayer, not throughput. XFS refuses anything under 300MB.
	const imageSize = 512 << 20
	playground := newDevicePlayground(t, gate.hostGate, imageSize)
	playground.writeWorkload(t, "engine-volume", 4, 32*1024)
	log, closeLog := playground.cut(t, "power-cut")
	defer func() { _ = closeLog() }()

	replayed := filepath.Join(gate.workDir, "engine-replay.img")
	if err := ReplayImage(log, replayed, imageSize, len(log.Entries)-1); err != nil {
		t.Fatalf("replaying the whole log: %v", err)
	}
	t.Logf("replayed %d log entries (sector size %d)", len(log.Entries), log.SectorSize)
	if err := compareImages(playground.device.Target.Image, replayed); err != nil {
		t.Fatalf("the replayed image is not the device the kernel wrote: %v", err)
	}
}

// compareImages reports the first differing offset, which is the only useful
// thing to say about two multi-gigabyte images that should be identical.
func compareImages(left, right string) error {
	first, err := os.Open(left)
	if err != nil {
		return err
	}
	defer func() { _ = first.Close() }()
	second, err := os.Open(right)
	if err != nil {
		return err
	}
	defer func() { _ = second.Close() }()
	const chunk = 1 << 20
	leftBuffer := make([]byte, chunk)
	rightBuffer := make([]byte, chunk)
	var offset int64
	for {
		leftRead, leftErr := io.ReadFull(first, leftBuffer)
		rightRead, rightErr := io.ReadFull(second, rightBuffer)
		if leftRead != rightRead {
			return fmt.Errorf("the images are different lengths (%d against %d bytes read at offset %d)", leftRead, rightRead, offset)
		}
		if !bytes.Equal(leftBuffer[:leftRead], rightBuffer[:rightRead]) {
			for index := range leftRead {
				if leftBuffer[index] != rightBuffer[index] {
					return fmt.Errorf("first difference at byte %d: device has %#x, replay has %#x", offset+int64(index), leftBuffer[index], rightBuffer[index])
				}
			}
		}
		offset += int64(leftRead)
		if leftErr != nil || rightErr != nil {
			if leftErr == nil || rightErr == nil {
				return fmt.Errorf("the images are different lengths at offset %d", offset)
			}
			return nil
		}
	}
}

// TestXFSHonoursFsyncAtEveryCut is the kernel-level control for the authority
// test. It asserts the same contract, in the same words, against a workload
// that never touched PortableFS. A failure here is a finding about XFS, the
// kernel or the block stack, and it means the authority-level result cannot be
// interpreted at all.
func TestXFSHonoursFsyncAtEveryCut(t *testing.T) {
	gate := requireDeviceGate(t)
	const imageSize = 512 << 20
	playground := newDevicePlayground(t, gate.hostGate, imageSize)
	ledger := playground.writeWorkload(t, "engine-volume", 6, 32*1024)
	fullLog, closeLog := playground.cut(t, "power-cut")
	defer func() { _ = closeLog() }()
	cut, found := fullLog.MarkEntry("power-cut")
	if !found {
		t.Fatal("the power-cut mark is not in the log; the mark channel was broken and no cut can be trusted")
	}
	log, err := fullLog.Through(cut)
	if err != nil {
		t.Fatalf("truncating the log at the power cut: %v", err)
	}
	verifyEveryCut(t, gate.hostGate, log, ledger, playground.options, imageSize, 6)
}

// verifyEveryCut replays each selected cut onto a fresh image, mounts it (which
// is what runs XFS log recovery), checks the durability contract, unmounts and
// then requires xfs_repair -n to find nothing to fix.
//
// Both halves matter. Content that survives on a filesystem xfs_repair would
// rebuild is not a durable filesystem, and a clean xfs_repair over content that
// vanished is not a durable one either.
func verifyEveryCut(t *testing.T, gate hostGate, log *Log, ledger *Ledger, mountOptions string, imageSize int64, barrierBudget int) {
	t.Helper()
	points, err := SelectPoints(log, ledger, barrierBudget)
	if err != nil {
		t.Fatalf("selecting replay points: %v", err)
	}
	t.Logf("replaying %d cuts out of a %d-entry log", len(points), len(log.Entries))
	checkpointCuts := 0
	for _, point := range points {
		name := fmt.Sprintf("entry-%06d-%s", point.EndEntry, point.Kind)
		if point.Kind == PointCheckpoint {
			checkpointCuts++
		}
		t.Run(name, func(t *testing.T) {
			image := filepath.Join(gate.workDir, "replay.img")
			if err := ReplayImage(log, image, imageSize, point.EndEntry); err != nil {
				t.Fatalf("%s: %v", point.Reason, err)
			}
			loop, err := AttachLoopImage(gate.runner, image)
			if err != nil {
				t.Fatalf("attaching the replayed image: %v", err)
			}
			defer func() {
				if err := loop.Detach(); err != nil {
					t.Errorf("detaching the replayed image: %v", err)
				}
			}()
			mountpoint := filepath.Join(gate.workDir, "replay-mount")
			unmount, err := MountXFS(gate.runner, loop.Device, mountpoint, mountOptions)
			if err != nil {
				// A replayed image that will not mount at all is a durability
				// failure, not a skip: the filesystem was supposed to recover.
				t.Fatalf("%s: the replayed filesystem does not mount, so it did not recover: %v", point.Reason, err)
			}
			expectations, err := Expectations(log, ledger, point.EndEntry)
			if err != nil {
				_ = unmount()
				t.Fatalf("deriving expectations: %v", err)
			}
			report := Verify(filepath.Join(mountpoint, ledger.Volume), expectations, point.EndEntry)
			verifyErr := report.Err()
			unmountErr := unmount()
			if verifyErr != nil {
				t.Fatalf("%s:\n%v", point.Reason, verifyErr)
			}
			if unmountErr != nil {
				t.Fatalf("unmounting the replayed filesystem: %v", unmountErr)
			}
			if err := CheckXFS(gate.runner, loop.Device); err != nil {
				t.Fatalf("%s: %v", point.Reason, err)
			}
			t.Logf("%s: %d checkpoints required durable and present, %d un-fsynced writes happened to survive",
				point.Reason, report.Durable, report.Surviving)
		})
	}
	if checkpointCuts == 0 {
		t.Fatal("no cut landed on a checkpoint mark; this run asserted nothing about the fsync contract")
	}
}
