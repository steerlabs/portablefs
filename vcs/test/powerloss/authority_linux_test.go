//go:build linux

package powerloss

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// The product-level instruments. Both drive a real portablefs-mount-v3 against
// a real portablefs-authority over a real XFS cell, and both assert the same
// contract in the same words. They differ only in what they take away.

// TestFsyncedWritesSurvivePowerLoss is the test the harness exists for.
//
// It stacks dm-log-writes under the XFS the authority serves, drives the mount
// with a workload that fsyncs at known points, kills the authority and the
// mount outright, and then replays the recorded write log to every one of
// those points and to a sweep of the filesystem's own barriers. At each replay
// it mounts the reconstructed device - which is what runs XFS log recovery -
// and requires that every write whose fsync had returned success is present
// and byte-exact, that no un-fsynced write left stale data behind, and that
// xfs_repair -n finds nothing it would correct.
//
// What it does not do is claim anything about a write that was merely
// acknowledged. See Expectations for why that line is where it is.
func TestFsyncedWritesSurvivePowerLoss(t *testing.T) {
	gate := requireAuthorityGate(t)
	requireLogWrites(t, gate.hostGate)

	playground := newDevicePlayground(t, gate.hostGate, gate.imageSize)
	cell := provisionCell(t, gate, playground.mountpoint)
	authority := cell.startAuthority(t, "power-cut")
	mount, mountpoint := cell.startMount(t, "power-cut", "access-0.token")

	ledgerPath := filepath.Join(gate.workDir, "ledger.json")
	driver := cell.runDriver(t, mountpoint, ledgerPath, InstrumentDevice, playground.device.Mark,
		"--prefix", "power-cut",
		"--checkpoints", fmt.Sprint(gate.checkpoints),
		"--label", "power cut under a live authority and kernel FUSE mount",
	)
	if err := driver.wait(t, 10*time.Minute); err != nil {
		driver.dump(t)
		authority.dump(t)
		mount.dump(t)
		t.Fatalf("the workload driver failed: %v", err)
	}

	// Power loss takes everything at once. The authority goes first because it
	// is the only process that can still be writing to the device; the mount
	// then has nothing to talk to, which is exactly the state a cut leaves.
	authority.kill(t)
	mount.kill(t)
	releaseMount(gate.runner, mountpoint)

	fullLog, closeLog := playground.cut(t, "power-cut")
	defer func() { _ = closeLog() }()
	cutEntry, found := fullLog.MarkEntry("power-cut")
	if !found {
		t.Fatal("the power-cut mark is not in the write log; the mark channel was broken and no cut can be trusted")
	}
	log, err := fullLog.Through(cutEntry)
	if err != nil {
		t.Fatalf("truncating the write log at the power cut: %v", err)
	}
	ledger, err := LoadLedger(ledgerPath)
	if err != nil {
		t.Fatalf("reading the workload's ledger: %v", err)
	}
	t.Logf("the workload recorded %d checkpoints; the device recorded %d writes up to the cut", len(ledger.Checkpoints), len(log.Entries))
	verifyEveryCut(t, gate.hostGate, log, ledger, playground.options, gate.imageSize, gate.barriers)
}

// TestAuthorityKillDuringWritesKeepsFsyncedData is the weaker, cheaper
// instrument, and it says so.
//
// SIGKILL removes the authority process but not the kernel's dirty page cache,
// so this is NOT a power-loss test and does not stand in for one. What it
// covers instead is the half of the story the device instrument cannot reach:
// that the authority restarts over a volume it was killed in the middle of
// writing, that a fresh mount attaches to it, that the volume serves again,
// and that nothing an fsync had already promised was lost along the way. The
// kill lands at a different point in each round.
func TestAuthorityKillDuringWritesKeepsFsyncedData(t *testing.T) {
	gate := requireAuthorityGate(t)
	loop, err := AttachLoop(gate.runner, filepath.Join(gate.workDir, "process-cell.img"), gate.imageSize)
	if err != nil {
		t.Fatalf("creating the cell image: %v", err)
	}
	t.Cleanup(func() {
		if err := loop.Detach(); err != nil {
			t.Errorf("detaching the cell image: %v", err)
		}
	})
	if _, err := gate.runner.Run("mkfs.xfs", "-q", "-f", loop.Device); err != nil {
		t.Fatalf("making the cell filesystem: %v", err)
	}
	mountpoint := filepath.Join(gate.workDir, "process-cell")
	unmount, err := MountXFS(gate.runner, loop.Device, mountpoint, "prjquota,nodev,nosuid,noexec,noatime")
	if err != nil {
		t.Fatalf("mounting the cell: %v", err)
	}
	t.Cleanup(func() {
		if err := unmount(); err != nil {
			t.Errorf("unmounting the cell: %v", err)
		}
	})
	cell := provisionCell(t, gate, mountpoint)

	// Each round kills the authority a different distance into the workload.
	// The delays are fixed rather than random: a harness whose coverage changes
	// run to run cannot say what a green result covered, and a failure that
	// cannot be reproduced from the test name is a failure nobody can fix.
	delays := []time.Duration{150 * time.Millisecond, 700 * time.Millisecond, 2 * time.Second, 4500 * time.Millisecond}
	for round := range gate.killRounds {
		delay := delays[round%len(delays)]
		t.Run(fmt.Sprintf("killed-after-%s", delay), func(t *testing.T) {
			runKillRound(t, gate, cell, round, delay)
		})
	}
}

func runKillRound(t *testing.T, gate authorityGate, cell *cell, round int, delay time.Duration) {
	t.Helper()
	authority := cell.startAuthority(t, fmt.Sprintf("kill-%d", round))
	mount, mountpoint := cell.startMount(t, fmt.Sprintf("kill-%d", round), fmt.Sprintf("access-%d.token", 1+2*round))
	ledgerPath := filepath.Join(gate.workDir, fmt.Sprintf("process-ledger-%d.json", round))
	driver := cell.runDriver(t, mountpoint, ledgerPath, InstrumentProcess, nil,
		// Every round writes into its own subtree: checkpoint files are
		// write-once, and a round that collided with the previous one would
		// fail on O_EXCL rather than on anything about durability.
		"--prefix", fmt.Sprintf("kill-%d", round),
		"--checkpoints", "100000",
		// The kill is what ends this workload. The duration bound is only a
		// guillotine: if the kill never landed the round would otherwise write
		// until it filled the volume's quota, and a quota failure would be
		// reported as a durability failure.
		"--duration", "60s",
		"--label", fmt.Sprintf("authority SIGKILLed %s into a sustained write workload", delay),
	)

	// The kill lands while the workload is in flight. If the driver has already
	// finished, the round proved nothing about a kill during writes and must
	// say so rather than pass.
	time.Sleep(delay)
	if driver.exited() {
		t.Fatalf("the workload finished before the %s kill; this round could not cut into a write and must not report a pass", delay)
	}
	authority.kill(t)
	// The driver is now writing into a mount with no authority. It will fail,
	// which is correct and expected; its ledger is durable up to its last
	// completed checkpoint either way.
	_ = driver.wait(t, 2*time.Minute)
	driver.kill(t)
	mount.kill(t)
	releaseMount(gate.runner, mountpoint)

	ledger, err := LoadLedger(ledgerPath)
	if err != nil {
		driver.dump(t)
		t.Fatalf("reading the workload's ledger: %v", err)
	}
	durable := 0
	for _, checkpoint := range ledger.Checkpoints {
		if checkpoint.Durability == Fsynced {
			durable++
		}
	}
	if durable == 0 {
		t.Fatalf("the workload completed no fsynced checkpoint before the %s kill; this round asserted nothing", delay)
	}

	// Restart over the volume the authority was killed in the middle of
	// writing, and attach a new mount to it.
	restarted := cell.startAuthority(t, fmt.Sprintf("restart-%d", round))
	t.Cleanup(func() { restarted.kill(t) })
	freshMount, freshMountpoint := cell.startMount(t, fmt.Sprintf("restart-%d", round), fmt.Sprintf("access-%d.token", 2+2*round))
	t.Cleanup(func() {
		freshMount.kill(t)
		releaseMount(gate.runner, freshMountpoint)
	})

	expectations, err := ExpectationsAfterRestart(ledger)
	if err != nil {
		t.Fatalf("deriving expectations: %v", err)
	}
	// Verification reads the served XFS directly. Root can, the service
	// identity's FUSE mount is not reachable from this process, and the
	// question being asked - what is on the volume - is answered there.
	report := Verify(cell.volumeRoot, expectations, -1)
	if err := report.Err(); err != nil {
		restarted.dump(t)
		t.Fatalf("after the %s kill and restart:\n%v", delay, err)
	}
	t.Logf("%s kill: %d fsynced checkpoints intact, %d un-fsynced writes also survived (a SIGKILL does not drop page cache)",
		delay, report.Durable, report.Surviving)

	// The volume must also still serve. A restart that preserved every byte and
	// then refused to work would satisfy the durability check and be useless,
	// so the same driver runs one more checkpoint through the fresh mount.
	liveness := filepath.Join(gate.workDir, fmt.Sprintf("process-liveness-%d.json", round))
	probe := cell.runDriver(t, freshMountpoint, liveness, InstrumentProcess, nil,
		"--prefix", fmt.Sprintf("probe-%d", round),
		"--checkpoints", "1",
		"--subdirs", "1",
		"--label", "liveness probe after restart",
	)
	if err := probe.wait(t, 2*time.Minute); err != nil {
		probe.dump(t)
		restarted.dump(t)
		t.Fatalf("after the %s kill the restarted volume does not serve: %v", delay, err)
	}
}
