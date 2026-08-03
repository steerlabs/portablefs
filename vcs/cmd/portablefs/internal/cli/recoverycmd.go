package cli

// EVERY MESSAGE MUST NAME A COMMAND THAT EXISTS AND CAN MAKE PROGRESS.
//
// `portablefs recovery` is the command the product had been instructing
// operators to run since before it existed. A mount whose write-back store held
// a terminally conflict/corrupt recovery job produced this, live:
//
//	portablefs umount                  -> "run portablefs umount --force"
//	portablefs umount --force          -> "durably park abandoned FSKit store:
//	                                       validate recovery registry: job is
//	                                       terminally conflict and requires
//	                                       explicit recovery resolution (409)"
//	portablefs umount --discard-record -> "run portablefs umount --force ... first"
//
// Three commands, one cycle, and the phrase "explicit recovery resolution"
// existed in exactly one place in the product: the error that refused. There was
// no command and no daemon route that performed one. The operator escaped only
// by moving our state directory by hand.
//
// `recovery list` shows what is in the store, without a lock and without
// changing anything, so the question "why will my unmount not finish" is
// answerable while a daemon still owns the store. `recovery resolve` performs
// the resolution the refusals name: it quarantines a terminal job's bytes (never
// deletes them), states exactly what was lost, and clears the block.

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/portablefsd"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// recoveryStore is one write-back store a mount could be using, with the
// transport that owns it. A mount path resolves to at most two candidates (the
// FUSE store the CLI owns and the FSKit store portablefsd owns) and the command
// acts on whichever actually exist.
type recoveryStore struct {
	transport string
	dir       string
	volumeID  string
	branch    string
}

func cmdRecovery(e *cmdEnv, args []string) int {
	if len(args) == 0 {
		return e.usageError("recovery", errors.New("expected a subcommand: list or resolve"))
	}
	switch args[0] {
	case "list":
		return e.recoveryList(args[1:])
	case "resolve":
		return e.recoveryResolve(args[1:])
	case "-h", "--help", "help":
		return e.printCommandHelp("recovery")
	default:
		return e.usageError("recovery", fmt.Errorf("unknown subcommand %q: expected list or resolve", args[0]))
	}
}

// recoveryStoresFor resolves a mount path to the write-back stores that could
// hold its recovery jobs.
//
// It deliberately does NOT require a live daemon, a live mount, or a readable
// kernel mount table. Every one of those is unavailable precisely when this
// command is needed; what it needs is the durable bookkeeping, and it takes the
// union of both sources so a mount recorded by only one of them still resolves.
func (e *cmdEnv) recoveryStoresFor(mountPath string) ([]recoveryStore, error) {
	stateDir, err := e.mountStateDir()
	if err != nil {
		return nil, err
	}
	var stores []recoveryStore
	seen := map[string]bool{}
	add := func(s recoveryStore) {
		if s.dir == "" || seen[s.dir] {
			return
		}
		seen[s.dir] = true
		stores = append(stores, s)
	}

	if st, err := readMountState(stateDir, mountPath); err == nil && st != nil && st.VolumeID != "" {
		add(recoveryStore{
			transport: "fuse",
			dir:       filepath.Join(stateDir, "writeback", storageDirID(st.VolumeID, st.Branch)),
			volumeID:  st.VolumeID,
			branch:    st.Branch,
		})
		add(recoveryStore{
			transport: "fskit",
			dir:       portablefsd.WritebackStoreDir(daemonStateDirFor(stateDir), st.VolumeID, st.Branch),
			volumeID:  st.VolumeID,
			branch:    st.Branch,
		})
	}
	daemonStateDir := daemonStateDirFor(stateDir)
	persisted, invErr := portablefsd.ReadPersistedAttachInventory(daemonStateDir)
	if invErr != nil && len(stores) == 0 {
		return nil, fmt.Errorf(
			"neither a mount record nor the durable portablefsd attach inventory names %s: %w",
			mountPath, invErr,
		)
	}
	for _, entry := range persisted {
		if filepath.Clean(entry.MountPath) != mountPath {
			continue
		}
		add(recoveryStore{
			transport: "fskit",
			dir:       portablefsd.WritebackStoreDir(daemonStateDir, entry.VolumeID, entry.Branch),
			volumeID:  entry.VolumeID,
			branch:    entry.Branch,
		})
	}
	if len(stores) == 0 {
		return nil, fmt.Errorf(
			"no write-back store is recorded for %s: neither a mount record nor a durable portablefsd attach names it, so there is no recovery job here to resolve",
			mountPath,
		)
	}
	return stores, nil
}

// daemonStateDirFor mirrors discardMountRecord's derivation: the mount state
// directory is <state>/mounts and the daemon's is its sibling.
func daemonStateDirFor(mountStateDir string) string {
	return filepath.Join(filepath.Dir(mountStateDir), "portablefsd")
}

func (e *cmdEnv) recoveryList(args []string) int {
	fs := newFlagSet("recovery")
	var o commonOpts
	addCommonFlags(fs, &o)
	positionals, err := parseArgs(fs, args)
	if err != nil {
		return e.handleParseError("recovery", err)
	}
	if len(positionals) != 1 {
		return e.usageError("recovery", errors.New("expected exactly one mount path"))
	}
	mountPath, err := canonicalMountPath(positionals[0])
	if err != nil {
		return e.fail("recovery", err)
	}
	stores, err := e.recoveryStoresFor(mountPath)
	if err != nil {
		return e.fail("recovery", err)
	}

	type row struct {
		Transport      string `json:"transport"`
		StoreDir       string `json:"storeDir"`
		StreamDir      string `json:"streamDir"`
		JobID          string `json:"jobId"`
		WALEpoch       uint64 `json:"walEpoch"`
		State          string `json:"state"`
		Quarantined    bool   `json:"quarantined"`
		PendingRecords uint64 `json:"pendingRecords"`
		PendingBytes   uint64 `json:"pendingBytes"`
		Resolvable     bool   `json:"resolvable"`
		LastError      string `json:"lastError,omitempty"`
		Remedy         string `json:"remedy,omitempty"`
	}
	var rows []row
	for _, store := range stores {
		reports, err := writeback.InspectStoreRecoveryJobs(store.dir)
		if err != nil {
			return e.fail("recovery", fmt.Errorf("inventory %s store %s: %w", store.transport, store.dir, err))
		}
		for _, rep := range reports {
			rows = append(rows, row{
				Transport:   store.transport,
				StoreDir:    store.dir,
				StreamDir:   rep.StreamDir,
				JobID:       rep.Job.JobID,
				WALEpoch:    rep.Job.WALEpoch,
				State:       rep.Job.State,
				Quarantined: rep.Quarantined,
				// A quarantined job's remaining debt is its LOSS, not its
				// backlog; RecoveryJob.Unrecovered is the one place that
				// distinction is made, so it is the one this reads.
				PendingRecords: unrecoveredRecords(rep.Job),
				PendingBytes:   unrecoveredBytes(rep.Job),
				Resolvable:     !rep.Quarantined && isTerminalRecoveryState(rep.Job.State),
				LastError:      rep.Job.LastError,
				Remedy:         rep.Job.Remedy,
			})
		}
	}
	if o.jsonOut {
		return e.printJSON(map[string]any{"mountPath": mountPath, "jobs": rows})
	}
	if len(rows) == 0 {
		fmt.Fprintf(e.stdout, "no write-back recovery job exists for %s\n", mountPath)
		return 0
	}
	for _, r := range rows {
		status := r.State
		if r.Quarantined {
			status += " (quarantined)"
		}
		fmt.Fprintf(e.stdout, "%s  epoch %d  %s  %s  %d record(s) / %d byte(s)\n",
			r.Transport, r.WALEpoch, r.JobID, status, r.PendingRecords, r.PendingBytes)
		if r.LastError != "" {
			fmt.Fprintf(e.stdout, "    cause: %s\n", r.LastError)
		}
		if r.Resolvable {
			fmt.Fprintf(e.stdout,
				"    blocking: this job refuses `portablefs umount --force` and every attach.\n"+
					"    resolve it with: portablefs recovery resolve %s --job %s\n",
				mountPath, r.JobID)
		}
		if r.Remedy != "" {
			fmt.Fprintf(e.stdout, "    remedy: %s\n", r.Remedy)
		}
	}
	return 0
}

func (e *cmdEnv) recoveryResolve(args []string) int {
	fs := newFlagSet("recovery")
	var o commonOpts
	var all bool
	var reason string
	var jobs stringListFlag
	addCommonFlags(fs, &o)
	fs.BoolVar(&all, "all-terminal", false, "resolve every terminally conflict/corrupt job in the mount's store")
	fs.StringVar(&reason, "reason", "", "operator note recorded durably beside the quarantined bytes")
	fs.Var(&jobs, "job", "recovery job id to resolve (repeatable)")
	positionals, err := parseArgs(fs, args)
	if err != nil {
		return e.handleParseError("recovery", err)
	}
	if len(positionals) != 1 {
		return e.usageError("recovery", errors.New("expected exactly one mount path"))
	}
	if len(jobs) == 0 && !all {
		// NO IMPLICIT BLAST RADIUS. Quarantining acknowledged bytes is a data
		// decision; the operator names the job or says explicitly that they mean
		// all of them. `recovery list` prints the exact invocation.
		return e.usageError("recovery", errors.New(
			"name the job to resolve with --job <jobId> (run `portablefs recovery list <mountPath>` to see them), or pass --all-terminal to resolve every terminal job in this mount's store"))
	}
	mountPath, err := canonicalMountPath(positionals[0])
	if err != nil {
		return e.fail("recovery", err)
	}
	stores, err := e.recoveryStoresFor(mountPath)
	if err != nil {
		return e.fail("recovery", err)
	}
	if reason = strings.TrimSpace(reason); reason == "" {
		reason = "explicit `portablefs recovery resolve` for " + mountPath
	}

	type storeOutcome struct {
		Transport string                          `json:"transport"`
		StoreDir  string                          `json:"storeDir"`
		Result    writeback.ResolveRecoveryResult `json:"result"`
	}
	var (
		outcomes []storeOutcome
		resolved int
		failures []error
	)
	for _, store := range stores {
		reports, err := writeback.InspectStoreRecoveryJobs(store.dir)
		if err != nil || len(reports) == 0 {
			// A store that does not exist for this transport is not an error:
			// a mount uses one transport and both candidates are derived.
			continue
		}
		result, err := writeback.ResolveTerminalRecoveryJobs(
			store.dir, store.volumeID, store.branch, reason, jobs,
		)
		if err != nil {
			failures = append(failures, fmt.Errorf("resolve %s store %s: %w", store.transport, store.dir, err))
			continue
		}
		resolved += len(result.Resolved)
		outcomes = append(outcomes, storeOutcome{Transport: store.transport, StoreDir: store.dir, Result: result})
	}
	// A refusal from one candidate store is only fatal when NO store resolved
	// anything: with two derived candidates, "job not in this store" is the
	// expected answer from the transport the mount does not use.
	if resolved == 0 && len(failures) != 0 {
		return e.fail("recovery", errors.Join(append([]error{
			fmt.Errorf("nothing was resolved for %s and nothing was moved", mountPath),
		}, failures...)...))
	}

	if o.jsonOut {
		return e.printJSON(map[string]any{
			"mountPath": mountPath,
			"resolved":  resolved,
			"stores":    outcomes,
		})
	}
	if resolved == 0 {
		fmt.Fprintf(e.stdout,
			"no terminally conflict or corrupt recovery job exists for %s; nothing was moved\n", mountPath)
		for _, outcome := range outcomes {
			for _, skipped := range outcome.Result.Skipped {
				fmt.Fprintf(e.stdout, "  epoch %d (%s): %s\n", skipped.WALEpoch, skipped.State, skipped.Reason)
			}
		}
		return 0
	}
	for _, outcome := range outcomes {
		for _, job := range outcome.Result.Resolved {
			fmt.Fprintf(e.stdout,
				"resolved %s recovery job %s (%s, epoch %d)\n"+
					"  %d acknowledged record(s) / %d byte(s) under %v never reached the authority\n"+
					"  the only remaining copy is retained at %s (nothing was deleted)\n",
				outcome.Transport, job.JobID, job.State, job.WALEpoch,
				job.LostRecords, job.LostBytes, job.LostScopes, job.QuarantinePath)
			if job.Remedy != "" {
				fmt.Fprintf(e.stdout, "  remedy: %s\n", job.Remedy)
			}
			if job.NamespaceHeld {
				fmt.Fprintf(e.stdout,
					"  note: this resolution is offline, so the authority delegation grants under %v are released by the next attach rather than now\n",
					job.LostScopes)
			}
		}
	}
	fmt.Fprintf(e.stdout,
		"the block is cleared: `portablefs umount --force %s` and a fresh mount can now proceed\n", mountPath)
	return 0
}

func isTerminalRecoveryState(state string) bool {
	return state == writeback.JobConflict || state == writeback.JobCorrupt
}

func unrecoveredRecords(job writeback.RecoveryJob) uint64 {
	records, _ := job.Unrecovered()
	return records
}

func unrecoveredBytes(job writeback.RecoveryJob) uint64 {
	_, bytes := job.Unrecovered()
	return bytes
}
