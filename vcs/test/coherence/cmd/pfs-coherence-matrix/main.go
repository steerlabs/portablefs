// Command pfs-coherence-matrix is the cross-mount POSIX coherence matrix for
// PortableFS.
//
// It is deliberately black box. It talks to two mounts of one volume through
// ordinary syscalls only, with no access to the frontend's internals and no
// injected kernel, so it cannot pass because a fake agreed with itself. The
// mounts are ordinary processes, which is what makes it possible to kill one
// uncleanly and require the other to keep serving.
//
//	pfs-coherence-matrix --a /mnt/one --b /mnt/two
//	pfs-coherence-matrix --a /mnt/one --b-ssh user@host --b /remote/mount
//	pfs-coherence-matrix --agent --root /mnt/two          (the far side)
//
// It links nothing but the standard library, so it can be copied to any machine
// that has one of the mounts and no PortableFS source tree.
//
// Exit status is 0 only when every case reached its declared expectation. A
// case that fails, a case that is expected to fail and passes, and a case that
// skips without being declared skippable are all non-zero.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
)

type status string

const (
	statusPass status = "PASS"
	statusFail status = "FAIL"
	statusSkip status = "SKIP"
)

type outcome struct {
	Name     string `json:"name"`
	What     string `json:"what"`
	Status   status `json:"status"`
	Expected status `json:"expected"`
	Reason   string `json:"reason,omitempty"`
	// Declared is the reason given on the command line for expecting a
	// non-passing status, kept separate from the reason the case itself gave.
	Declared   string   `json:"declared_reason,omitempty"`
	Failures   []string `json:"failures,omitempty"`
	Notes      []string `json:"notes,omitempty"`
	DurationMs int64    `json:"duration_ms"`
	// Unexpected is true when the observed status is not the declared one. An
	// unexpected pass counts: a declared platform limitation that quietly
	// started working must be re-examined, not left in the expectation list.
	Unexpected bool `json:"unexpected"`
}

type expectation struct {
	status status
	reason string
}

func main() {
	if err := runMatrix(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "pfs-coherence-matrix: %v\n", err)
		os.Exit(1)
	}
}

type expectFlag map[string]expectation

func (e expectFlag) String() string { return "" }

func (e expectFlag) Set(value string) error {
	name, rest, ok := strings.Cut(value, "=")
	if !ok {
		return fmt.Errorf("expectation %q must be <case>=<FAIL|SKIP>:<reason>", value)
	}
	want, reason, ok := strings.Cut(rest, ":")
	if !ok || strings.TrimSpace(reason) == "" {
		return fmt.Errorf("expectation %q must state a reason: <case>=<FAIL|SKIP>:<reason>", value)
	}
	switch status(strings.ToUpper(want)) {
	case statusFail:
		e[name] = expectation{status: statusFail, reason: reason}
	case statusSkip:
		e[name] = expectation{status: statusSkip, reason: reason}
	default:
		return fmt.Errorf("expectation %q must be FAIL or SKIP; PASS is the default and cannot be declared", value)
	}
	return nil
}

func runMatrix(arguments []string) error {
	flags := flag.NewFlagSet("pfs-coherence-matrix", flag.ExitOnError)
	var (
		agent     = flags.Bool("agent", false, "serve the operation vocabulary on stdin/stdout for a remote driver")
		root      = flags.String("root", "", "agent mode: the mount root this agent operates on")
		mountA    = flags.String("a", "", "first mount root (local)")
		mountB    = flags.String("b", "", "second mount root")
		sshTarget = flags.String("b-ssh", "", "run the second mount's operations on this ssh target instead of locally")
		sshBinary = flags.String("b-ssh-binary", "pfs-coherence-matrix", "path to this program on the ssh target")
		label     = flags.String("label", "", "label for this run, printed in the report")
		only      = flags.String("only", "", "comma separated case names to run")
		listCases = flags.Bool("list", false, "print the case names and exit")
		altGID    = flags.Int("alt-gid", 0, "an alternate GID this identity may chown to; without it the ownership case skips")
		fenceCmd  = flags.String("fence-command", "", "shell command that kills the second mount uncleanly; without it the peer-loss case skips")
		replaces  = flags.Int("atomic-replace-rounds", 20, "rounds of the atomic replacement case")
		// The machine-local route cases are gated on the harness being told how
		// to observe a route at all. Without these the cases skip loudly rather
		// than assert a property nothing in the run configured.
		localRoute = flags.String("local-route", "",
			"workspace-relative directory both mounts serve from their own machine-local backing; without it the route cases skip")
		routesContract = flags.String("routes-contract-command", "",
			"shell command that attaches with a stale routing revision without adopting, then adopts and retries, printing a key=value summary; without it that case skips")
		jsonOut    = flags.String("json", "", "write the machine readable result to this file")
		expects    = expectFlag{}
		timeoutArg = flags.Duration("case-timeout", 5*time.Minute, "per-case wall clock bound")
		staleCheck = flags.Bool("self-check-stale", false,
			"falsifiability control: replay the first successful pathname observation on mount A; declared stale-sensitive cases must turn red")
		expectDisjoint = flags.Bool("expect-disjoint-namespace", false,
			"control mode: the second root deliberately does not share the volume, so the shared-namespace probe must fail rather than pass")
	)
	flags.Var(expects, "expect", "declared non-passing expectation: <case>=<FAIL|SKIP>:<reason> (repeatable)")
	if err := flags.Parse(arguments); err != nil {
		return err
	}
	cases := allCases()
	if *listCases {
		for _, entry := range cases {
			fmt.Printf("%s\t%s\n", entry.name, entry.what)
		}
		return nil
	}
	if *agent {
		if *root == "" {
			return fmt.Errorf("--agent requires --root")
		}
		return runAgent(*root)
	}
	if *mountA == "" || *mountB == "" {
		return fmt.Errorf("--a and --b are required")
	}
	known := map[string]bool{}
	for _, entry := range cases {
		known[entry.name] = true
	}
	for name := range expects {
		if !known[name] {
			return fmt.Errorf("expectation names unknown case %q", name)
		}
	}
	selected := map[string]bool{}
	if *only != "" {
		for _, name := range strings.Split(*only, ",") {
			name = strings.TrimSpace(name)
			if !known[name] {
				return fmt.Errorf("--only names unknown case %q", name)
			}
			selected[name] = true
		}
	}

	local, err := newLocalActor("mount-A", *mountA)
	if err != nil {
		return err
	}
	defer local.close()
	var first actor = local
	if *staleCheck {
		first = newStaleActor(local)
		fmt.Printf("SELF-CHECK: mount-A observations are being served from a frozen first answer.\n")
		fmt.Printf("SELF-CHECK: every declared stale-sensitive case must FAIL below.\n\n")
	}

	var second actor
	if *sshTarget != "" {
		remote, err := newRemoteActor("mount-B", *sshTarget, *sshBinary, *mountB, []string{"-o", "BatchMode=yes", "-o", "ConnectTimeout=10"})
		if err != nil {
			return fmt.Errorf("attach the second mount over ssh: %w", err)
		}
		second = remote
	} else {
		local, err := newLocalActor("mount-B", *mountB)
		if err != nil {
			return err
		}
		second = local
	}
	defer second.close()

	runID := fmt.Sprintf("coherence-%d", time.Now().UnixNano())
	if out, err := first.exec(request{Op: "mkdirall", Path: runID, Mode: 0o755}); err != nil || out.Err != "" {
		return fmt.Errorf("create the run directory %s on mount-A: %v%s", runID, err, out.Err)
	}
	// The two roots must actually be the same volume. Running the matrix
	// against two unrelated directories would produce a wall of failures that
	// look like product defects, so the shared namespace is proven up front —
	// and a misconfigured run stops here instead of continuing under a note
	// nobody reads. The disjoint-namespace control run inverts the probe
	// explicitly: there the second root must NOT share the namespace, and a
	// control that accidentally pointed at the volume would validate nothing.
	if out, err := second.exec(request{Op: "stat", Path: runID}); err != nil {
		return fmt.Errorf("probe the run directory from the second mount: %w", err)
	} else if out.Err != "" && !*expectDisjoint {
		return fmt.Errorf("the second mount cannot see %s created by the first (%s); the two roots do not share a namespace, so this run would measure nothing — fix the mounts or pass -expect-disjoint-namespace for the control phase", runID, out.Err)
	} else if out.Err == "" && *expectDisjoint {
		return fmt.Errorf("-expect-disjoint-namespace was passed but the second root can see %s created by the first; a disjoint control pointed at the real volume proves nothing", runID)
	}

	header := *label
	if header == "" {
		header = fmt.Sprintf("%s | %s", *mountA, *mountB)
	}
	fmt.Printf("== PortableFS cross-mount coherence matrix ==\n")
	fmt.Printf("run:      %s\n", runID)
	fmt.Printf("subject:  %s\n", header)
	fmt.Printf("mount-A:  %s\n", *mountA)
	if *sshTarget != "" {
		fmt.Printf("mount-B:  %s:%s (ssh)\n", *sshTarget, *mountB)
	} else {
		fmt.Printf("mount-B:  %s\n", *mountB)
	}
	fmt.Printf("started:  %s\n\n", time.Now().Format(time.RFC3339))

	sort.SliceStable(cases, func(i, j int) bool {
		return !cases[i].destructive && cases[j].destructive
	})

	results := make([]outcome, 0, len(cases))
	for _, entry := range cases {
		if len(selected) != 0 && !selected[entry.name] {
			continue
		}
		result := executeCase(entry, first, second, runID, caseInputs{
			altGID:         *altGID,
			fenceCmd:       *fenceCmd,
			replaces:       *replaces,
			localRoute:     *localRoute,
			routesContract: *routesContract,
		}, *timeoutArg)
		want := expectation{status: statusPass}
		if declared, ok := expects[entry.name]; ok {
			want = declared
		}
		result.Expected = want.status
		result.Unexpected = result.Status != want.status
		// The declared reason and the reason the case itself gave are kept
		// apart. They can disagree, and that disagreement is a signal.
		result.Declared = strings.TrimSpace(want.reason)
		results = append(results, result)
		printCase(result)
	}

	return report(results, *jsonOut)
}

// caseInputs is everything a case needs that the command line supplies. It is a
// struct rather than a parameter list because every field is an observation
// capability: a case that is not given one skips or fails, and adding a
// positional argument for each of them is how a caller silently passes the wrong
// one.
type caseInputs struct {
	altGID         int
	fenceCmd       string
	replaces       int
	localRoute     string
	routesContract string
}

func executeCase(entry coherenceCase, a, b actor, runID string, inputs caseInputs, timeout time.Duration) (result outcome) {
	run := &caseRun{
		a: a, b: b, dir: runID + "/" + entry.name,
		altGID: inputs.altGID, fenceCmd: inputs.fenceCmd, replaces: inputs.replaces,
		localRoute: inputs.localRoute, routesContract: inputs.routesContract,
	}
	result = outcome{Name: entry.name, What: entry.what}
	started := time.Now()
	defer func() {
		notes, failures, skip := run.snapshot()
		result.DurationMs = time.Since(started).Milliseconds()
		result.Notes, result.Failures = notes, failures
		if recovered := recover(); recovered != nil {
			aborted, ok := recovered.(abortCase)
			if !ok {
				panic(recovered)
			}
			if skip != "" {
				result.Status = statusSkip
				result.Reason = skip
				return
			}
			result.Status = statusFail
			result.Failures = append(result.Failures, "aborted: "+aborted.reason)
			return
		}
		if skip != "" {
			result.Status = statusSkip
			result.Reason = skip
			return
		}
		if len(failures) != 0 {
			result.Status = statusFail
			return
		}
		result.Status = statusPass
	}()

	if out, err := a.exec(request{Op: "mkdirall", Path: run.dir, Mode: 0o755}); err != nil {
		run.abort("create the case directory: %v", err)
	} else if out.Err != "" {
		run.abort("create the case directory: %s", out.Err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if recovered := recover(); recovered != nil {
				if aborted, ok := recovered.(abortCase); ok {
					if _, _, skip := run.snapshot(); skip == "" {
						run.fail("aborted: %s", aborted.reason)
					}
					return
				}
				panic(recovered)
			}
		}()
		entry.run(run)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
		run.fail("case did not complete within %s; a hung operation is a failure, not a pass", timeout)
	}
	return result
}

func printCase(result outcome) {
	marker := string(result.Status)
	if result.Unexpected {
		marker += "(UNEXPECTED)"
	}
	fmt.Printf("CASE %-46s %s\n", result.Name, marker)
	fmt.Printf("     %s\n", result.What)
	if result.Reason != "" {
		fmt.Printf("     observed: %s\n", result.Reason)
	}
	if result.Declared != "" {
		fmt.Printf("     declared: expected %s because %s\n", result.Expected, result.Declared)
	}
	for _, note := range result.Notes {
		fmt.Printf("     note:   %s\n", note)
	}
	for _, failure := range result.Failures {
		fmt.Printf("     FAIL:   %s\n", failure)
	}
	fmt.Println()
}

func report(results []outcome, jsonPath string) error {
	var pass, fail, skip, unexpected int
	fmt.Printf("== matrix ==\n")
	for _, result := range results {
		switch result.Status {
		case statusPass:
			pass++
		case statusFail:
			fail++
		case statusSkip:
			skip++
		}
		note := ""
		if result.Unexpected {
			unexpected++
			note = fmt.Sprintf("  <-- UNEXPECTED (declared %s)", result.Expected)
		}
		fmt.Printf("%-6s %-46s%s\n", result.Status, result.Name, note)
	}
	fmt.Printf("\ntotal=%d pass=%d fail=%d skip=%d unexpected=%d\n", len(results), pass, fail, skip, unexpected)

	if jsonPath != "" {
		encoded, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			return err
		}
		if err := os.WriteFile(jsonPath, append(encoded, '\n'), 0o644); err != nil {
			return err
		}
	}
	if unexpected != 0 {
		return fmt.Errorf("%d case(s) did not reach their declared expectation", unexpected)
	}
	// The final line must not read stronger than the run was. "Every case
	// reached its declared expectation" with half the cases declared FAIL or
	// SKIP is a true sentence that gets read as a green matrix, so the
	// declared-away cases are named right where the eye lands.
	if fail == 0 && skip == 0 {
		fmt.Printf("RESULT: every case passed\n")
		return nil
	}
	var declaredAway []string
	for _, result := range results {
		if result.Status != statusPass {
			declaredAway = append(declaredAway, fmt.Sprintf("%s(%s)", result.Name, result.Status))
		}
	}
	fmt.Printf("RESULT: %d case(s) passed; %d reached a declared non-passing expectation and were NOT demonstrated: %s\n",
		pass, len(declaredAway), strings.Join(declaredAway, ", "))
	return nil
}
