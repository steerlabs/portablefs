package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/trendup-ai/portablefs/vcs/internal/clientcore"
)

// startWatchdog aborts the process with a full goroutine dump if the run
// exceeds d. This exists because the harness once LOOKED hung (a long, silent,
// fsync-bound setup phase) and was killed blind: any future wedge now
// self-diagnoses with stacks instead of needing an external kill, and a CI run
// can never wedge a runner indefinitely.
func startWatchdog(d time.Duration) {
	if d <= 0 {
		return
	}
	go func() {
		time.Sleep(d)
		buf := make([]byte, 1<<20)
		n := runtime.Stack(buf, true)
		fmt.Fprintf(os.Stderr, "\npfsbench: WATCHDOG: run exceeded %v; goroutine dump:\n%s\n", d, buf[:n])
		os.Exit(2)
	}()
}

// resultFile is one pfsbench run's JSON output.
type resultFile struct {
	Label     string        `json:"label"`
	Transport string        `json:"transport"`
	Profile   profile       `json:"profile"`
	N         int           `json:"n"`
	Config    benchConfig   `json:"config"`
	Machine   machineInfo   `json:"machine"`
	StartedAt time.Time     `json:"startedAt"`
	Phases    []phaseResult `json:"phases"`
}

type benchConfig struct {
	WriteBack       bool  `json:"writeBack"`
	NegativeCache   bool  `json:"negativeCache"`
	NoReaddirPlus   bool  `json:"noReaddirPlus"`
	FlushMs         int   `json:"flushMs"`
	FlushMaxRecords int   `json:"flushMaxRecords"`
	FlushMaxBytes   int64 `json:"flushMaxBytes"`
	SessionTTLMs    int   `json:"sessionTTLMs"`
	Pool            int   `json:"pool"`
}

type machineInfo struct {
	GOOS      string `json:"goos"`
	GOARCH    string `json:"goarch"`
	NumCPU    int    `json:"numCPU"`
	GoVersion string `json:"goVersion"`
	CPU       string `json:"cpu,omitempty"`
	MemBytes  int64  `json:"memBytes,omitempty"`
	Hostname  string `json:"hostname,omitempty"`
}

func collectMachineInfo() machineInfo {
	mi := machineInfo{GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, NumCPU: runtime.NumCPU(), GoVersion: runtime.Version()}
	mi.Hostname, _ = os.Hostname()
	switch runtime.GOOS {
	case "darwin":
		if out, err := exec.Command("sysctl", "-n", "machdep.cpu.brand_string").Output(); err == nil {
			mi.CPU = strings.TrimSpace(string(out))
		}
		if out, err := exec.Command("sysctl", "-n", "hw.memsize").Output(); err == nil {
			fmt.Sscanf(strings.TrimSpace(string(out)), "%d", &mi.MemBytes)
		}
	case "linux":
		if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				if strings.HasPrefix(line, "model name") {
					if i := strings.Index(line, ":"); i >= 0 {
						mi.CPU = strings.TrimSpace(line[i+1:])
					}
					break
				}
			}
		}
		if b, err := os.ReadFile("/proc/meminfo"); err == nil {
			var kb int64
			fmt.Sscanf(string(b), "MemTotal: %d kB", &kb)
			mi.MemBytes = kb << 10
		}
	}
	return mi
}

func cmdRun(args []string) {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	transport := fs.String("transport", "core", "local | core | fuse")
	profileName := fs.String("profile", "full", "full | quick")
	workloads := fs.String("workloads", "W1,W2,W3,W4,W5", "comma-separated workload list")
	n := fs.Int("n", 3, "runs per phase (p50 reported)")
	out := fs.String("out", "", "JSON output path (default stdout)")
	label := fs.String("label", "default", "config label recorded in the result (report groups by it)")

	writeBack := fs.Bool("writeback", false, "enable write-back sessions (delegation + local overlay + async flush)")
	negCache := fs.Bool("negcache", false, "enable the version-gated negative lookup cache")
	noRDP := fs.Bool("no-readdirplus", false, "disable readdir-plus attr-cache fill")
	flushMs := fs.Int("flush-ms", 250, "write-back flush interval (ms)")
	flushMaxRecords := fs.Int("flush-max-records", 0, "records per FlushBatch RPC (0 = default 512)")
	flushMaxBytes := fs.Int64("flush-max-bytes", 0, "payload bytes per FlushBatch RPC (0 = unbounded)")
	sessionTTLMs := fs.Int("session-ttl-ms", 0, "attr/entry TTL while a subtree delegation is held (0 = off)")
	pool := fs.Int("pool", 16, "fsproto connection pool size")

	mountBin := fs.String("mount-bin", "", "path to the built mount binary (fuse transport)")
	dir := fs.String("dir", "", "working directory (default: a fresh temp dir)")
	watchdogMin := fs.Int("watchdog-min", 30, "abort with a goroutine dump after this many minutes (0 = off)")
	_ = fs.Parse(args)

	startWatchdog(time.Duration(*watchdogMin) * time.Minute)
	p, ok := profiles[*profileName]
	if !ok {
		log.Fatalf("pfsbench run: unknown profile %q", *profileName)
	}
	cfg := benchConfig{
		WriteBack: *writeBack, NegativeCache: *negCache, NoReaddirPlus: *noRDP,
		FlushMs: *flushMs, FlushMaxRecords: *flushMaxRecords, FlushMaxBytes: *flushMaxBytes,
		SessionTTLMs: *sessionTTLMs, Pool: *pool,
	}

	work := *dir
	if work == "" {
		var err error
		work, err = os.MkdirTemp("", "pfsbench-")
		if err != nil {
			log.Fatal(err)
		}
		defer os.RemoveAll(work)
	}

	bfs, cleanup, err := buildTransport(*transport, work, cfg, *mountBin)
	if err != nil {
		log.Fatalf("pfsbench run: %v", err)
	}
	defer cleanup()

	r := &runner{fs: bfs, transport: *transport, n: *n}
	for _, w := range strings.Split(*workloads, ",") {
		var werr error
		switch strings.TrimSpace(w) {
		case "W1":
			werr = runW1(r, p)
		case "W2":
			werr = runW2(r, p)
		case "W3":
			werr = runW3(r, p)
		case "W4":
			werr = runW4(r, p)
		case "W5":
			werr = runW5(r, p)
		case "":
		default:
			log.Fatalf("pfsbench run: unknown workload %q", w)
		}
		if werr != nil {
			log.Fatalf("pfsbench run: %v", werr)
		}
		log.Printf("%s done (transport=%s)", w, *transport)
	}

	res := resultFile{
		Label: *label, Transport: *transport, Profile: p, N: *n, Config: cfg,
		Machine: collectMachineInfo(), StartedAt: time.Now(), Phases: r.results,
	}
	data, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	data = append(data, '\n')
	if *out == "" {
		os.Stdout.Write(data)
		return
	}
	if err := os.MkdirAll(filepath.Dir(*out), 0o755); err != nil {
		log.Fatal(err)
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		log.Fatal(err)
	}
	log.Printf("wrote %s", *out)
}

// buildTransport provisions the benchFS for a transport. core and fuse start a
// throwaway in-process authority (disk-backed WAL under work/).
func buildTransport(transport, work string, cfg benchConfig, mountBin string) (benchFS, func(), error) {
	switch transport {
	case "local":
		root := filepath.Join(work, "localfs")
		if err := os.MkdirAll(root, 0o755); err != nil {
			return nil, nil, err
		}
		return newLocalFS(root), func() {}, nil

	case "core":
		addr, stop, err := startAuthority(context.Background(), "127.0.0.1:0", filepath.Join(work, "authority.wal"))
		if err != nil {
			return nil, nil, err
		}
		bfs, err := newCoreFS(addr, coreOptions(cfg))
		if err != nil {
			stop()
			return nil, nil, err
		}
		return bfs, func() { _ = bfs.Close(); stop() }, nil

	case "fuse":
		return buildFuseTransport(work, cfg, mountBin)

	default:
		return nil, nil, fmt.Errorf("unknown transport %q", transport)
	}
}

func coreOptions(cfg benchConfig) clientcore.Options {
	return clientcore.Options{
		Pool:            cfg.Pool,
		Owner:           "pfsbench",
		WriteBack:       cfg.WriteBack,
		FlushInterval:   time.Duration(cfg.FlushMs) * time.Millisecond,
		FlushMaxRecords: cfg.FlushMaxRecords,
		FlushMaxBytes:   cfg.FlushMaxBytes,
		NegativeCache:   cfg.NegativeCache,
		NoReaddirPlus:   cfg.NoReaddirPlus,
		SessionTTL:      time.Duration(cfg.SessionTTLMs) * time.Millisecond,
	}
}
