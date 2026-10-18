package lantrace

import (
	"container/list"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"sort"
	"strings"
	"text/tabwriter"
)

// DefaultJoinWindow is the default number of unmatched anchors each
// correlation join holds.
const DefaultJoinWindow = 1 << 16

// ReportConfig bounds the report. Zero fields take the defaults.
type ReportConfig struct {
	// JoinWindow bounds the unmatched anchors held per join.
	JoinWindow int
}

// StreamInfo describes one producer stream of the collection.
type StreamInfo struct {
	Stream       uint32 `json:"stream"`
	Layer        Layer  `json:"layer"`
	Process      Label  `json:"process"`
	Clock        Label  `json:"clock"`
	Emitted      uint64 `json:"emitted"`
	Lost         uint64 `json:"lost"`
	Read         uint64 `json:"read"`
	Rejected     uint64 `json:"rejected"`
	Incomplete   bool   `json:"incomplete"`
	Inconsistent bool   `json:"inconsistent"`
}

// Join statuses. A join is exact only when both layers were traced, every
// anchor carried the identity namespace the key requires, and every anchor
// matched exactly one partner with the same operation metadata.
const (
	JoinNotTraced   = "not_traced"
	JoinUnavailable = "unavailable"
	JoinIncomplete  = "incomplete"
	JoinExact       = "exact"
)

// JoinCoverage is the cross-layer correlation coverage of one join.
type JoinCoverage struct {
	Name           string `json:"name"`
	Key            string `json:"key"`
	Left           string `json:"left"`
	Right          string `json:"right"`
	Applicable     bool   `json:"applicable"`
	Status         string `json:"status"`
	Matched        uint64 `json:"matched"`
	UnmatchedLeft  uint64 `json:"unmatched_left"`
	UnmatchedRight uint64 `json:"unmatched_right"`
	EvictedLeft    uint64 `json:"evicted_left"`
	EvictedRight   uint64 `json:"evicted_right"`
	// Unqualified counts anchors that lacked the key's namespace and so could
	// not be joined at all; any makes the join unavailable.
	Unqualified uint64 `json:"unqualified"`
	// Conflicts counts identities whose anchors disagreed on operation
	// metadata: two anchors with one identity that describe different
	// operations are different requests, not a match.
	Conflicts uint64 `json:"conflicts"`
}

// LatencySummary summarizes in-process durations. P50 and P90 are the upper
// bounds of log-linear histogram buckets, at most 12.5% above the true
// quantile and never outside [Min, Max]; Count, Min, Max and Total are exact.
type LatencySummary struct {
	Count uint64 `json:"count"`
	Min   uint64 `json:"min_ns"`
	P50   uint64 `json:"p50_ns"`
	P90   uint64 `json:"p90_ns"`
	Max   uint64 `json:"max_ns"`
	Total uint64 `json:"total_ns"`
}

// Report is the analysis of one collection. Counters keys are drawn from
// AggregateKeys, so they are bounded by the grammar's categories.
type Report struct {
	Run               Label        `json:"run"`
	Streams           []StreamInfo `json:"streams"`
	Events            uint64       `json:"events"`
	ProducerLost      uint64       `json:"producer_lost"`
	Dropped           uint64       `json:"dropped"`
	Rejected          uint64       `json:"rejected"`
	IncompleteStreams uint64       `json:"incomplete_streams"`
	// InconsistentStreams counts complete streams whose sequence numbers do
	// not reconcile with their trailer under the sequence rule.
	InconsistentStreams uint64                    `json:"inconsistent_streams"`
	Joins               []JoinCoverage            `json:"joins"`
	Counters            map[string]uint64         `json:"counters"`
	Latencies           map[string]LatencySummary `json:"latencies"`
	AttributionValid    bool                      `json:"attribution_valid"`
	InvalidReasons      []string                  `json:"invalid_reasons,omitempty"`
}

const (
	joinFrontendDaemon  = "frontend_daemon"
	joinClientAuthority = "client_authority"
)

var traceTotals = []string{"events", "producer_lost", "dropped", "rejected", "incomplete_streams", "inconsistent_streams", "lost_events"}

// BuildReport reads one collection written by Collect. A malformed or
// internally inconsistent collection is an error; lost or uncorrelated
// records are reported, and make AttributionValid false.
func BuildReport(r io.Reader, cfg ReportConfig) (*Report, error) {
	if cfg.JoinWindow < 0 {
		return nil, errors.New("lantrace: join window must not be negative")
	}
	if cfg.JoinWindow == 0 {
		cfg.JoinWindow = DefaultJoinWindow
	}
	lines := newLineReader(r)
	readLine := func(what string) ([]byte, error) {
		line, err := lines.next()
		if err == io.EOF {
			return nil, fmt.Errorf("lantrace: collection ends before its %s", what)
		}
		return line, err
	}
	next := func(what string) (record, error) {
		line, err := readLine(what)
		if err != nil {
			return record{}, err
		}
		return parseLine(line, true)
	}

	first, err := readLine("collection record")
	if err != nil {
		return nil, err
	}
	rec, err := parseLine(first, true)
	if err != nil || rec.Record != recordCollection {
		if p, perr := parseLine(first, false); perr == nil && p.Record == recordHeader {
			return nil, errors.New("lantrace: input is a producer stream, not a collection; run collect first")
		}
		if err != nil {
			return nil, err
		}
		return nil, errors.New("lantrace: input is not a collection")
	}
	rep := &Report{Run: rec.Run, Counters: map[string]uint64{}, Latencies: map[string]LatencySummary{}}
	present := map[Layer]bool{}
	for i := uint32(1); i <= rec.Streams; i++ {
		h, err := next("stream headers")
		if err != nil {
			return nil, err
		}
		if h.Record != recordHeader || h.Stream != i {
			return nil, fmt.Errorf("lantrace: collection must declare stream %d next", i)
		}
		if h.Run != rep.Run {
			return nil, errors.New("lantrace: stream header names a different run")
		}
		rep.Streams = append(rep.Streams, StreamInfo{Stream: i, Layer: h.Layer, Process: h.Process, Clock: h.Clock})
		present[h.Layer] = true
	}

	a := &aggregator{counters: rep.Counters, latencies: map[string]*histogram{}}
	a.joins[0] = newJoin(JoinCoverage{Name: joinFrontendDaemon, Key: "(conn_ns, conn, request)",
		Left: "frontend local/send", Right: "daemon local/enqueue",
		Applicable: present[LayerFrontend] && present[LayerDaemon]}, cfg.JoinWindow)
	a.joins[1] = newJoin(JoinCoverage{Name: joinClientAuthority, Key: "(session, authority_request)",
		Left: "daemon or linux_client authority/send", Right: "authority authority/receive",
		Applicable: (present[LayerDaemon] || present[LayerLinuxClient]) && present[LayerAuthority]}, cfg.JoinWindow)

	// Per-stream sequence state, validated independently of Collect: written
	// events of one stream carry strictly increasing numbers, so a duplicate
	// or reordered number is a malformed collection, never a second event.
	lastSeq := make([]uint64, len(rep.Streams))
	counted := make([]uint64, len(rep.Streams))
	trailers := 0
	var summary *record
	for summary == nil {
		rec, err := next("summary record")
		if err != nil {
			return nil, err
		}
		switch rec.Record {
		case recordEvent:
			if trailers > 0 {
				return nil, errors.New("lantrace: event after the stream trailers")
			}
			if rec.Stream > uint32(len(rep.Streams)) {
				return nil, errors.New("lantrace: event names an undeclared stream")
			}
			layer := rep.Streams[rec.Stream-1].Layer
			if err := rec.checkEvent(layer); err != nil {
				return nil, err
			}
			if rec.Seq <= lastSeq[rec.Stream-1] {
				return nil, fmt.Errorf("lantrace: stream %d events are not in strictly increasing sequence order", rec.Stream)
			}
			lastSeq[rec.Stream-1] = rec.Seq
			counted[rec.Stream-1]++
			rep.Events++
			a.add(layer, &rec.Event)
		case recordTrailer:
			trailers++
			if rec.Stream != uint32(trailers) || trailers > len(rep.Streams) {
				return nil, errors.New("lantrace: stream trailers must follow in stream order")
			}
			s := &rep.Streams[rec.Stream-1]
			if rec.Incomplete && rec.Inconsistent {
				return nil, fmt.Errorf("lantrace: stream %d trailer is both incomplete and inconsistent", rec.Stream)
			}
			s.Emitted, s.Lost, s.Read, s.Rejected, s.Incomplete, s.Inconsistent = rec.Emitted, rec.Lost, rec.Read, rec.Rejected, rec.Incomplete, rec.Inconsistent
		case recordSummary:
			if trailers != len(rep.Streams) {
				return nil, errors.New("lantrace: summary before every stream trailer")
			}
			summary = &rec
		default:
			return nil, errors.New("lantrace: unexpected record in collection")
		}
	}
	if _, err := lines.next(); err != io.EOF {
		return nil, errors.New("lantrace: data after the collection summary")
	}

	var read, rejected, lost, incomplete, inconsistent uint64
	for i, s := range rep.Streams {
		read += s.Read
		rejected += s.Rejected
		lost += s.Lost
		if s.Incomplete {
			incomplete++
		}
		if s.Inconsistent {
			inconsistent++
		}
		// Reconcile this stream's written events with its trailer. With no
		// collector drops every read event is present, so the collection
		// must agree exactly; with drops only the bounds can be rechecked,
		// and a bound Collect missed is still a malformed collection.
		if counted[i] > s.Read || (summary.Dropped == 0 && counted[i] != s.Read) {
			return nil, fmt.Errorf("lantrace: stream %d has %d events but its trailer reports %d read", s.Stream, counted[i], s.Read)
		}
		if !s.Incomplete {
			bad := !sequenceConsistent(lastSeq[i], s.Read, s.Rejected, s.Emitted, s.Lost)
			if bad && !s.Inconsistent || (summary.Dropped == 0 && !bad && s.Inconsistent) {
				return nil, fmt.Errorf("lantrace: stream %d trailer misstates whether its sequence numbers reconcile", s.Stream)
			}
		}
	}
	if summary.Events != rep.Events || summary.Events+summary.Dropped != read || summary.Rejected != rejected ||
		summary.ProducerLost != lost || summary.IncompleteStreams != incomplete || summary.InconsistentStreams != inconsistent {
		return nil, errors.New("lantrace: collection summary does not match its records")
	}
	rep.ProducerLost, rep.Dropped, rep.Rejected, rep.IncompleteStreams, rep.InconsistentStreams =
		summary.ProducerLost, summary.Dropped, summary.Rejected, summary.IncompleteStreams, summary.InconsistentStreams

	a.finish(rep)
	rep.judge()
	return rep, nil
}

// judge decides whether exact attribution holds. Any lost, dropped,
// rejected, incomplete, evicted or unmatched record means some request's
// attribution is unknown, so totals derived from the trace are lower bounds.
func (rep *Report) judge() {
	var reasons []string
	if rep.ProducerLost > 0 {
		reasons = append(reasons, fmt.Sprintf("%d events lost by producers", rep.ProducerLost))
	}
	if rep.Dropped > 0 {
		reasons = append(reasons, fmt.Sprintf("%d events dropped by collector bounds", rep.Dropped))
	}
	if rep.Rejected > 0 {
		reasons = append(reasons, fmt.Sprintf("%d records rejected as invalid", rep.Rejected))
	}
	if rep.IncompleteStreams > 0 {
		reasons = append(reasons, fmt.Sprintf("%d streams have no trailer", rep.IncompleteStreams))
	}
	if rep.InconsistentStreams > 0 {
		reasons = append(reasons, fmt.Sprintf("%d streams have sequence numbers that do not reconcile with their trailers", rep.InconsistentStreams))
	}
	for _, s := range rep.Streams {
		if !s.Incomplete && s.Emitted != s.Read {
			reasons = append(reasons, fmt.Sprintf("stream %d trailer reports %d events but %d were read", s.Stream, s.Emitted, s.Read))
		}
	}
	for _, j := range rep.Joins {
		if !j.Applicable {
			continue
		}
		if j.Unqualified > 0 {
			reasons = append(reasons, fmt.Sprintf("join %s unavailable: %d anchors lack the identity namespace its key %s requires", j.Name, j.Unqualified, j.Key))
		}
		if j.Conflicts > 0 {
			reasons = append(reasons, fmt.Sprintf("join %s found %d identities whose anchors describe different operations", j.Name, j.Conflicts))
		}
		if j.EvictedLeft+j.EvictedRight > 0 {
			reasons = append(reasons, fmt.Sprintf("join %s evicted %d anchors from its bounded window", j.Name, j.EvictedLeft+j.EvictedRight))
		}
		if j.UnmatchedLeft+j.UnmatchedRight > 0 {
			reasons = append(reasons, fmt.Sprintf("join %s left %d left and %d right anchors unmatched", j.Name, j.UnmatchedLeft, j.UnmatchedRight))
		}
	}
	rep.InvalidReasons = reasons
	rep.AttributionValid = len(reasons) == 0
}

// WriteText writes the human-readable report. When attribution is invalid
// that is the first line.
func (rep *Report) WriteText(w io.Writer) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	p := func(format string, args ...any) { fmt.Fprintf(tw, format, args...) }
	if rep.AttributionValid {
		p("attribution: exact for this run (no lost, dropped, rejected, incomplete, evicted or unmatched records)\n")
	} else {
		p("ATTRIBUTION INVALID: exact attribution is invalid for this run; trace totals are lower bounds\n")
		for _, reason := range rep.InvalidReasons {
			p("  - %s\n", reason)
		}
	}
	p("run %s  schema %s\n\n", rep.Run, Schema)

	p("stream\tlayer\tprocess\tclock\temitted\tlost\tread\trejected\tcomplete\n")
	for _, s := range rep.Streams {
		p("%d\t%s\t%s\t%s\t%d\t%d\t%d\t%d\t%t\n", s.Stream, s.Layer, s.Process, s.Clock, s.Emitted, s.Lost, s.Read, s.Rejected, !s.Incomplete)
	}
	p("\nevents %d  producer_lost %d  dropped %d  rejected %d  incomplete_streams %d  inconsistent_streams %d\n\n",
		rep.Events, rep.ProducerLost, rep.Dropped, rep.Rejected, rep.IncompleteStreams, rep.InconsistentStreams)

	p("join\tkey\tstatus\tmatched\tunmatched left\tunmatched right\tevicted left\tevicted right\tunqualified\tconflicts\n")
	for _, j := range rep.Joins {
		if !j.Applicable {
			p("%s\t%s\tnot traced: needs both %s and %s\n", j.Name, j.Key, j.Left, j.Right)
			continue
		}
		p("%s\t%s\t%s\t%d\t%d\t%d\t%d\t%d\t%d\t%d\n", j.Name, j.Key, j.Status, j.Matched, j.UnmatchedLeft, j.UnmatchedRight,
			j.EvictedLeft, j.EvictedRight, j.Unqualified, j.Conflicts)
	}

	p("\ncounter\tvalue\n")
	for _, k := range sortedKeys(rep.Counters) {
		p("%s\t%d\n", k, rep.Counters[k])
	}
	p("\nlatency (ns; p50/p90 bucket upper bounds within 12.5%%)\tcount\tmin\tp50\tp90\tmax\ttotal\n")
	for _, k := range sortedKeys(rep.Latencies) {
		l := rep.Latencies[k]
		p("%s\t%d\t%d\t%d\t%d\t%d\t%d\n", k, l.Count, l.Min, l.P50, l.P90, l.Max, l.Total)
	}
	return tw.Flush()
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

type aggregator struct {
	counters  map[string]uint64
	latencies map[string]*histogram
	joins     [2]*join
}

func key(parts ...string) string { return strings.Join(parts, ".") }

func (a *aggregator) inc(parts ...string) { a.counters[key(parts...)]++ }

func (a *aggregator) addN(n uint64, parts ...string) {
	a.counters[key(parts...)] = satAdd(a.counters[key(parts...)], n)
}

func (a *aggregator) observe(d Nanos, parts ...string) {
	k := key(parts...)
	h := a.latencies[k]
	if h == nil {
		h = &histogram{}
		a.latencies[k] = h
	}
	h.add(uint64(d))
}

func isClient(l Layer) bool { return l == LayerDaemon || l == LayerLinuxClient }

// add folds one validated event into the aggregates. Each counter has one
// defined source so that a request is counted once: foreground opcodes at
// the client send or authority receive, Lookup polarity at the reply, cache
// exposure and miss reasons at the single final decision, released tokens at
// the batch acknowledgement.
func (a *aggregator) add(layer Layer, e *Event) {
	L := string(layer)
	switch e.Kind {
	case KindCallback:
		if e.Phase == PhaseEntry {
			a.inc(L, "callback", string(e.CallbackKind))
			if e.CallbackKind == CallbackGetAttr && e.Origin != "" {
				a.inc(L, "callback", "get_attr", string(e.Origin))
			}
		}
	case KindLocal:
		if (layer == LayerFrontend && e.Phase == PhaseSend) || (layer == LayerDaemon && e.Phase == PhaseEnqueue) {
			a.inc(L, "local", string(e.LocalOp))
			if e.LocalOp == LocalGetAttr && e.Origin != "" {
				a.inc(L, "local", "get_attr", string(e.Origin))
			}
			side := 0
			if layer == LayerDaemon {
				side = 1
			}
			// conn is unique only within one daemon process, so the key is
			// qualified by the run-unique namespace both sides must hold.
			// An anchor without it cannot be joined: the join is unavailable
			// rather than matched on a number another daemon also uses.
			if e.ConnNS == "" {
				a.joins[0].unqualified()
			} else {
				a.joins[0].add(side, joinKey{label: e.ConnNS, scope: e.Conn, id: e.Request}, joinMeta{op: string(e.LocalOp), mount: e.Mount})
			}
		}
	case KindCache:
		c := string(e.Candidate)
		switch e.Phase {
		case PhaseCandidate:
			a.inc(L, "cache", "candidate", c, string(e.CacheResult))
			if e.CacheResult != CacheMiss {
				a.inc(L, "cache", "candidate_hits")
			}
		case PhaseFinal:
			if e.Exposure == ExposureAccepted && e.CacheResult != CacheMiss {
				a.inc(L, "cache", "exposed", c, string(e.CacheResult))
				a.inc(L, "cache", "exposed_hits")
			} else {
				a.inc(L, "cache", "ordinary_read", c)
				a.inc(L, "cache", "ordinary_reads")
				if e.MissReason != "" {
					a.inc(L, "cache", "miss_reason", c, string(e.MissReason))
				}
			}
			if e.Coordinate != "" {
				a.inc(L, "cache", "coordinate", string(e.Coordinate))
			}
		}
	case KindSource:
		a.inc(L, "source", string(e.Phase))
		if e.Phase == PhaseAck && e.Successor != 0 {
			a.inc(L, "source", "delayed_ack")
		}
	case KindOpen:
		a.inc(L, "open", string(e.OpenReason), string(e.RPC))
	case KindRelease:
		a.inc(L, "release", string(e.ReleaseKind), "final")
	case KindReleaseBatch:
		a.inc(L, "release", string(e.ReleaseKind), string(e.Phase))
		if e.Phase == PhaseAcked {
			a.addN(uint64(e.Tokens), L, "release", string(e.ReleaseKind), "tokens")
		}
	case KindAuthority:
		anchor, reply := PhaseReceive, PhaseReply
		side := 1
		if isClient(layer) {
			anchor, reply, side = PhaseSend, PhaseReceive, 0
		}
		op := string(e.AuthorityOp)
		if e.Phase == anchor {
			if e.Dispatch == "" || e.Dispatch == DispatchOriginal {
				a.inc(L, "authority", op)
				if foregroundAuthorityOps.has(e.AuthorityOp) {
					a.inc(L, "authority_total", "foreground")
				} else {
					a.inc(L, "authority_total", "background")
				}
			} else {
				a.inc(L, "authority_dispatch", string(e.Dispatch), op)
			}
			a.joins[1].add(side, joinKey{label: e.Session, id: e.AuthorityRequest}, joinMeta{op: op})
		}
		if e.Phase == reply {
			if e.Duration > 0 {
				a.observe(e.Duration, L, "authority_time", op)
			}
			if e.AuthorityOp == AuthorityLookup {
				switch {
				case e.Lookup != "":
					a.inc(L, "lookup", string(e.Lookup))
				case e.Outcome == "" || e.Outcome == OutcomeOK:
					a.inc(L, "lookup", "unclassified")
				default:
					a.inc(L, "lookup", "error")
				}
			}
		}
	case KindBarrier:
		a.inc(L, "barrier", string(e.Barrier))
	case KindSyscall:
		a.observe(e.Duration, L, "syscall", string(e.Syscall))
		a.addN(uint64(e.Waiters), L, "syscall", string(e.Syscall), "waiters")
	case KindWait:
		a.observe(e.Duration, L, "wait", string(e.Wait))
	case KindOccupancy:
		k := key(L, "occupancy", string(e.Resource), "max")
		a.counters[k] = max(a.counters[k], uint64(e.Count))
		if e.Phase == PhaseFinal {
			a.addN(uint64(e.Count), L, "occupancy", string(e.Resource), "final")
		}
	case KindMkdirWitness:
		a.inc(L, "mkdir_witness", string(e.Witness), string(e.Seed))
	case KindRenewal:
		a.inc(L, "renewal", string(e.RenewalOrigin), string(e.RenewalOutcome))
	case KindSuperblock:
		a.inc(L, "superblock_load", string(e.Load))
	}
}

func (a *aggregator) finish(rep *Report) {
	for k, h := range a.latencies {
		s := h.summary()
		rep.Latencies[k] = s
		a.counters[k] = s.Count
		a.counters[k+".total_ns"] = s.Total
	}
	for _, j := range a.joins {
		j.finish()
		rep.Joins = append(rep.Joins, j.cov)
		if j.cov.Applicable {
			a.counters[key("trace", "join", j.cov.Name, "matched")] = j.cov.Matched
			a.counters[key("trace", "join", j.cov.Name, "unmatched")] = j.cov.UnmatchedLeft + j.cov.UnmatchedRight
			a.counters[key("trace", "join", j.cov.Name, "evicted")] = j.cov.EvictedLeft + j.cov.EvictedRight
			a.counters[key("trace", "join", j.cov.Name, "unqualified")] = j.cov.Unqualified
			a.counters[key("trace", "join", j.cov.Name, "conflicts")] = j.cov.Conflicts
		}
	}
	a.counters["trace.events"] = rep.Events
	a.counters["trace.producer_lost"] = rep.ProducerLost
	a.counters["trace.dropped"] = rep.Dropped
	a.counters["trace.rejected"] = rep.Rejected
	a.counters["trace.incomplete_streams"] = rep.IncompleteStreams
	a.counters["trace.inconsistent_streams"] = rep.InconsistentStreams
	a.counters["trace.lost_events"] = satAdd(satAdd(rep.ProducerLost, rep.Dropped), rep.Rejected)
}

type joinKey struct {
	label Label  // conn_ns for pfslocal identities, session for authority identities
	scope uint64 // conn, for pfslocal identities
	id    uint64 // request or authority request
}

// joinMeta is what both anchors of one identity must agree on. A mount label
// is compared only when both anchors carry one.
type joinMeta struct {
	op    string
	mount Label
}

func (m joinMeta) agrees(o joinMeta) bool {
	return m.op == o.op && (m.mount == "" || o.mount == "" || m.mount == o.mount)
}

type joinEntry struct {
	key  joinKey
	meta joinMeta
	side int
	n    uint64
	elem *list.Element
}

// join matches anchors from two layers by qualified identity. It is the only
// per-request state in the analyzer and it is bounded: at capacity the oldest
// unmatched anchor is evicted and counted, so memory does not grow with run
// length and an eviction invalidates attribution instead of silently
// lowering coverage. Collect's elapsed-time interleaving keeps partners close
// enough that a correct run needs only a small window. Anchors are counted as
// a multiset, so a resend that reuses an identity matches a second receive.
type join struct {
	cov      JoinCoverage
	capacity int
	pending  map[joinKey]*joinEntry
	order    list.List
}

func newJoin(cov JoinCoverage, capacity int) *join {
	return &join{cov: cov, capacity: capacity, pending: map[joinKey]*joinEntry{}}
}

// unqualified counts an anchor that lacks the key's namespace.
func (j *join) unqualified() {
	if j.cov.Applicable {
		j.cov.Unqualified++
	}
}

func (j *join) add(side int, k joinKey, meta joinMeta) {
	if !j.cov.Applicable {
		return
	}
	if e, ok := j.pending[k]; ok {
		if !e.meta.agrees(meta) {
			// One identity naming two operations cannot be attributed; the
			// conflicting anchor is counted, never matched or merged.
			j.cov.Conflicts++
			return
		}
		if e.side == side {
			e.n++
			return
		}
		j.cov.Matched++
		if e.n--; e.n == 0 {
			j.order.Remove(e.elem)
			delete(j.pending, k)
		}
		return
	}
	if len(j.pending) >= j.capacity {
		oldest := j.order.Front().Value.(*joinEntry)
		if oldest.side == 0 {
			j.cov.EvictedLeft += oldest.n
		} else {
			j.cov.EvictedRight += oldest.n
		}
		j.order.Remove(oldest.elem)
		delete(j.pending, oldest.key)
	}
	e := &joinEntry{key: k, meta: meta, side: side, n: 1}
	e.elem = j.order.PushBack(e)
	j.pending[k] = e
}

func (j *join) finish() {
	for _, e := range j.pending {
		if e.side == 0 {
			j.cov.UnmatchedLeft += e.n
		} else {
			j.cov.UnmatchedRight += e.n
		}
	}
	j.pending = nil
	c := &j.cov
	switch {
	case !c.Applicable:
		c.Status = JoinNotTraced
	case c.Unqualified > 0:
		c.Status = JoinUnavailable
	case c.Conflicts+c.UnmatchedLeft+c.UnmatchedRight+c.EvictedLeft+c.EvictedRight > 0:
		c.Status = JoinIncomplete
	default:
		c.Status = JoinExact
	}
}

// histogram is a fixed log-linear histogram: exact below 8, then eight
// buckets per power of two up to MaxNanos. Its size is constant, so latency
// summaries cost bounded memory however many samples a run has.
type histogram struct {
	count, total, min, max uint64
	buckets                [8 + 50*8]uint64
}

func bucketOf(v uint64) int {
	if v < 8 {
		return int(v)
	}
	e := bits.Len64(v) - 1
	return 8 + (e-3)*8 + int((v>>(e-3))&7)
}

func bucketUpper(i int) uint64 {
	if i < 8 {
		return uint64(i)
	}
	e, m := (i-8)/8+3, uint64((i-8)%8)
	return (8+m)<<(e-3) + 1<<(e-3) - 1
}

func (h *histogram) add(v uint64) {
	if h.count == 0 || v < h.min {
		h.min = v
	}
	h.max = max(h.max, v)
	h.count++
	h.total = satAdd(h.total, v)
	h.buckets[bucketOf(v)]++
}

func (h *histogram) quantile(percent uint64) uint64 {
	rank := max((h.count*percent+99)/100, 1)
	var seen uint64
	for i, n := range h.buckets {
		if seen += n; seen >= rank {
			return min(max(bucketUpper(i), h.min), h.max)
		}
	}
	return h.max
}

func (h *histogram) summary() LatencySummary {
	return LatencySummary{Count: h.count, Min: h.min, P50: h.quantile(50), P90: h.quantile(90), Max: h.max, Total: h.total}
}

func satAdd(a, b uint64) uint64 {
	if s := a + b; s >= a {
		return s
	}
	return ^uint64(0)
}

// AggregateKeys returns every counter key a Report can produce. Reconcile
// uses it to refuse a mapping that names a key no trace could contain.
func AggregateKeys() map[string]struct{} {
	u := map[string]struct{}{}
	add := func(parts ...string) { u[key(parts...)] = struct{}{} }
	for _, t := range traceTotals {
		add("trace", t)
	}
	for _, j := range []string{joinFrontendDaemon, joinClientAuthority} {
		for _, m := range []string{"matched", "unmatched", "evicted", "unqualified", "conflicts"} {
			add("trace", "join", j, m)
		}
	}
	latency := func(parts ...string) {
		add(parts...)
		add(append(parts, "total_ns")...)
	}
	for _, l := range layers.ordered {
		L := string(l)
		for _, k := range callbackKinds.ordered {
			add(L, "callback", string(k))
		}
		for _, o := range origins.ordered {
			add(L, "callback", "get_attr", string(o))
			add(L, "local", "get_attr", string(o))
		}
		for _, op := range localOps.ordered {
			add(L, "local", string(op))
		}
		add(L, "cache", "candidate_hits")
		add(L, "cache", "exposed_hits")
		add(L, "cache", "ordinary_reads")
		for _, c := range candidates.ordered {
			C := string(c)
			for _, r := range cacheResults.ordered {
				add(L, "cache", "candidate", C, string(r))
				add(L, "cache", "exposed", C, string(r))
			}
			add(L, "cache", "ordinary_read", C)
			for _, m := range missReasons.ordered {
				add(L, "cache", "miss_reason", C, string(m))
			}
		}
		for _, c := range coordinates.ordered {
			add(L, "cache", "coordinate", string(c))
		}
		for _, p := range ruleSpecs[KindSource].phases {
			add(L, "source", string(p))
		}
		add(L, "source", "delayed_ack")
		for _, r := range openReasons.ordered {
			for _, rpc := range rpcs.ordered {
				add(L, "open", string(r), string(rpc))
			}
		}
		for _, k := range releaseKinds.ordered {
			add(L, "release", string(k), "final")
			add(L, "release", string(k), "tokens")
			for _, p := range ruleSpecs[KindReleaseBatch].phases {
				add(L, "release", string(k), string(p))
			}
		}
		add(L, "authority_total", "foreground")
		add(L, "authority_total", "background")
		for _, op := range authorityOps.ordered {
			add(L, "authority", string(op))
			latency(L, "authority_time", string(op))
			for _, d := range dispatches.ordered[1:] {
				add(L, "authority_dispatch", string(d), string(op))
			}
		}
		for _, p := range lookupPolarities.ordered {
			add(L, "lookup", string(p))
		}
		add(L, "lookup", "unclassified")
		add(L, "lookup", "error")
		for _, b := range barriers.ordered {
			add(L, "barrier", string(b))
		}
		for _, s := range syscalls.ordered {
			latency(L, "syscall", string(s))
			add(L, "syscall", string(s), "waiters")
		}
		for _, w := range waitKinds.ordered {
			latency(L, "wait", string(w))
		}
		for _, r := range resources.ordered {
			add(L, "occupancy", string(r), "max")
			add(L, "occupancy", string(r), "final")
		}
		for _, w := range witnesses.ordered {
			for _, s := range seeds.ordered {
				add(L, "mkdir_witness", string(w), string(s))
			}
		}
		for _, o := range renewalOrigins.ordered {
			for _, r := range renewalOutcomes.ordered {
				add(L, "renewal", string(o), string(r))
			}
		}
		for _, ld := range loads.ordered {
			add(L, "superblock_load", string(ld))
		}
	}
	return u
}
