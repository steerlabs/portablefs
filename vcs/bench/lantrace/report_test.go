package lantrace

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

const session Label = "s-1"

// scenario records one small correlated run through real Recorders and
// returns the collection.
func scenario(t *testing.T) []byte {
	t.Helper()
	emit := func(layer Layer, process Label, events ...Event) *bytes.Buffer {
		var buf bytes.Buffer
		r, err := NewRecorder(&buf, testRun, layer, process, RecorderConfig{})
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range events {
			if err := r.Emit(e); err != nil {
				t.Fatalf("%s emit %+v: %v", layer, e, err)
			}
		}
		if err := r.Close(); err != nil {
			t.Fatal(err)
		}
		return &buf
	}
	name, err := EncodeName([]byte("src01.txt"))
	if err != nil {
		t.Fatal(err)
	}
	frontend := emit(LayerFrontend, "fskit-appex",
		Event{Kind: KindCallback, Phase: PhaseEntry, Callback: 1, CallbackKind: CallbackLookup, Parent: 2, NameHex: name},
		frontendSend(1, 1, LocalLookup),
		Event{Kind: KindCallback, Phase: PhaseReply, Callback: 1, CallbackKind: CallbackLookup, Outcome: OutcomeError, Errno: 2},
		Event{Kind: KindCallback, Phase: PhasePublicationComplete, Callback: 1, CallbackKind: CallbackLookup, Conn: 1, Operation: 9, Publication: PublicationPublished},
		Event{Kind: KindCallback, Phase: PhaseEntry, Callback: 2, CallbackKind: CallbackGetAttr, Origin: OriginFramework},
		frontendSend(1, 2, LocalGetAttr),
		Event{Kind: KindLocal, Phase: PhaseSend, Conn: 1, Request: 3, LocalOp: LocalGetAttr, Origin: OriginSyntheticEnumeration},
		Event{Kind: KindOpen, Item: 10, OpenReason: OpenCreateReuse, Mode: ModeWrite, RPC: RPCAvoided, LiveMode: LiveWrite},
		Event{Kind: KindRelease, Item: 10, ReleaseKind: ReleaseClose},
	)
	daemon := emit(LayerDaemon, "portablefsd",
		daemonEnqueue(1, 1, LocalLookup),
		daemonEnqueue(1, 2, LocalGetAttr),
		daemonEnqueue(1, 3, LocalGetAttr),
		Event{Kind: KindCache, Phase: PhaseCandidate, Conn: 1, Request: 1, Candidate: CandidateCompleteness, CacheResult: CacheNegative, Parent: 2, NameHex: name, Cert: CertPresent, Search: SearchPermitted},
		Event{Kind: KindCache, Phase: PhaseFinal, Conn: 1, Request: 1, Candidate: CandidateCompleteness, CacheResult: CacheNegative, Exposure: ExposureAccepted, Coordinate: CoordinateFirst},
		Event{Kind: KindCache, Phase: PhaseCandidate, Conn: 1, Request: 2, Candidate: CandidateAttrCache, CacheResult: CacheMiss, MissReason: MissCold},
		Event{Kind: KindCache, Phase: PhaseFinal, Conn: 1, Request: 2, Candidate: CandidateAttrCache, CacheResult: CacheMiss, Exposure: ExposureOrdinaryRead, MissReason: MissCold},
		Event{Kind: KindCache, Phase: PhaseCandidate, Conn: 1, Request: 3, Candidate: CandidateAttrCache, CacheResult: CachePositive, Proof: ProofValid, ProofAge: 1000, SourceState: SourceSettled},
		Event{Kind: KindCache, Phase: PhaseFinal, Conn: 1, Request: 3, Candidate: CandidateAttrCache, CacheResult: CachePositive, Exposure: ExposureOrdinaryRead, MissReason: MissTerminal},
		authoritySend(session, 1, AuthorityGetAttr),
		Event{Kind: KindAuthority, Phase: PhaseReceive, Session: session, AuthorityRequest: 1, AuthorityOp: AuthorityGetAttr, Outcome: OutcomeOK, Duration: 6000},
		authoritySend(session, 2, AuthorityLookup),
		Event{Kind: KindAuthority, Phase: PhaseReceive, Session: session, AuthorityRequest: 2, AuthorityOp: AuthorityLookup, Lookup: LookupStampedNegative, Duration: 5000},
		authoritySend(session, 3, AuthorityLookup),
		Event{Kind: KindAuthority, Phase: PhaseReceive, Session: session, AuthorityRequest: 3, AuthorityOp: AuthorityLookup, Lookup: LookupPositive, Duration: 7000},
		authoritySend(session, 4, AuthorityCreate),
		Event{Kind: KindAuthority, Phase: PhaseSend, Session: session, AuthorityRequest: 4, AuthorityOp: AuthorityCreate, Dispatch: DispatchReplay},
		authoritySend(session, 5, AuthorityKeepAlive),
		Event{Kind: KindReleaseBatch, Phase: PhaseSent, ReleaseKind: ReleaseClose, Batch: 1, Count: 3},
		Event{Kind: KindReleaseBatch, Phase: PhaseAcked, ReleaseKind: ReleaseClose, Batch: 1, Tokens: 5},
		Event{Kind: KindReleaseBatch, Phase: PhaseSent, ReleaseKind: ReleaseReclaim, Batch: 2, Count: 2},
		Event{Kind: KindReleaseBatch, Phase: PhaseAcked, ReleaseKind: ReleaseReclaim, Batch: 2, Tokens: 2},
		Event{Kind: KindSource, Phase: PhaseAcquire, Conn: 1, Operation: 9},
		Event{Kind: KindSource, Phase: PhaseAck, Conn: 1, Operation: 9, Successor: 10, Publication: PublicationPublished},
		Event{Kind: KindOpen, Item: 11, OpenReason: OpenFirst, Mode: ModeRead, RPC: RPCEmitted, Conn: 1, Request: 3},
		Event{Kind: KindWait, Wait: WaitReservation, Duration: 100, Conn: 1, Request: 2},
		Event{Kind: KindWait, Wait: WaitReservation, Duration: 300},
		Event{Kind: KindOccupancy, Phase: PhaseSample, Resource: ResourcePendingReservations, Count: 5, Limit: 1024},
		Event{Kind: KindOccupancy, Phase: PhaseFinal, Resource: ResourcePendingReservations},
		Event{Kind: KindRenewal, RenewalOrigin: RenewalInitial, RenewalOutcome: RenewalInstalled, Session: session, Duration: 9000},
		Event{Kind: KindMkdirWitness, Item: 12, Parent: 2, Witness: WitnessPermitted, Seed: SeedMembershipAndSearch, CutSeq: 44},
	)
	authority := emit(LayerAuthority, "authority",
		Event{Kind: KindSuperblock, Superblock: "sb1", Load: LoadQuiet},
		authorityReceive(session, 1, AuthorityGetAttr),
		authorityReceive(session, 2, AuthorityLookup),
		Event{Kind: KindAuthority, Phase: PhaseReply, Session: session, AuthorityRequest: 2, AuthorityOp: AuthorityLookup, Lookup: LookupStampedNegative, Duration: 400},
		authorityReceive(session, 3, AuthorityLookup),
		Event{Kind: KindAuthority, Phase: PhaseReply, Session: session, AuthorityRequest: 3, AuthorityOp: AuthorityLookup, Lookup: LookupPositive, Duration: 600},
		authorityReceive(session, 4, AuthorityCreate),
		authorityReceive(session, 4, AuthorityCreate),
		authorityReceive(session, 5, AuthorityKeepAlive),
		Event{Kind: KindBarrier, Barrier: BarrierSyncfs, Session: session, AuthorityRequest: 4},
		Event{Kind: KindSyscall, Syscall: SyscallSyncfs, Duration: 1000, Waiters: 2, Superblock: "sb1"},
		Event{Kind: KindSyscall, Syscall: SyscallSyncfs, Duration: 3000},
		Event{Kind: KindSyscall, Syscall: SyscallFsync, Duration: 500},
	)
	var out bytes.Buffer
	if _, err := Collect(&out, []Input{
		{Name: "frontend", Reader: frontend}, {Name: "daemon", Reader: daemon}, {Name: "authority", Reader: authority},
	}, CollectConfig{}); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestReportAggregatesScenario(t *testing.T) {
	rep := reportOf(t, scenario(t), ReportConfig{})
	if !rep.AttributionValid {
		t.Fatalf("clean scenario invalid: %v", rep.InvalidReasons)
	}
	want := map[string]uint64{
		"frontend.callback.lookup":                             1,
		"frontend.callback.get_attr":                           1,
		"frontend.callback.get_attr.framework":                 1,
		"frontend.local.lookup":                                1,
		"frontend.local.get_attr":                              2,
		"frontend.local.get_attr.synthetic_enumeration":        1,
		"frontend.open.create_reuse.avoided":                   1,
		"frontend.release.close.final":                         1,
		"daemon.local.lookup":                                  1,
		"daemon.local.get_attr":                                2,
		"daemon.cache.candidate.completeness.negative":         1,
		"daemon.cache.candidate.attr_cache.miss":               1,
		"daemon.cache.candidate.attr_cache.positive":           1,
		"daemon.cache.candidate_hits":                          2,
		"daemon.cache.exposed.completeness.negative":           1,
		"daemon.cache.exposed_hits":                            1,
		"daemon.cache.ordinary_reads":                          2,
		"daemon.cache.ordinary_read.attr_cache":                2,
		"daemon.cache.miss_reason.attr_cache.cold":             1,
		"daemon.cache.miss_reason.attr_cache.terminal":         1,
		"daemon.cache.coordinate.first":                        1,
		"daemon.authority.get_attr":                            1,
		"daemon.authority.lookup":                              2,
		"daemon.authority.create":                              1,
		"daemon.authority.keep_alive":                          1,
		"daemon.authority_dispatch.replay.create":              1,
		"daemon.authority_total.foreground":                    4,
		"daemon.authority_total.background":                    1,
		"daemon.lookup.positive":                               1,
		"daemon.lookup.stamped_negative":                       1,
		"daemon.authority_time.lookup":                         2,
		"daemon.authority_time.lookup.total_ns":                12000,
		"daemon.release.close.sent":                            1,
		"daemon.release.close.tokens":                          5,
		"daemon.release.reclaim.sent":                          1,
		"daemon.release.reclaim.tokens":                        2,
		"daemon.source.acquire":                                1,
		"daemon.source.ack":                                    1,
		"daemon.source.delayed_ack":                            1,
		"daemon.open.first.emitted":                            1,
		"daemon.wait.reservation":                              2,
		"daemon.wait.reservation.total_ns":                     400,
		"daemon.occupancy.pending_reservations.max":            5,
		"daemon.occupancy.pending_reservations.final":          0,
		"daemon.renewal.initial.installed":                     1,
		"daemon.mkdir_witness.permitted.membership_and_search": 1,
		"authority.authority.get_attr":                         1,
		"authority.authority.lookup":                           2,
		"authority.authority.create":                           2,
		"authority.authority_total.foreground":                 5,
		"authority.authority_total.background":                 1,
		"authority.lookup.positive":                            1,
		"authority.lookup.stamped_negative":                    1,
		"authority.barrier.syncfs":                             1,
		"authority.syscall.syncfs":                             2,
		"authority.syscall.syncfs.total_ns":                    4000,
		"authority.syscall.syncfs.waiters":                     2,
		"authority.syscall.fsync":                              1,
		"authority.superblock_load.quiet":                      1,
		"trace.lost_events":                                    0,
		"trace.join.frontend_daemon.matched":                   3,
		"trace.join.frontend_daemon.unmatched":                 0,
		"trace.join.client_authority.matched":                  6,
		"trace.join.client_authority.unmatched":                0,
		"trace.join.client_authority.evicted":                  0,
	}
	for k, v := range want {
		got, ok := rep.Counters[k]
		if !ok || got != v {
			t.Errorf("%s = %d (present %t), want %d", k, got, ok, v)
		}
	}
	if got := rep.Latencies["authority.syscall.syncfs"]; got != (LatencySummary{Count: 2, Min: 1000, P50: 1023, P90: 3000, Max: 3000, Total: 4000}) {
		t.Errorf("syncfs latency = %+v", got)
	}
	universe := AggregateKeys()
	for k := range rep.Counters {
		if _, ok := universe[k]; !ok {
			t.Errorf("report produced key %q outside AggregateKeys", k)
		}
	}
	for k := range rep.Latencies {
		if _, ok := universe[k]; !ok {
			t.Errorf("report produced latency key %q outside AggregateKeys", k)
		}
	}
	var text bytes.Buffer
	if err := rep.WriteText(&text); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(text.String(), "attribution: exact") {
		t.Fatalf("text report does not lead with attribution:\n%s", text.String())
	}
	if _, err := json.Marshal(rep); err != nil {
		t.Fatal(err)
	}
}

func TestReportCorrelationCoverage(t *testing.T) {
	type cov struct{ matched, unmatchedLeft, unmatchedRight, evictedLeft, evictedRight uint64 }
	fiveFrontendThenDaemon := func() []*streamBuilder {
		f, d := newStream(LayerFrontend), newStream(LayerDaemon)
		// An early daemon event anchors the daemon stream's elapsed time,
		// so all frontend sends merge before the daemon enqueues.
		d.ev(0, waitEvent(1))
		for i := range uint64(5) {
			f.ev(Nanos(i), frontendSend(1, i+1, LocalLookup))
			d.ev(Nanos(100+i), daemonEnqueue(1, i+1, LocalLookup))
		}
		return []*streamBuilder{f.end(0), d.end(0)}
	}
	cases := []struct {
		name    string
		streams func() []*streamBuilder
		window  int
		join    string
		want    cov
		valid   bool
	}{
		{"matched", fiveFrontendThenDaemon, 16, joinFrontendDaemon, cov{matched: 5}, true},
		{"evicted by a small window", fiveFrontendThenDaemon, 2, joinFrontendDaemon,
			cov{unmatchedRight: 2, evictedLeft: 5, evictedRight: 3}, false},
		{"same request on another connection does not match", func() []*streamBuilder {
			return []*streamBuilder{
				newStream(LayerFrontend).ev(0, frontendSend(1, 7, LocalLookup)).end(0),
				newStream(LayerDaemon).ev(0, daemonEnqueue(2, 7, LocalLookup)).end(0),
			}
		}, 16, joinFrontendDaemon, cov{unmatchedLeft: 1, unmatchedRight: 1}, false},
		{"unmatched authority receive", func() []*streamBuilder {
			return []*streamBuilder{
				newStream(LayerDaemon).ev(0, authoritySend(session, 1, AuthorityLookup)).end(0),
				newStream(LayerAuthority).ev(0, authorityReceive(session, 1, AuthorityLookup)).ev(1, authorityReceive("s-other", 1, AuthorityLookup)).end(0),
			}
		}, 16, joinClientAuthority, cov{matched: 1, unmatchedRight: 1}, false},
		{"linux client joins the authority", func() []*streamBuilder {
			return []*streamBuilder{
				newStream(LayerLinuxClient).ev(0, authoritySend("s-linux", 1, AuthorityWrite)).end(0),
				newStream(LayerAuthority).ev(0, authorityReceive("s-linux", 1, AuthorityWrite)).end(0),
			}
		}, 16, joinClientAuthority, cov{matched: 1}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, _ := collectStreams(t, CollectConfig{}, tc.streams()...)
			rep := reportOf(t, out, ReportConfig{JoinWindow: tc.window})
			var j JoinCoverage
			for _, c := range rep.Joins {
				if c.Name == tc.join {
					j = c
				}
			}
			if !j.Applicable {
				t.Fatalf("join %s not applicable", tc.join)
			}
			got := cov{j.Matched, j.UnmatchedLeft, j.UnmatchedRight, j.EvictedLeft, j.EvictedRight}
			if got != tc.want {
				t.Fatalf("coverage = %+v, want %+v", got, tc.want)
			}
			if rep.AttributionValid != tc.valid {
				t.Fatalf("attribution valid = %t, reasons %v", rep.AttributionValid, rep.InvalidReasons)
			}
		})
	}
}

func TestReportJoinNotApplicableWithoutBothLayers(t *testing.T) {
	out, _ := collectStreams(t, CollectConfig{}, newStream(LayerFrontend).ev(0, frontendSend(1, 1, LocalLookup)).end(0))
	rep := reportOf(t, out, ReportConfig{})
	for _, j := range rep.Joins {
		if j.Applicable {
			t.Fatalf("join %s applicable with only a frontend stream", j.Name)
		}
	}
	if !rep.AttributionValid {
		t.Fatalf("untraced joins invalidated attribution: %v", rep.InvalidReasons)
	}
	var text bytes.Buffer
	if err := rep.WriteText(&text); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text.String(), "not traced") {
		t.Fatalf("text report does not say the join was not traced:\n%s", text.String())
	}
}

func TestReportSignalsInvalidAttribution(t *testing.T) {
	clean := func() *streamBuilder { return newStream(LayerDaemon).ev(0, waitEvent(1)).ev(1, waitEvent(2)) }
	cases := []struct {
		name    string
		streams []*streamBuilder
		cfg     CollectConfig
		reason  string
	}{
		{"clean", []*streamBuilder{clean().end(0)}, CollectConfig{}, ""},
		{"producer lost", []*streamBuilder{clean().end(2)}, CollectConfig{}, "2 events lost by producers"},
		{"collector dropped", []*streamBuilder{clean().end(0)}, CollectConfig{MaxEvents: 1}, "1 events dropped by collector bounds"},
		{"rejected", []*streamBuilder{clean().raw(`{"record":"event"}`).end(0)}, CollectConfig{}, "1 records rejected"},
		{"incomplete", []*streamBuilder{clean()}, CollectConfig{}, "1 streams have no trailer"},
		{"trailer disagrees", []*streamBuilder{clean().raw(`{"record":"trailer","emitted":9,"lost":0}`)}, CollectConfig{}, "trailer reports 9 events but 2 were read"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, _ := collectStreams(t, tc.cfg, tc.streams...)
			rep := reportOf(t, out, ReportConfig{})
			var text bytes.Buffer
			if err := rep.WriteText(&text); err != nil {
				t.Fatal(err)
			}
			first, _, _ := strings.Cut(text.String(), "\n")
			if tc.reason == "" {
				if !rep.AttributionValid || !strings.HasPrefix(first, "attribution: exact") {
					t.Fatalf("clean run: valid=%t first line %q", rep.AttributionValid, first)
				}
				return
			}
			if rep.AttributionValid || !strings.HasPrefix(first, "ATTRIBUTION INVALID") {
				t.Fatalf("valid=%t first line %q", rep.AttributionValid, first)
			}
			if !strings.Contains(strings.Join(rep.InvalidReasons, "\n"), tc.reason) || !strings.Contains(text.String(), tc.reason) {
				t.Fatalf("reasons %v lack %q", rep.InvalidReasons, tc.reason)
			}
		})
	}
}

func TestReportRejectsMalformedCollections(t *testing.T) {
	out, _ := collectStreams(t, CollectConfig{}, newStream(LayerDaemon).ev(0, waitEvent(1)).end(0))
	lines := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	// lines: collection, header, event, trailer, summary
	join := func(ls ...string) []byte { return []byte(strings.Join(ls, "\n") + "\n") }
	cases := []struct {
		name string
		data []byte
		want string
	}{
		{"producer stream", newStream(LayerDaemon).ev(0, waitEvent(1)).end(0).buf.Bytes(), "not a collection"},
		{"truncated", join(lines[:4]...), "ends before its summary"},
		{"missing header", join(lines[0], lines[2]), "declare stream 1"},
		{"undeclared stream", join(lines[0], lines[1], strings.Replace(lines[2], `"stream":1`, `"stream":2`, 1), lines[3], lines[4]), "undeclared stream"},
		{"summary mismatch", join(lines[0], lines[1], lines[2], lines[3], strings.Replace(lines[4], `"events":1`, `"events":2`, 1)), "summary does not match"},
		{"event after trailer", join(lines[0], lines[1], lines[3], lines[2], lines[4]), "event after the stream trailers"},
		{"data after summary", join(append(lines, lines[4])...), "data after the collection summary"},
		{"invalid event", join(lines[0], lines[1], strings.Replace(lines[2], `"wait":"reservation"`, `"wait":"lunch"`, 1), lines[3], lines[4]), "invalid value"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := BuildReport(bytes.NewReader(tc.data), ReportConfig{})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("BuildReport error = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestHistogramQuantilesAreBoundedEstimates(t *testing.T) {
	cases := []struct {
		name     string
		values   []uint64
		p50, p90 uint64 // true quantiles (nearest rank)
	}{
		{"single", []uint64{777}, 777, 777},
		{"small exact", []uint64{1, 2, 3, 4, 5, 6, 7}, 4, 7},
		{"uniform", seq(1, 100), 50, 90},
		{"wide", []uint64{10, 1_000, 100_000, 10_000_000, uint64(MaxNanos)}, 100_000, uint64(MaxNanos)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var h histogram
			for _, v := range tc.values {
				h.add(v)
			}
			s := h.summary()
			for _, q := range []struct{ got, true uint64 }{{s.P50, tc.p50}, {s.P90, tc.p90}} {
				if q.got < q.true || q.got > q.true+q.true/8 {
					t.Fatalf("estimate %d outside [%d, %d]", q.got, q.true, q.true+q.true/8)
				}
			}
			if s.Count != uint64(len(tc.values)) || s.Min != tc.values[0] || s.Max != tc.values[len(tc.values)-1] {
				t.Fatalf("summary = %+v", s)
			}
		})
	}
}

func seq(from, to uint64) []uint64 {
	var out []uint64
	for v := from; v <= to; v++ {
		out = append(out, v)
	}
	return out
}

func TestReconcile(t *testing.T) {
	rep := reportOf(t, scenario(t), ReportConfig{})
	cases := []struct {
		name     string
		counters map[string]uint64
		mapping  map[string]string
		status   string
	}{
		{"match", map[string]uint64{"lookups": 2}, map[string]string{"lookups": "daemon.authority.lookup"}, ReconcileMatch},
		{"stamped negative match", map[string]uint64{"neg": 1}, map[string]string{"neg": "daemon.lookup.stamped_negative"}, ReconcileMatch},
		{"released tokens mismatch", map[string]uint64{"tokens": 7}, map[string]string{"tokens": "daemon.release.close.tokens"}, ReconcileMismatch},
		{"barrier syscalls match", map[string]uint64{"syncfs": 2}, map[string]string{"syncfs": "authority.syscall.syncfs"}, ReconcileMatch},
		{"zero lost events match", map[string]uint64{"lost": 0}, map[string]string{"lost": "trace.lost_events"}, ReconcileMatch},
		{"nonzero lost events mismatch", map[string]uint64{"lost": 3}, map[string]string{"lost": "trace.lost_events"}, ReconcileMismatch},
		{"absent aggregate is zero", map[string]uint64{"renames": 0}, map[string]string{"renames": "daemon.authority.rename"}, ReconcileMatch},
		{"missing counter", map[string]uint64{}, map[string]string{"lookups": "daemon.authority.lookup"}, ReconcileMissingCounter},
		{"misspelled aggregate", map[string]uint64{"lookups": 0}, map[string]string{"lookups": "daemon.authority.lookpu"}, ReconcileUnknownAggregate},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			lines, ok := Reconcile(rep, tc.counters, tc.mapping)
			if len(lines) != 1 || lines[0].Status != tc.status || ok != (tc.status == ReconcileMatch) {
				t.Fatalf("lines=%+v ok=%t, want status %s", lines, ok, tc.status)
			}
		})
	}
}
