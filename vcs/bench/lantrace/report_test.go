package lantrace

import (
	"bytes"
	"encoding/json"
	"fmt"
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
			if (layer == LayerFrontend || layer == LayerDaemon) && e.RequestID != 0 && e.FrontendPID == 0 {
				e.FrontendPID, e.AttachRef, e.ConnRole = 1234, "attach-1", "portablefskit"
				if layer == LayerFrontend {
					e.Conn = "550e8400-e29b-41d4-a716-446655440000"
				} else {
					e.Conn = "42"
				}
			}
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
		Event{Kind: KindCallback, Phase: PhasePublicationComplete, Callback: 1, CallbackKind: CallbackLookup, Conn: "550e8400-e29b-41d4-a716-446655440000", Operation: 9, Publication: PublicationPublished},
		Event{Kind: KindCallback, Phase: PhaseEntry, Callback: 2, CallbackKind: CallbackGetAttr, Origin: OriginFramework},
		frontendSend(1, 2, LocalGetAttr),
		func() Event { e := frontendSend(1, 3, LocalGetAttr); e.Origin = OriginSyntheticEnumeration; return e }(),
		Event{Kind: KindOpen, Item: 10, OpenReason: OpenCreateReuse, Mode: ModeWrite, RPC: RPCAvoided, LiveMode: LiveWrite},
		Event{Kind: KindRelease, Item: 10, ReleaseKind: ReleaseClose},
	)
	daemon := emit(LayerDaemon, "portablefsd",
		daemonEnqueue(1, 1, LocalLookup),
		daemonEnqueue(1, 2, LocalGetAttr),
		daemonEnqueue(1, 3, LocalGetAttr),
		Event{Kind: KindCache, Phase: PhaseCandidate, Conn: "42", RequestID: 1, Candidate: CandidateCompleteness, CacheResult: CacheNegative, Parent: 2, NameHex: name, Cert: CertPresent, Search: SearchPermitted},
		Event{Kind: KindCache, Phase: PhaseFinal, Conn: "42", RequestID: 1, Candidate: CandidateCompleteness, CacheResult: CacheNegative, Exposure: ExposureAccepted, Coordinate: CoordinateFirst},
		Event{Kind: KindCache, Phase: PhaseCandidate, Conn: "42", RequestID: 2, Candidate: CandidateAttrCache, CacheResult: CacheMiss, MissReason: MissCold},
		Event{Kind: KindCache, Phase: PhaseFinal, Conn: "42", RequestID: 2, Candidate: CandidateAttrCache, CacheResult: CacheMiss, Exposure: ExposureOrdinaryRead, MissReason: MissCold},
		Event{Kind: KindCache, Phase: PhaseCandidate, Conn: "42", RequestID: 3, Candidate: CandidateAttrCache, CacheResult: CachePositive, Proof: ProofValid, ProofAge: 1000, SourceState: SourceSettled},
		Event{Kind: KindCache, Phase: PhaseFinal, Conn: "42", RequestID: 3, Candidate: CandidateAttrCache, CacheResult: CachePositive, Exposure: ExposureOrdinaryRead, MissReason: MissTerminal},
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
		Event{Kind: KindSource, Phase: PhaseAcquire, Conn: "42", Operation: 9},
		Event{Kind: KindSource, Phase: PhaseAck, Conn: "42", Operation: 9, Successor: 10, Publication: PublicationPublished},
		Event{Kind: KindOpen, Item: 11, OpenReason: OpenFirst, Mode: ModeRead, RPC: RPCEmitted, Conn: "42", RequestID: 3},
		Event{Kind: KindWait, Wait: WaitReservation, Duration: 100, Conn: "42", RequestID: 2},
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
	type cov struct {
		matched, unmatchedLeft, unmatchedRight, evictedLeft, evictedRight, unqualified, conflicts uint64
		status                                                                                    string
	}
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
	pair := func(front, daemon Event) func() []*streamBuilder {
		return func() []*streamBuilder {
			return []*streamBuilder{
				newStream(LayerFrontend).ev(0, front).end(0),
				newStream(LayerDaemon).ev(0, daemon).end(0),
			}
		}
	}
	cases := []struct {
		name    string
		streams func() []*streamBuilder
		window  int
		join    string
		want    cov
		valid   bool
	}{
		{"matched", fiveFrontendThenDaemon, 16, joinFrontendDaemon, cov{matched: 5, status: JoinExact}, true},
		{"evicted by a small window", fiveFrontendThenDaemon, 2, joinFrontendDaemon,
			cov{unmatchedRight: 2, evictedLeft: 5, evictedRight: 3, status: JoinIncomplete}, false},
		{"same request on another attach does not match",
			pair(frontendSend(1, 7, LocalLookup), daemonEnqueue(2, 7, LocalLookup)),
			16, joinFrontendDaemon, cov{unmatchedLeft: 1, unmatchedRight: 1, status: JoinIncomplete}, false},
		{"same attach and request in another role does not match",
			pair(frontendSend(1, 1, LocalLookup), func() Event { e := daemonEnqueue(1, 1, LocalLookup); e.ConnRole = "portablefskit-events"; return e }()),
			16, joinFrontendDaemon, cov{unmatchedLeft: 1, unmatchedRight: 1, status: JoinIncomplete}, false},
		{"same request on another frontend PID does not match",
			pair(frontendSend(1, 1, LocalLookup), func() Event { e := daemonEnqueue(1, 1, LocalLookup); e.FrontendPID++; return e }()),
			16, joinFrontendDaemon, cov{unmatchedLeft: 1, unmatchedRight: 1, status: JoinIncomplete}, false},
		{"different request IDs do not match",
			pair(frontendSend(1, 1, LocalLookup), daemonEnqueue(1, 2, LocalLookup)),
			16, joinFrontendDaemon, cov{unmatchedLeft: 1, unmatchedRight: 1, status: JoinIncomplete}, false},
		{"conflicting operation is not a match",
			pair(frontendSend(1, 1, LocalLookup), daemonEnqueue(1, 1, LocalGetAttr)),
			16, joinFrontendDaemon, cov{unmatchedLeft: 1, conflicts: 1, status: JoinIncomplete}, false},
		{"conflicting mount is not a match",
			pair(func() Event { e := frontendSend(1, 1, LocalLookup); e.Mount = "mount-a"; return e }(),
				func() Event { e := daemonEnqueue(1, 1, LocalLookup); e.Mount = "mount-b"; return e }()),
			16, joinFrontendDaemon, cov{unmatchedLeft: 1, conflicts: 1, status: JoinIncomplete}, false},
		// A daemon-local counter alone supplies no shared identity.
		{"anchors without the shared tuple leave the join unavailable",
			pair(func() Event { e := frontendSend(1, 1, LocalLookup); e.FrontendPID = 0; return e }(), func() Event { e := daemonEnqueue(1, 1, LocalGetAttr); e.FrontendPID = 0; return e }()),
			16, joinFrontendDaemon, cov{unqualified: 2, status: JoinUnavailable}, false},
		{"one side without an attach leaves the join unavailable",
			pair(frontendSend(1, 1, LocalLookup), func() Event { e := daemonEnqueue(1, 1, LocalLookup); e.AttachRef = ""; return e }()),
			16, joinFrontendDaemon, cov{unmatchedLeft: 1, unqualified: 1, status: JoinUnavailable}, false},
		{"unmatched authority receive", func() []*streamBuilder {
			return []*streamBuilder{
				newStream(LayerDaemon).ev(0, authoritySend(session, 1, AuthorityLookup)).end(0),
				newStream(LayerAuthority).ev(0, authorityReceive(session, 1, AuthorityLookup)).ev(1, authorityReceive("s-other", 1, AuthorityLookup)).end(0),
			}
		}, 16, joinClientAuthority, cov{matched: 1, unmatchedRight: 1, status: JoinIncomplete}, false},
		{"conflicting authority operation is not a match", func() []*streamBuilder {
			return []*streamBuilder{
				newStream(LayerDaemon).ev(0, authoritySend(session, 1, AuthorityLookup)).end(0),
				newStream(LayerAuthority).ev(0, authorityReceive(session, 1, AuthorityGetAttr)).end(0),
			}
		}, 16, joinClientAuthority, cov{unmatchedLeft: 1, conflicts: 1, status: JoinIncomplete}, false},
		{"linux client joins the authority", func() []*streamBuilder {
			return []*streamBuilder{
				newStream(LayerLinuxClient).ev(0, authoritySend("s-linux", 1, AuthorityWrite)).end(0),
				newStream(LayerAuthority).ev(0, authorityReceive("s-linux", 1, AuthorityWrite)).end(0),
			}
		}, 16, joinClientAuthority, cov{matched: 1, status: JoinExact}, true},
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
			got := cov{j.Matched, j.UnmatchedLeft, j.UnmatchedRight, j.EvictedLeft, j.EvictedRight, j.Unqualified, j.Conflicts, j.Status}
			if got != tc.want {
				t.Fatalf("coverage = %+v, want %+v", got, tc.want)
			}
			if rep.AttributionValid != tc.valid {
				t.Fatalf("attribution valid = %t, reasons %v", rep.AttributionValid, rep.InvalidReasons)
			}
		})
	}
}

// BuildReport validates per-stream sequence order on its own; it does not
// rely on Collect having done so.
func TestReportRejectsInvalidSequenceHistories(t *testing.T) {
	twoEvents := func() []byte {
		out, _ := collectStreams(t, CollectConfig{}, newStream(LayerDaemon).ev(0, waitEvent(1)).ev(1, waitEvent(2)).end(0))
		return out
	}
	gapped := func() []byte {
		// Numbers 1 and 3 with emitted=2, lost=0: one number is unaccounted
		// for, so Collect flags the stream inconsistent.
		out, sum := collectStreams(t, CollectConfig{}, newStream(LayerDaemon).evSeq(1, 0, waitEvent(1)).evSeq(3, 1, waitEvent(2)).end(0))
		if sum.InconsistentStreams != 1 {
			t.Fatalf("collect did not flag the gap: %+v", sum)
		}
		return out
	}
	cases := []struct {
		name   string
		edit   func([]byte) []byte
		source func() []byte
	}{
		{"duplicate sequence", func(b []byte) []byte { return bytes.Replace(b, []byte(`"seq":2,`), []byte(`"seq":1,`), 1) }, twoEvents},
		{"reordered sequence", func(b []byte) []byte {
			b = bytes.Replace(b, []byte(`"seq":1,`), []byte(`"seq":9,`), 1)
			return b
		}, twoEvents},
		{"gap the trailer does not flag", func(b []byte) []byte {
			b = bytes.Replace(b, []byte(`,"inconsistent":true`), nil, 1)
			return bytes.Replace(b, []byte(`"inconsistent_streams":1`), []byte(`"inconsistent_streams":0`), 1)
		}, gapped},
		{"consistent stream flagged inconsistent", func(b []byte) []byte {
			b = bytes.Replace(b, []byte(`"rejected":0}`), []byte(`"rejected":0,"inconsistent":true}`), 1)
			return bytes.Replace(b, []byte(`"inconsistent_streams":0`), []byte(`"inconsistent_streams":1`), 1)
		}, twoEvents},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			original := tc.source()
			edited := tc.edit(append([]byte(nil), original...))
			if bytes.Equal(edited, original) {
				t.Fatal("edit did not change the collection")
			}
			if _, err := BuildReport(bytes.NewReader(edited), ReportConfig{}); err == nil {
				t.Fatal("BuildReport accepted an invalid sequence history")
			}
		})
	}
	t.Run("flagged gap invalidates attribution", func(t *testing.T) {
		rep := reportOf(t, gapped(), ReportConfig{})
		if rep.AttributionValid || !strings.Contains(strings.Join(rep.InvalidReasons, "\n"), "do not reconcile") {
			t.Fatalf("valid=%t reasons %v", rep.AttributionValid, rep.InvalidReasons)
		}
	})
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

// A complete tuple and each producer's own connection witness are required
// throughout the run, including records after an otherwise matching pair.
func TestReportRefusesUnprovableLocalConnections(t *testing.T) {
	for _, field := range []string{"frontend_pid", "attach_ref", "conn_role", "request_id", "conn"} {
		t.Run("missing "+field, func(t *testing.T) {
			f, d := frontendSend(1, 1, LocalLookup), daemonEnqueue(1, 1, LocalLookup)
			switch field {
			case "frontend_pid":
				d.FrontendPID = 0
			case "attach_ref":
				d.AttachRef = ""
			case "conn_role":
				d.ConnRole = ""
			case "request_id":
				d.RequestID = 0
			case "conn":
				d.Conn = ""
			}
			out, _ := collectStreams(t, CollectConfig{}, newStream(LayerFrontend).ev(0, f).end(0), newStream(LayerDaemon).ev(0, d).end(0))
			assertLocalJoinUnavailable(t, reportOf(t, out, ReportConfig{}))
		})
	}
	for _, layer := range []Layer{LayerFrontend, LayerDaemon} {
		t.Run("duplicate same-role connection on "+string(layer), func(t *testing.T) {
			f, d := newStream(LayerFrontend), newStream(LayerDaemon)
			f.ev(0, frontendSend(1, 1, LocalLookup))
			d.ev(0, daemonEnqueue(1, 1, LocalLookup))
			// The first pair has already matched before another connection
			// appears, with a disjoint request ID. It must erase that match.
			if layer == LayerFrontend {
				e := frontendSend(1, 2, LocalLookup)
				e.Conn = "111e8400-e29b-41d4-a716-446655440000"
				f.ev(100, e)
			} else {
				e := daemonEnqueue(1, 2, LocalLookup)
				e.Conn = "99"
				d.ev(100, e)
			}
			out, _ := collectStreams(t, CollectConfig{}, f.end(0), d.end(0))
			assertLocalJoinUnavailable(t, reportOf(t, out, ReportConfig{}))
		})
	}
	t.Run("PID reuse across producer processes", func(t *testing.T) {
		// Even equal daemon-local counters in different producer streams
		// are distinct connections. A recycled PID cannot reconnect them.
		out, _ := collectStreams(t, CollectConfig{},
			newStream(LayerFrontend).ev(0, frontendSend(1, 1, LocalLookup)).end(0),
			newStream(LayerDaemon).ev(0, daemonEnqueue(1, 1, LocalLookup)).end(0),
			newStream(LayerDaemon).ev(0, daemonEnqueue(1, 2, LocalLookup)).end(0))
		assertLocalJoinUnavailable(t, reportOf(t, out, ReportConfig{}))
	})
	t.Run("pre-bind record cannot be repaired by a later Resolve", func(t *testing.T) {
		prebind := frontendSend(1, 1, LocalLookup)
		prebind.AttachRef = ""
		out, _ := collectStreams(t, CollectConfig{},
			newStream(LayerFrontend).ev(0, prebind).ev(100, frontendSend(1, 2, LocalLookup)).end(0),
			newStream(LayerDaemon).ev(0, daemonEnqueue(1, 2, LocalLookup)).end(0))
		assertLocalJoinUnavailable(t, reportOf(t, out, ReportConfig{}))
	})
	t.Run("request-bearing non-anchor cannot hide a second connection", func(t *testing.T) {
		late := daemonEnqueue(1, 2, LocalLookup)
		late.Phase = PhaseReply
		late.Conn = "99"
		out, _ := collectStreams(t, CollectConfig{},
			newStream(LayerFrontend).ev(0, frontendSend(1, 1, LocalLookup)).end(0),
			newStream(LayerDaemon).ev(0, daemonEnqueue(1, 1, LocalLookup)).ev(100, late).end(0))
		assertLocalJoinUnavailable(t, reportOf(t, out, ReportConfig{}))
	})
	t.Run("local witness cannot change its binding", func(t *testing.T) {
		out, _ := collectStreams(t, CollectConfig{},
			newStream(LayerFrontend).ev(0, frontendSend(1, 1, LocalLookup)).ev(100, frontendSend(2, 1, LocalLookup)).end(0),
			newStream(LayerDaemon).ev(0, daemonEnqueue(1, 1, LocalLookup)).ev(100, daemonEnqueue(2, 1, LocalLookup)).end(0))
		assertLocalJoinUnavailable(t, reportOf(t, out, ReportConfig{}))
	})
	t.Run("whole-run uniqueness inventory is bounded without eviction", func(t *testing.T) {
		f, d := newStream(LayerFrontend), newStream(LayerDaemon)
		for i := uint64(1); i <= MaxLocalConnections+1; i++ {
			front, daemon := frontendSend(i, 1, LocalLookup), daemonEnqueue(i, 1, LocalLookup)
			front.Conn, daemon.Conn = front.AttachRef, daemon.AttachRef+"-daemon"
			f.ev(Nanos(i), front)
			d.ev(Nanos(i), daemon)
		}
		out, _ := collectStreams(t, CollectConfig{}, f.end(0), d.end(0))
		assertLocalJoinUnavailable(t, reportOf(t, out, ReportConfig{}))
	})
}

func assertLocalJoinUnavailable(t *testing.T, rep *Report) {
	t.Helper()
	j := rep.Joins[0]
	if j.Status != JoinUnavailable || j.Matched != 0 || j.Unqualified == 0 || rep.AttributionValid {
		t.Fatalf("join %+v validity %t reasons %v", j, rep.AttributionValid, rep.InvalidReasons)
	}
}

func TestReportJoinsDistinctRolesAndFrontendPIDs(t *testing.T) {
	f, d := newStream(LayerFrontend), newStream(LayerDaemon)
	for i := uint32(0); i < 3; i++ {
		front, daemon := frontendSend(1, 1, LocalLookup), daemonEnqueue(1, 1, LocalLookup)
		if i == 1 {
			front.ConnRole, daemon.ConnRole = "portablefskit-events", "portablefskit-events"
		}
		if i == 2 {
			front.FrontendPID++
			daemon.FrontendPID++
		}
		front.Conn = TraceID(fmt.Sprintf("uuid-%d", i))
		daemon.Conn = TraceID(fmt.Sprintf("%d", i+42))
		f.ev(Nanos(i), front)
		d.ev(Nanos(i), daemon)
	}
	out, _ := collectStreams(t, CollectConfig{}, f.end(0), d.end(0))
	rep := reportOf(t, out, ReportConfig{})
	if !rep.AttributionValid || rep.Joins[0].Matched != 3 || rep.Joins[0].Status != JoinExact {
		t.Fatalf("join %+v reasons %v", rep.Joins[0], rep.InvalidReasons)
	}
}

func TestReviewRepeatedLocalRequestIdentity(t *testing.T) {
	f, d := newStream(LayerFrontend), newStream(LayerDaemon)
	f.ev(0, frontendSend(1, 1, LocalLookup)).ev(100, frontendSend(1, 1, LocalGetAttr))
	d.ev(0, daemonEnqueue(1, 1, LocalLookup)).ev(100, daemonEnqueue(1, 1, LocalGetAttr))
	out, _ := collectStreams(t, CollectConfig{}, f.end(0), d.end(0))
	rep := reportOf(t, out, ReportConfig{})
	if rep.AttributionValid || rep.Joins[0].Matched != 0 || rep.Joins[0].Status != JoinUnavailable {
		t.Fatalf("same full key identifies Lookup and GetAttr but report certifies: join=%+v valid=%t", rep.Joins[0], rep.AttributionValid)
	}
}

func TestReportLocalAnchorOrderProvesUniqueness(t *testing.T) {
	for _, layer := range []Layer{LayerFrontend, LayerDaemon} {
		for _, id := range []uint64{1, 2} {
			for _, op := range []LocalOp{LocalLookup, LocalGetAttr} {
				t.Run(fmt.Sprintf("%s/id-%d/%s", layer, id, op), func(t *testing.T) {
					f, d := newStream(LayerFrontend), newStream(LayerDaemon)
					f.ev(0, frontendSend(1, 2, LocalLookup))
					d.ev(0, daemonEnqueue(1, 2, LocalLookup))
					if layer == LayerFrontend {
						f.ev(100, frontendSend(1, id, op))
					} else {
						d.ev(100, daemonEnqueue(1, id, op))
					}
					out, _ := collectStreams(t, CollectConfig{}, f.end(0), d.end(0))
					assertLocalJoinUnavailable(t, reportOf(t, out, ReportConfig{}))
				})
			}
		}
	}
}
