# G2 performance and conformance report

G2 implements R1–R10, the initiator publication-gate proof, C1–C11 and the
amended performance work. The design owner's F10 decision is recorded in
[design.md](design.md) and the full decision/test history in
[integration.md](integration.md#g2). Linux entry_valid and attr_valid remain
zero. Withdrawal acknowledges daemon binding removal and cached-data
InodeNotify; EntryNotify is excluded from that acknowledgement because the
retained kernel proof demonstrates the parent-lock cycle.

The implementation bounds transport recovery, preserves capacity errnos and
fence loss, flushes unmount obligations through the subscription horizon, and
adds the missing read/recall/capability/initiator proofs. Daemon metadata hits
are allocation-free, including dirty FULL holders. READDIRPLUS populates those
caches; new-directory completeness and negative caching remove CREATE probes.
Own commit progress, periodic durability, local FULL FLUSH and batched close
remove per-file control work. Flushes use four ordered chunks and bounded
identity workers; namespace withdrawal targets admitted cache footprints.
Read-page admission, CONTROL batch application and dependency queues avoid
repeated per-entry or waiter scans. Existing ingress fingerprint reuse and
ledger trimming were verified rather than implemented twice.

## Measurements

The complete chronology, raw workload observations and exact timing boundaries
are in [results.md](results.md). Tables below distinguish full workloads from
microbenchmarks and test duration. The shared Docker VM was not isolated.

| Measured item | Before | After | Boundary |
| --- | ---: | ---: | --- |
| Cached positive / negative LOOKUP allocations | 22 / 9 | 0 / 0 | Callback plus physical reply settlement; zero Authority RPCs |
| Cached shared / FULL-holder GETATTR allocations | 18 / 13 | 0 / 0 | Same boundary |
| FULL-holder LOOKUP allocations | No earlier sample | 0 | Callback plus settlement |
| Lone-writer Barrier/file | 0.982 (M's 40,000-file run) | 0.000575/file | Includes periodic and completion cuts |
| Lone-writer ChangeAck / additional control poll per file | 1.025 / 1.025 (M) | 0 / 0 | 1,000-file and full install proofs |
| FULL FLUSH/file | 1 (M) | 0 | Unlocked FULL delegation |
| Cold 1,000-entry listing | No earlier measurement | 4 READDIR, 0 LOOKUP | Mounted `ls -ln`; not a latency sample |
| 1,000-file close conformance duration | 5.26 s | 0.69 / 0.64 s | Whole test, including setup/teardown |
| CloseBatch/file | Unavailable | 0.019 / 0.016 | Same conformance repetitions; serial CLOSE 0 |
| Fresh-name LOOKUP/file | 1.05 (preceding full baseline) | 0 | Different workload sizes; final full baseline also zero |
| Own-data notifications, 100 never-cached writes | 100 | 0 | Daemon test; zero allocations on new fast path |
| Three writes after cached reader close | Per-write notify | 1 coalesced notify | No immediate notifications; live readers still drain synchronously |
| Unrelated-directory MKDIR with partitioned peer | Wait through ~10 s horizon | 416.794 us | Isolated mounted withdrawal test |
| 96-round peer-open/write regression | 99.89–100.49 s | 0.33 / 0.35 s | Unchanged whole-test bound |
| FlushAll worker pool, 32 / 4,096 files | No earlier sample | 7.76 us / 1.946 ms | Fake-flusher benchmark |
| Four-chunk ordered mounted overlap | No earlier sample | 1.13 s | Whole regression, including setup |
| 256-identity read-page admission | 64.4–65.4 us; 1,792 allocations; 256 turns | 19.0–19.2 us; 520 allocations; 1 turn | Host coordinator microbenchmark |
| CONTROL assembly, 64 / 256 entries | 63.208 / 489.961 us | 27.167 / 41.042 us | Linux handler microbenchmark |
| CONTROL assembly, 1,024 / 4,096 entries | 6,949.290 / 109,887.755 us | 141.126 / 1,118.173 us | Same; allocations unchanged |
| One-key queue, 64 / 256 waiters | 106.333 / 1,679.000 us | 15.625 / 38.916 us | Host coordinator microbenchmark |
| One-key queue, 1,024 / 4,096 waiters | 26,856.750 / 435,402.708 us | 142.458 / 548.375 us | Same |
| 256 common-plus-distinct-key waiters | 5,755,139 bytes | 122,162 bytes | Allocation regression |
| 4,096 single-key waiters | 1,016,432 bytes; 16,393 allocations | 1,278,984 bytes; 20,495 allocations | Retained-claim bookkeeping tradeoff |
| Disjoint dependency / global-reference turn | 3.731 / 67.990 us | 3.741 / 68.108 us | Steady host benchmark; no claimed improvement |
| Four-reader reply-registry lookup | 42.75 ns | 22.64 ns | Linux read-only microbenchmark; both zero allocations |
| Shared kernel LOOKUP round trip | No comparable earlier sample | p50 2.708 us; p95 14.750 us | 2,000 paired kernel requests; zero Authority RPCs |
| FULL-holder kernel LOOKUP round trip | No comparable earlier sample | p50 10.292 us; p95 29.458 us | Same; median meets target, tail does not |

The fingerprint comparison measures existing paths, not a new speedup:
standalone 1 MiB fingerprint 331.101 us, canonical metadata with ingress digest
1.404 us, retained read with digest 329.866 us and without digest 13.787 us;
protobuf clone/marshal 54.933/38.024 us. The successful install profile attributes
2.42% cumulative CPU to FlushBatch and 2.03% to the scatter mutation client path.
Those overlapping samples do not establish per-file flush RPC overhead as
dominant, so the conditional multi-identity flush RPC was not added.

The intermediate full install exposed inline close durability: after items
0a/0b/1/2, one/eight-worker time was 277.050/274.056 seconds at
3.9226/3.9300 requests per operation; after release batching and completeness
caching it was 34.665/15.409 seconds at 2.001024/1.975619. Focused durability,
own-progress and local-FLUSH tests took 5.36, 5.37 and 5.26 seconds respectively
with 0.007 Barrier/file before release batching reduced that to 0.002/file.
These are intermediate observations, not the final baseline.

Other recorded timing boundaries have no pre-change equivalent. The first
shared cached LOOKUP daemon-service sample was 4.417/5.708 us p50/p95 and its
whole syscall 70.125/79.958 us. The later shared/FULL-holder samples were
4.750/6.125 and 4.792/6.167 us daemon service, with whole-syscall
71.208/82.417 and 71.208/81.625 us. Each syscall includes two permission
GETATTRs in addition to LOOKUP. They cannot substitute for the kernel probe.
The exact kernel sample has 1,931 shared and 1,766 FULL-holder requests below
20 us out of 2,000 each. Full tables preserve intermediate runs and different
instrumentation; no uniform wall-time speedup is claimed.

## Final workload comparison

| Workload | G before (s) | G2 final (s) | G requests/op | G2 requests/op | G2 filesystem requests/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| install, 1 worker(s) | 21.028568 | 22.479856 | 7.480524 | 1.980643 | 1.966167 |
| install, 8 worker(s) | 15.706301 | 11.717305 | 6.849524 | 1.979524 | 1.966929 |
| git-status-cold | 1.379696 | 2.084653 | 1.027400 | 2.031300 | 1.026000 |
| git-status-warm | 1.195970 | 2.372260 | 0.018600 | 1.023450 | 0.018100 |
| two-mount-write-list-read | 2.644504 | 3.229293 | 9.819500 | 23.142500 | 3.170500 |

One-worker install retains one CREATE and one background WRITE per file;
LOOKUP, GETATTR, FLUSH, ChangeAck and additional control polling are all zero. Directory
creation and close/release batches are amortized. Eight-worker misses and every
control request remain visible in the opcode table. The install denominator is
42,000 operations (40,000 files plus 2,000 directories); opcode/file divides by
40,000. These are different denominators.

Cold and warm Git each issue 20,104 RECLAIMs;
READDIRPLUS capability cleanup raises total RPC counts even though warm metadata
is cached. The peer workload issues 69,257 RECLAIMs,
performs 5 scans, observes 140 files during writing,
and verifies all 2,000. G's preceding peer sample observed one file during
writing; the overlap differs materially. These shared-VM timings are not an
isolated speedup experiment, and Git/peer totals are explicit remaining costs.

Full opcode and barrier/drain tables are in [results.md](results.md#g2-final-baseline-and-qualification).

## Interfaces

- Optional batched CLOSE operation, bounded to 128 handles, with ordered per-handle
  errors and exact replay; peers without the optional feature retain serial close.
- Optional `ordered-delegated-flush-v1`, additive `WriteRequest.flush_sequence`
  and `Response.session_terminal`. Frozen required feature strings remain intact.
- Writeback batch/scatter flushing, identity-scoped durability, and errno-bearing
  drop reports/accessors; coordinator read-set guards and exact withdrawal leases.
- One profile-capture path and an optional kernel LOOKUP bpftrace probe. Neither
  changes the required production protocol or default gate prerequisites.

## Qualification and limits

Final gate and workload results are recorded below. Focused Docker
wrappers exit 70 if required inventory is omitted; that is never a full gate pass.
Historical failed runs remain in results.md, including the fixed admission
lock cycle and PLUS cleanup pressure, and one unexplained profile mount abort.
Three focused profiled install repeats and a complete profiled baseline passed
after that abort. Capability RECLAIM traffic remains a measurable Git and peer
workload cost. Local timings are not production SLOs. Live macOS FSKit,
package-manager soak and a production-network cell are not demonstrated by
these Linux gates.

## Exact qualification commands

- `bash scripts/verify-local.sh --full`: exit 0 at production commit `bcc23eb`,
  `/tmp/cv2-g2-final-full5.log`. Foundation/cgo Darwin and static Linux builds,
  native Go/race/vet, all 345 Swift tests with exact inventory equality,
  release/workflow policy and architecture scans pass.
- `bash scripts/xfs-fuse-integration.sh`: invoked by that full gate; all 76
  required privileged cases and one root boundary pass.
- `bash scripts/coherence-matrix-linux.sh`: invoked by that full gate; 28 cases
  and all controls pass. The existing single-principal chown case is explicitly
  skipped, not counted as demonstrated. A separate final invocation also exits
  0 (`/tmp/cv2-g2-final-matrix.log`), with both mounts still serving.
- `PORTABLEFS_GO_TEST_FLAGS='-run ^TestPagedReaddirContinuesAcrossRemoteMutation$ -count=10' bash scripts/xfs-fuse-integration.sh`:
  ten passes after the PLUS fix; wrapper 70 solely for omitted inventory.
- `docker run --rm -v "$PWD/vcs:/src:ro" -w /src golang@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36 go test -race ./internal/fusev3 -run '^TestReadDirPlus' -count=5`:
  pass. The full gate also runs the complete Linux package tests.

- `PORTABLEFS_PERFORMANCE_TEST=1 PORTABLEFS_GO_TEST_FLAGS='-run ^TestCoherenceBaseline$' bash scripts/xfs-fuse-integration.sh`:
  all workloads pass in 116.58s, with Git preparation at shipping cache
  capacity, completion barriers and close drain. Focused wrapper exits 70 for
  omitted inventory; `/tmp/cv2-g2-final-baseline3.log`.

## Changed files

The following is the cumulative G2 file inventory from the parent of R1 through
the qualification fix. The final report and raw measurement artifact are
`docs/coherence-v2/G2-report.md` and `docs/coherence-v2/results-g2-final.jsonl`.

- `docs/coherence-v2/client.md`
- `docs/coherence-v2/design.md`
- `docs/coherence-v2/handler.md`
- `docs/coherence-v2/integration.md`
- `docs/coherence-v2/profiles.md`
- `docs/coherence-v2/results-g2-after-11.jsonl`
- `docs/coherence-v2/results-g2-profile.jsonl`
- `docs/coherence-v2/results-g2-state-index.jsonl`
- `docs/coherence-v2/results.md`
- `docs/coherence-v2/wire.md`
- `proto/authority/v1/authority.proto`
- `scripts/cached-lookup-roundtrip.bt`
- `scripts/coherence-matrix-linux.sh`
- `scripts/coherence-v2-profiles.py`
- `scripts/xfs-fuse-integration.sh`
- `vcs/internal/authoritypb/authority.pb.go`
- `vcs/internal/authorityrpc/cache_footprint_linux.go`
- `vcs/internal/authorityrpc/cache_footprint_linux_test.go`
- `vcs/internal/authorityrpc/change_ack_lane_test.go`
- `vcs/internal/authorityrpc/client.go`
- `vcs/internal/authorityrpc/client_restart_test.go`
- `vcs/internal/authorityrpc/client_test.go`
- `vcs/internal/authorityrpc/client_transport.go`
- `vcs/internal/authorityrpc/close_batch_linux.go`
- `vcs/internal/authorityrpc/close_batch_linux_test.go`
- `vcs/internal/authorityrpc/close_batch_wire_test.go`
- `vcs/internal/authorityrpc/coherence_control_linux.go`
- `vcs/internal/authorityrpc/coherence_control_linux_test.go`
- `vcs/internal/authorityrpc/coherence_create_linux_test.go`
- `vcs/internal/authorityrpc/coherence_mutation_linux.go`
- `vcs/internal/authorityrpc/coherence_mutation_linux_test.go`
- `vcs/internal/authorityrpc/coherence_open_linux.go`
- `vcs/internal/authorityrpc/coherence_read_stamp_linux_test.go`
- `vcs/internal/authorityrpc/coherence_readdir_guard_linux_test.go`
- `vcs/internal/authorityrpc/coherence_reads_linux.go`
- `vcs/internal/authorityrpc/coherence_reads_linux_test.go`
- `vcs/internal/authorityrpc/coherence_v2_client_test.go`
- `vcs/internal/authorityrpc/coherence_v2_wire_test.go`
- `vcs/internal/authorityrpc/fingerprint_benchmark_test.go`
- `vcs/internal/authorityrpc/frame.go`
- `vcs/internal/authorityrpc/frame_segments_test.go`
- `vcs/internal/authorityrpc/frame_test.go`
- `vcs/internal/authorityrpc/optional_close_linux_test.go`
- `vcs/internal/authorityrpc/optional_close_test.go`
- `vcs/internal/authorityrpc/ordered_flush_linux_test.go`
- `vcs/internal/authorityrpc/ordered_lanes_test.go`
- `vcs/internal/authorityrpc/protocol.go`
- `vcs/internal/authorityrpc/protocol_test.go`
- `vcs/internal/authorityrpc/server.go`
- `vcs/internal/authorityrpc/server_metrics.go`
- `vcs/internal/authorityrpc/server_transport.go`
- `vcs/internal/authorityrpc/session_terminal_linux_test.go`
- `vcs/internal/authorityrpc/session_terminal_test.go`
- `vcs/internal/authorityrpc/transport_registry.go`
- `vcs/internal/authorityrpc/transport_role.go`
- `vcs/internal/authorityrpc/transport_role_test.go`
- `vcs/internal/authorityrpc/volume_handler_linux.go`
- `vcs/internal/authorityrpc/volume_handler_linux_test.go`
- `vcs/internal/authorityrpc/wire_validate.go`
- `vcs/internal/fusev3/cache_batch_linux.go`
- `vcs/internal/fusev3/cache_ownership_admission_linux_test.go`
- `vcs/internal/fusev3/cache_publication_linux.go`
- `vcs/internal/fusev3/cached_metadata_linux.go`
- `vcs/internal/fusev3/client_v7_linux_test.go`
- `vcs/internal/fusev3/coherence_baseline_linux_test.go`
- `vcs/internal/fusev3/coherence_linux.go`
- `vcs/internal/fusev3/coherence_measurement_linux_test.go`
- `vcs/internal/fusev3/coherence_profile_linux_test.go`
- `vcs/internal/fusev3/complete_directory_linux.go`
- `vcs/internal/fusev3/complete_directory_linux_test.go`
- `vcs/internal/fusev3/concurrent_truncate_proof_linux_test.go`
- `vcs/internal/fusev3/control_horizon_linux_test.go`
- `vcs/internal/fusev3/create_truncate_linux_test.go`
- `vcs/internal/fusev3/delegation_frontend_linux.go`
- `vcs/internal/fusev3/delegation_linux.go`
- `vcs/internal/fusev3/delegation_linux_test.go`
- `vcs/internal/fusev3/delegation_pipeline_integration_linux_test.go`
- `vcs/internal/fusev3/delegation_pipeline_linux.go`
- `vcs/internal/fusev3/delegation_pipeline_linux_test.go`
- `vcs/internal/fusev3/delegation_release_linux.go`
- `vcs/internal/fusev3/delegation_release_linux_test.go`
- `vcs/internal/fusev3/epoch_frontend_linux_test.go`
- `vcs/internal/fusev3/epoch_rpc_linux.go`
- `vcs/internal/fusev3/file_durability_linux_test.go`
- `vcs/internal/fusev3/flush_linux.go`
- `vcs/internal/fusev3/flush_linux_test.go`
- `vcs/internal/fusev3/fuse_linux.go`
- `vcs/internal/fusev3/fuse_linux_test.go`
- `vcs/internal/fusev3/graft_linux_test.go`
- `vcs/internal/fusev3/holder_metadata_linux.go`
- `vcs/internal/fusev3/holder_metadata_linux_test.go`
- `vcs/internal/fusev3/integration_linux_test.go`
- `vcs/internal/fusev3/integration_localroutes_linux_test.go`
- `vcs/internal/fusev3/integration_support_linux_test.go`
- `vcs/internal/fusev3/kernel_invalidation_proof_linux_test.go`
- `vcs/internal/fusev3/kernel_namespace_lock_proof_linux_test.go`
- `vcs/internal/fusev3/own_read_cache_integration_linux_test.go`
- `vcs/internal/fusev3/own_read_cache_linux.go`
- `vcs/internal/fusev3/own_read_cache_linux_test.go`
- `vcs/internal/fusev3/performance_integration_linux_test.go`
- `vcs/internal/fusev3/raw_linux.go`
- `vcs/internal/fusev3/readdirplus_linux.go`
- `vcs/internal/fusev3/readdirplus_linux_test.go`
- `vcs/internal/fusev3/registry_read_linux_test.go`
- `vcs/internal/fusev3/revocation_linux_test.go`
- `vcs/internal/fusev3/source_publication_linux.go`
- `vcs/internal/fusev3/source_publication_linux_test.go`
- `vcs/internal/fusev3/stock_write_linux.go`
- `vcs/internal/fusev3/subscription_batch_linux.go`
- `vcs/internal/fusev3/subscription_batch_linux_test.go`
- `vcs/internal/fusev3/subscription_linux.go`
- `vcs/internal/fusev3/subscription_linux_test.go`
- `vcs/internal/fusev3/targeted_withdrawal_integration_linux_test.go`
- `vcs/internal/restoremode/interop_test.go`
- `vcs/internal/volumeserver/cache_footprint.go`
- `vcs/internal/volumeserver/cache_footprint_test.go`
- `vcs/internal/volumeserver/delegation.go`
- `vcs/internal/volumeserver/delegation_read_set.go`
- `vcs/internal/volumeserver/delegation_read_set_test.go`
- `vcs/internal/volumeserver/delegation_test.go`
- `vcs/internal/volumeserver/delegation_try.go`
- `vcs/internal/volumeserver/delegation_try_test.go`
- `vcs/internal/volumeserver/mutation_sequencer.go`
- `vcs/internal/volumeserver/mutation_sequencer_scaling_test.go`
- `vcs/internal/volumeserver/ordered_flush.go`
- `vcs/internal/volumeserver/ordered_flush_test.go`
- `vcs/internal/volumeserver/storage_sequencer.go`
- `vcs/internal/volumeserver/storage_sequencer_test.go`
- `vcs/internal/volumeserver/subscription.go`
- `vcs/internal/volumeserver/subscription_test.go`
- `vcs/internal/writeback/buffer.go`
- `vcs/internal/writeback/buffer_test.go`
- `vcs/internal/writeback/flush.go`
- `vcs/internal/writeback/flush_observer_test.go`
- `vcs/internal/writeback/flush_pool_test.go`
- `vcs/internal/writeback/read.go`
- `vcs/internal/writeback/release_overlay_test.go`
- `vcs/internal/writeback/types.go`
- `vcs/internal/writeback/wave.go`
- `vcs/internal/writeback/wave_test.go`
- `vcs/internal/xfsstore/readdir_linux_test.go`
- `vcs/internal/xfsstore/volume_linux.go`
- `vcs/internal/xfsstore/volume_linux_test.go`

- `docs/coherence-v2/G2-report.md`
- `docs/coherence-v2/results-g2-final.jsonl`
- `docs/performance.md`
