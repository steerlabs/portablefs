# Coherence v2 baseline

This is the pre-v7 performance baseline required by workstream E. It measures
the v6 implementation at `origin/main` `67c52ef` with only documentation,
kernel-proof tests, and this measurement harness added. It is an observed
sample, not a performance gate or an SLO.

## Environment

The measurement ran on 2026-09-16 in the privileged Docker suite on a 4 CPU,
8 GiB Linux VM. The container reported kernel `6.8.0-100-generic`. The suite
used image
`golang@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36`,
a 1 GiB loop-backed XFS image stored on the container's `/var/tmp` tmpfs, and
the normal test-volume quota of 512 MiB and
200,000 inodes.

The PortableFS cases used the existing integration fixture: an in-process
Authority over loopback TLS, loop-backed XFS storage, and real kernel FUSE
mounts. These timings do not measure physical-disk throughput. The measured
mounts used 65,536 as both the name-cache capacity and
per-session item capacity. Those are the shipping capacities; the other
settings remain the integration fixture profile.

The exact command was:

```sh
PORTABLEFS_PERFORMANCE_TEST=1 \
PORTABLEFS_GO_TEST_FLAGS='-run ^TestCoherenceBaseline$' \
bash scripts/xfs-fuse-integration.sh
```

Output was captured with `tee` in `/tmp/cv2-coherence-baseline-final.log`; the
complete measurement records are preserved below.

`TestCoherenceBaseline` passed in 1,343.64 seconds. The wrapper exited 70 after
the passing test because a focused `-run` invocation does not run the suite's
other required tests. That audit result is expected for the documented focused
command; it is not a benchmark failure.

Unrelated test containers began using the shared VM after the direct-install
rows completed. The wall times therefore are not isolated comparisons and
should not be treated as speedup ratios. Authority counts are scoped to the
fixture's in-process request handler, so other containers do not enter those
counts. Every requested workload ran at full size; none was scaled down.

## Method

The install workload creates a tree of 2,000 directories, then creates, writes
1 KiB to, and closes 40,000 files. It runs once with one worker and once with
eight. Its operation denominator is 42,000: one logical operation per installed
file plus one per directory. The Authority meter begins before the install
workload's empty-root preflight, while wall timing begins immediately after the
preflight. The PortableFS install counts therefore include that preflight's
`OPEN`, `READ_DIR`, and `CLOSE`; its small duration is outside the reported wall
time.

The Git workload creates and commits 20,000 distinct 1 KiB files in 100
directories, disables automatic GC and maintenance in the repository, and
isolates the run from system and global Git configuration. Preparation waits
1.1 seconds before `git add` so the index is newer than every tracked file.
Both measured commands are ordinary `git status --porcelain=v1` runs over a
clean repository. The operation denominator is 20,000 tracked files.

For direct XFS, the cold Git run follows `sync` and `FADV_DONTNEED` on every
regular file. This asks the kernel to discard clean file pages but retains
inode and dentry caches. For PortableFS, cold means that the complete Authority
and mount were recreated
before the first status; it does not claim that the backing XFS page cache was
dropped. Warm is the immediate second status in both cases.

Preparing the 20,000-file repository through a fresh fixture already set to
65,536 entries failed during `git add` at
`src-014/file-002841.txt`: `unable to create temporary file: Transport endpoint
is not connected`, followed by a FUSE `LOOKUP` write failure with `ENOTCONN`.
The failure's cause was not isolated. The final run prepared the repository
through the established 4,096-entry integration profile, then recreated the
complete Authority and mount at 65,536 before either measured status. Thus both
Git measurements use the shipping name-cache and session-item capacities;
only untimed repository setup uses 4,096.

The two-mount workload publishes 2,000 files through mount A while mount B
repeatedly lists the directory and reads and validates published files. The
reader completes an initial scan before the writer starts, and the writer waits
for B to validate the first file before continuing. The denominator is 4,000:
one write and one verified read per file. An `ESTALE` from a listing that races
a v6 mutation is retried and counted; `EIO` and `ENOTCONN` are not retried.

The headline Authority count includes every filesystem and control request
observed at the handler, including renewal, reclaim, lease-event, and lease
discharge traffic. The filesystem-only columns make that split visible. The
meter stays open until asynchronous FUSE `RELEASE` calls receive their
corresponding Authority `CLOSE` replies, and the drain duration is reported
separately from workload wall time. Long-poll requests
are counted when they enter the handler.

## Results

| Workload | Target | Workers | Wall (s) | Authority requests | Requests/op | Filesystem requests | Filesystem requests/op | Close drain (s) |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Install: 40,000 files + 2,000 dirs | Direct XFS | 1 | 0.578806 | 0 | 0 | 0 | 0 | - |
| Install: 40,000 files + 2,000 dirs | PortableFS | 1 | 386.762771 | 329,884 | 7.854381 | 210,201 | 5.004786 | 0.001376 |
| Install: 40,000 files + 2,000 dirs | Direct XFS | 8 | 0.344368 | 0 | 0 | 0 | 0 | - |
| Install: 40,000 files + 2,000 dirs | PortableFS | 8 | 273.738199 | 317,582 | 7.561476 | 208,079 | 4.954262 | 0.002229 |
| Git status: cold, 20,000 files | Direct XFS | - | 0.037750 | 0 | 0 | 0 | 0 | - |
| Git status: cold, 20,000 files | PortableFS | - | 10.572948 | 20,809 | 1.040450 | 20,525 | 1.026250 | 0.000003 |
| Git status: warm, 20,000 files | Direct XFS | - | 0.021925 | 0 | 0 | 0 | 0 | - |
| Git status: warm, 20,000 files | PortableFS | - | 2.042038 | 553 | 0.027650 | 363 | 0.018150 | 0.000004 |
| Two-mount write/list/read, 2,000 files | Direct XFS | - | 0.063784 | 0 | 0 | 0 | 0 | - |
| Two-mount write/list/read, 2,000 files | PortableFS | - | 12.536042 | 31,510 | 7.877500 | 22,680 | 5.670000 | 0.001131 |

The direct two-view workload made 10 directory scans, retried four reads that
observed an incomplete file, and verified 1,928 files before the writer
finished. The PortableFS workload made 229 directory scans, retried 203
`ESTALE` results, needed no incomplete or vanished-file read retries, and
verified 467 files before the writer finished. These observations establish
that the reader and writer overlapped in both cases.

## Raw observations

These are the complete `PORTABLEFS_BASELINE` JSON records from the final run.

```jsonl
{"scenario":"install","operations":42000,"files":40000,"directories":2000,"workers":1,"wall_seconds":0.578806105,"target":"direct-xfs","authority_requests":0,"authority_requests_per_operation":0,"authority_filesystem_requests":0,"authority_filesystem_requests_per_operation":0}
{"scenario":"install","operations":42000,"files":40000,"directories":2000,"workers":8,"wall_seconds":0.344368418,"target":"direct-xfs","authority_requests":0,"authority_requests_per_operation":0,"authority_filesystem_requests":0,"authority_filesystem_requests_per_operation":0}
{"scenario":"install","operations":42000,"files":40000,"directories":2000,"workers":1,"wall_seconds":386.762770797,"target":"portablefs","authority_requests":329884,"authority_requests_per_operation":7.854380952380953,"authority_filesystem_requests":210201,"authority_filesystem_requests_per_operation":5.004785714285714,"authority_filesystem_breakdown":{"close":40001,"create":40000,"flush":40000,"get_attr":3509,"lookup":44689,"mkdir":2000,"open":1,"read_dir":1,"write":40000},"authority_control_breakdown":{"acknowledge_source_lease_discharge":82001,"keep_alive":58,"reclaim":6831,"renew_leases":30793},"authority_drain_seconds":0.001376353}
{"scenario":"install","operations":42000,"files":40000,"directories":2000,"workers":8,"wall_seconds":273.738199316,"target":"portablefs","authority_requests":317582,"authority_requests_per_operation":7.56147619047619,"authority_filesystem_requests":208079,"authority_filesystem_requests_per_operation":4.954261904761905,"authority_filesystem_breakdown":{"close":40001,"create":40000,"flush":40000,"get_attr":1690,"lookup":44386,"mkdir":2000,"open":1,"read_dir":1,"write":40000},"authority_control_breakdown":{"acknowledge_source_lease_discharge":82001,"keep_alive":41,"reclaim":2386,"renew_leases":25075},"authority_drain_seconds":0.002228794}
{"scenario":"git-status-cold","operations":20000,"files":20000,"wall_seconds":0.03775042,"target":"direct-xfs","authority_requests":0,"authority_requests_per_operation":0,"authority_filesystem_requests":0,"authority_filesystem_requests_per_operation":0}
{"scenario":"git-status-warm","operations":20000,"files":20000,"wall_seconds":0.021924776,"target":"direct-xfs","authority_requests":0,"authority_requests_per_operation":0,"authority_filesystem_requests":0,"authority_filesystem_requests_per_operation":0}
{"scenario":"git-status-cold","operations":20000,"files":20000,"wall_seconds":10.572948301,"target":"portablefs","authority_requests":20809,"authority_requests_per_operation":1.04045,"authority_filesystem_requests":20525,"authority_filesystem_requests_per_operation":1.02625,"authority_filesystem_breakdown":{"close":120,"create":1,"flush":17,"get_attr":1,"lookup":20143,"open":119,"read":20,"read_dir":103,"unlink":1},"authority_control_breakdown":{"acknowledge_source_lease_discharge":2,"keep_alive":1,"reclaim":4,"renew_leases":277},"authority_drain_seconds":0.000002958}
{"scenario":"git-status-warm","operations":20000,"files":20000,"wall_seconds":2.04203828,"target":"portablefs","authority_requests":553,"authority_requests_per_operation":0.02765,"authority_filesystem_requests":363,"authority_filesystem_requests_per_operation":0.01815,"authority_filesystem_breakdown":{"close":120,"create":1,"flush":17,"lookup":2,"open":119,"read_dir":103,"unlink":1},"authority_control_breakdown":{"acknowledge_source_lease_discharge":2,"reclaim":1,"renew_leases":187},"authority_drain_seconds":0.000004041}
{"scenario":"two-mount-write-list-read","operations":4000,"files":2000,"directory_scans":10,"incomplete_read_retries":4,"files_observed_during_write":1928,"wall_seconds":0.063783873,"target":"direct-xfs","authority_requests":0,"authority_requests_per_operation":0,"authority_filesystem_requests":0,"authority_filesystem_requests_per_operation":0}
{"scenario":"two-mount-write-list-read","operations":4000,"files":2000,"transient_retries":203,"directory_scans":229,"files_observed_during_write":467,"wall_seconds":12.536041922999999,"target":"portablefs","authority_requests":31510,"authority_requests_per_operation":7.8775,"authority_filesystem_requests":22680,"authority_filesystem_requests_per_operation":5.67,"authority_filesystem_breakdown":{"close":4229,"create":2000,"flush":4000,"get_attr":865,"lookup":4419,"open":2229,"read":2009,"read_dir":929,"write":2000},"authority_control_breakdown":{"acknowledge_lease_event":2002,"acknowledge_source_lease_discharge":4000,"keep_alive":2,"next_lease_event":2002,"reclaim":418,"renew_leases":406},"authority_drain_seconds":0.00113098}
```
