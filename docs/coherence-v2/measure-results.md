# Protocol 7 measurement results

Product revision: `5f76079`; v6 reference: `67c52ef`. Two unprofiled runs use the unchanged `TestCoherenceBaseline` workload and meter. Raw observations are in `vcs/bench/coherencebench/testdata/results/v7-run{1,2}.jsonl`.

## Method and environment

Both runs use the method in [baseline.md](baseline.md): 40,000 1 KiB files and 2,000 directories with 1 and 8 workers (42,000 operations); cold then immediate warm ordinary `git status --porcelain=v1` on 20,000 committed 1 KiB files (20,000 operations); and 2,000 published and verified files across two mounts (4,000 operations). Git configuration, the 1.1-second pre-add wait, cold-cache definitions, and initial reader/writer handshake are unchanged. The install meter includes empty-root preflight; its wall time excludes preflight. Git disables automatic GC/maintenance and ignores system/global configuration. Direct-XFS cold status follows `sync` and `FADV_DONTNEED` on regular files while retaining inode/dentry caches; PortableFS cold recreates the Authority and mount without claiming eviction of backing XFS file pages.

The measured name cache and item capacities are 65,536. Untimed Git setup retains the baseline's 4,096-name-cache workaround, followed by a complete Authority/mount recreation at 65,536; its item capacity remains 65,536. The separate shipping-capacity regression is recorded in [measure-findings.md](measure-findings.md).

Measurements ran on 2026-09-16. The privileged Docker VM has 4 CPUs and 8 GiB RAM (8,309,018,624 reported bytes), kernel `6.8.0-100-generic`. The digest-pinned image is `golang@sha256:116d58cbd88c1297624acc6e967a060012422bacf9930927e23fb719189c6f36`. Storage is a 1 GiB loop-backed XFS image on `/var/tmp` tmpfs, with a 512 MiB/200,000-inode test-volume quota. Authority and mounts run in the fixture process over loopback TLS and real kernel FUSE. These timings do not measure physical-disk throughput.

Unrelated containers run on the shared VM during these measurements. The wall times therefore are not isolated comparisons and should not be treated as speedup ratios. Authority counts are scoped to the fixture's in-process request handler, so other containers do not enter those counts. Every requested workload ran at full size; none was scaled down.

Exact command, run twice (logs `/tmp/cv2-measure-run1.log` and `/tmp/cv2-measure-run2.log`):

```sh
PORTABLEFS_PERFORMANCE_TEST=1 \
PORTABLEFS_GO_TEST_FLAGS='-run ^TestCoherenceBaseline$' \
bash scripts/xfs-fuse-integration.sh
```

Both complete tests passed: run 1 in 157.08s and run 2 in 157.94s. The focused wrapper's exit 70 denotes missing unrelated required tests after the benchmark PASS. It is not a full-suite gate pass.

Counts include every filesystem and control request, including requests entering long polls. The meter remains active through asynchronous FUSE RELEASE and Authority CLOSE completion. The separate drain column excludes that duration from workload wall time. No explicit directory durability barrier was added to the baseline method.

## Wall time and requests

| Workload | Target | v6 seconds | v6 requests | v6 requests/op | v7 run 1 seconds | v7 run 1 requests | v7 run 1 requests/op | v7 run 2 seconds | v7 run 2 requests | v7 run 2 requests/op |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Install (40,000 files, 1 worker) | direct-xfs | 0.578806 | 0 | 0.000000 | 0.638134 | 0 | 0.000000 | 0.588055 | 0 | 0.000000 |
| Install (40,000 files, 8 workers) | direct-xfs | 0.344368 | 0 | 0.000000 | 0.539694 | 0 | 0.000000 | 0.480171 | 0 | 0.000000 |
| Install (40,000 files, 1 worker) | portablefs | 386.762771 | 329,884 | 7.854381 | 28.615024 | 330,882 | 7.878143 | 25.340879 | 331,746 | 7.898714 |
| Install (40,000 files, 8 workers) | portablefs | 273.738199 | 317,582 | 7.561476 | 23.448464 | 276,391 | 6.580738 | 17.336575 | 275,084 | 6.549619 |
| Git status cold (20,000 files) | direct-xfs | 0.037750 | 0 | 0.000000 | 0.012877 | 0 | 0.000000 | 0.010153 | 0 | 0.000000 |
| Git status warm (20,000 files) | direct-xfs | 0.021925 | 0 | 0.000000 | 0.011208 | 0 | 0.000000 | 0.008538 | 0 | 0.000000 |
| Git status cold (20,000 files) | portablefs | 10.572948 | 20,809 | 1.040450 | 1.349883 | 20,554 | 1.027700 | 1.332196 | 20,538 | 1.026900 |
| Git status warm (20,000 files) | portablefs | 2.042038 | 553 | 0.027650 | 1.045073 | 370 | 0.018500 | 1.134188 | 370 | 0.018500 |
| Two-mount write/list/read (2,000 files) | direct-xfs | 0.063784 | 0 | 0.000000 | 0.022379 | 0 | 0.000000 | 0.075126 | 0 | 0.000000 |
| Two-mount write/list/read (2,000 files) | portablefs | 12.536042 | 31,510 | 7.877500 | 1.863137 | 42,081 | 10.520250 | 2.362157 | 40,307 | 10.076750 |

## Close drain and filesystem counts

The original v6 classifier labels new v7 control opcodes as filesystem requests. This table moves subscription, change-event/acknowledgment, and delegation-release/acknowledgment traffic to control; raw JSON retains the original fields. Total Authority counts are unchanged. `barrier` remains a filesystem operation.

| Workload | Version/run | Filesystem requests | Filesystem requests/op | Close drain seconds |
| --- | --- | ---: | ---: | ---: |
| Install (40,000 files, 1 worker) | v6 | 210,201 | 5.004786 | 0.001376 |
| Install (40,000 files, 1 worker) | v7 run 1 | 245,570 | 5.846905 | 0.018517 |
| Install (40,000 files, 1 worker) | v7 run 2 | 246,303 | 5.864357 | 0.019425 |
| Install (40,000 files, 8 workers) | v6 | 208,079 | 4.954262 | 0.002229 |
| Install (40,000 files, 8 workers) | v7 run 1 | 214,237 | 5.100881 | 0.314907 |
| Install (40,000 files, 8 workers) | v7 run 2 | 213,205 | 5.076310 | 0.210924 |
| Git status cold (20,000 files) | v6 | 20,525 | 1.026250 | 0.000003 |
| Git status cold (20,000 files) | v7 run 1 | 20,534 | 1.026700 | 0.010914 |
| Git status cold (20,000 files) | v7 run 2 | 20,526 | 1.026300 | 0.011121 |
| Git status warm (20,000 files) | v6 | 363 | 0.018150 | 0.000004 |
| Git status warm (20,000 files) | v7 run 1 | 363 | 0.018150 | 0.010965 |
| Git status warm (20,000 files) | v7 run 2 | 363 | 0.018150 | 0.012252 |
| Two-mount write/list/read (2,000 files) | v6 | 22,680 | 5.670000 | 0.001131 |
| Two-mount write/list/read (2,000 files) | v7 run 1 | 23,212 | 5.803000 | 0.001127 |
| Two-mount write/list/read (2,000 files) | v7 run 2 | 23,218 | 5.804500 | 0.001151 |

## Per-opcode requests

Zero denotes an opcode absent from that run's recorded map.

### Install (40,000 files, 1 worker)

| Opcode | v6 | v7 run 1 | v7 run 2 |
| --- | ---: | ---: | ---: |
| `acknowledge_source_lease_discharge` | 82,001 | 0 | 0 |
| `barrier` | 0 | 39,277 | 39,418 |
| `change_ack` | 0 | 40,994 | 40,910 |
| `close` | 40,001 | 40,001 | 40,001 |
| `create` | 40,000 | 40,000 | 40,000 |
| `delegation_release` | 0 | 1,133 | 1,056 |
| `flush` | 40,000 | 40,000 | 40,000 |
| `get_attr` | 3,509 | 112 | 326 |
| `keep_alive` | 58 | 4 | 3 |
| `lookup` | 44,689 | 44,178 | 44,556 |
| `mkdir` | 2,000 | 2,000 | 2,000 |
| `next_control_event` | 0 | 40,994 | 40,910 |
| `open` | 1 | 1 | 1 |
| `read_dir` | 1 | 1 | 1 |
| `reclaim` | 6,831 | 2,178 | 2,556 |
| `renew_leases` | 30,793 | 0 | 0 |
| `renew_subscription` | 0 | 9 | 8 |
| `write` | 40,000 | 40,000 | 40,000 |


### Install (40,000 files, 8 workers)

| Opcode | v6 | v7 run 1 | v7 run 2 |
| --- | ---: | ---: | ---: |
| `acknowledge_source_lease_discharge` | 82,001 | 0 | 0 |
| `barrier` | 0 | 7,915 | 6,730 |
| `change_ack` | 0 | 29,800 | 29,604 |
| `close` | 40,001 | 40,001 | 40,001 |
| `create` | 40,000 | 40,000 | 40,000 |
| `delegation_release` | 0 | 314 | 314 |
| `flush` | 40,000 | 40,000 | 40,000 |
| `get_attr` | 1,690 | 89 | 122 |
| `keep_alive` | 41 | 3 | 2 |
| `lookup` | 44,386 | 44,230 | 44,350 |
| `mkdir` | 2,000 | 2,000 | 2,000 |
| `next_control_event` | 0 | 29,800 | 29,604 |
| `open` | 1 | 1 | 1 |
| `read_dir` | 1 | 1 | 1 |
| `reclaim` | 2,386 | 2,230 | 2,350 |
| `renew_leases` | 25,075 | 0 | 0 |
| `renew_subscription` | 0 | 7 | 5 |
| `write` | 40,000 | 40,000 | 40,000 |


### Git status cold (20,000 files)

| Opcode | v6 | v7 run 1 | v7 run 2 |
| --- | ---: | ---: | ---: |
| `acknowledge_source_lease_discharge` | 2 | 0 | 0 |
| `change_ack` | 0 | 2 | 2 |
| `close` | 120 | 120 | 120 |
| `create` | 1 | 1 | 1 |
| `delegation_release` | 0 | 1 | 1 |
| `flush` | 17 | 17 | 17 |
| `get_attr` | 1 | 0 | 0 |
| `keep_alive` | 1 | 0 | 0 |
| `lookup` | 20,143 | 20,153 | 20,145 |
| `next_control_event` | 0 | 2 | 2 |
| `open` | 119 | 119 | 119 |
| `read` | 20 | 20 | 20 |
| `read_dir` | 103 | 103 | 103 |
| `reclaim` | 4 | 15 | 7 |
| `renew_leases` | 277 | 0 | 0 |
| `unlink` | 1 | 1 | 1 |


### Git status warm (20,000 files)

| Opcode | v6 | v7 run 1 | v7 run 2 |
| --- | ---: | ---: | ---: |
| `acknowledge_source_lease_discharge` | 2 | 0 | 0 |
| `change_ack` | 0 | 2 | 2 |
| `close` | 120 | 120 | 120 |
| `create` | 1 | 1 | 1 |
| `delegation_release` | 0 | 1 | 1 |
| `flush` | 17 | 17 | 17 |
| `lookup` | 2 | 2 | 2 |
| `next_control_event` | 0 | 2 | 2 |
| `open` | 119 | 119 | 119 |
| `read_dir` | 103 | 103 | 103 |
| `reclaim` | 1 | 2 | 2 |
| `renew_leases` | 187 | 0 | 0 |
| `unlink` | 1 | 1 | 1 |


### Two-mount write/list/read (2,000 files)

| Opcode | v6 | v7 run 1 | v7 run 2 |
| --- | ---: | ---: | ---: |
| `acknowledge_lease_event` | 2,002 | 0 | 0 |
| `acknowledge_source_lease_discharge` | 4,000 | 0 | 0 |
| `barrier` | 0 | 1,943 | 1,890 |
| `change_ack` | 0 | 6,242 | 6,326 |
| `close` | 4,229 | 4,009 | 4,010 |
| `create` | 2,000 | 2,000 | 2,000 |
| `delegation_break_ack` | 0 | 2,652 | 1,655 |
| `delegation_release` | 0 | 86 | 105 |
| `flush` | 4,000 | 4,000 | 4,000 |
| `get_attr` | 865 | 162 | 146 |
| `keep_alive` | 2 | 0 | 0 |
| `lookup` | 4,419 | 4,957 | 4,984 |
| `next_control_event` | 0 | 8,933 | 8,020 |
| `next_lease_event` | 2,002 | 0 | 0 |
| `open` | 2,229 | 2,009 | 2,010 |
| `read` | 2,009 | 2,002 | 2,001 |
| `read_dir` | 929 | 130 | 177 |
| `reclaim` | 418 | 956 | 983 |
| `renew_leases` | 406 | 0 | 0 |
| `write` | 2,000 | 2,000 | 2,000 |


## Reader/writer overlap

| Target/run | Directory scans | ESTALE retries | Incomplete-read retries | Vanished-read retries | Files verified before writer finished |
| --- | ---: | ---: | ---: | ---: | ---: |
| v6 direct-xfs | 10 | 0 | 4 | 0 | 1928 |
| v6 portablefs | 229 | 203 | 0 | 0 | 467 |
| v7 run 1 direct-xfs | 7 | 0 | 0 | 0 | 1601 |
| v7 run 1 portablefs | 9 | 0 | 0 | 0 | 1190 |
| v7 run 2 direct-xfs | 14 | 0 | 3 | 0 | 1704 |
| v7 run 2 portablefs | 10 | 0 | 0 | 0 | 1302 |
