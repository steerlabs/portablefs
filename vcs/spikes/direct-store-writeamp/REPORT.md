# Direct-store write-amplification measurement

This is a measurement spike, not a filesystem prototype. It compares the
existing `vcs/internal/pft2` editor with bbolt 1.5.0 under the same logical
workloads and transaction boundaries.

## Recommendation

Do not use PFT2 as the Phase 1 live on-replica format under a durable root per
small operation. It is the less write-amplifying of the two measured engines,
but it misses the exploration's absolute rejection gates by a wide margin.
Do not use default durable bbolt as the fallback either: it wrote more than
PFT2 on the dominant random, append, and mixed workloads.

At the largest fixture (524,288 files; PFT2 inode-index depth 3), PFT2 wrote
22.56 physical bytes per random 4 KiB application byte, versus 35.00 for
bbolt. The realistic mix was 39.45 for PFT2 versus 51.03 for bbolt. With
three replicas durably applying the same mutation, those become 67.69 versus
105.00 for random writes and 118.36 versus 153.09 for the mix.

The Phase 4 format gates require at most 2x one-replica amplification for
sequential bulk data and reject random overwrites above 15x across three full
replicas. PFT2's smallest sequential point was already 5.06x per replica. At
depth two and above, random writes were 54.94x-67.69x across three replicas.
The canonical PFT2 objects alone were 2.40x at depth one and 15.70x at depth
two for random writes, so garbage collection or a different append-log frame
cannot recover the missing order of magnitude.

The honest Phase 0 result is therefore that neither measured format is
acceptable. Keep PFT2 as the immutable snapshot and export format. Before
selecting a Phase 1 live engine, run this same counter-based harness against a
long-lived Pebble configuration and, separately, measure batching. If no KV
configuration passes the absolute gates, stop the direct-store direction;
relative victory over bbolt is not a waiver for PFT2's rejection thresholds.

## Measurement definition

The primary number is the delta of the macOS kernel's per-process
`ri_diskio_byteswritten` counter around a sequence of durable transactions.
Every PFT2 transaction appends its exact new canonical objects plus a root
install record and calls `fsync`. Every bbolt `Update` uses its default durable
commit (`NoSync=false`, `NoFreelistSync=false`, array freelist), and the DB is
synced again before the ending counter. These are actual process-attributed
kernel disk bytes, not encoded-size estimates. The counter does not expose
SSD-controller/NAND write amplification.

For PFT2, `format_bytes` in the raw data separately counts the exact canonical
object bytes emitted by the production editor, and `path_write_bytes` counts
the actual append-log records passed to `write(2)`. The append log is a
measurement sink only; it is not a proposed persistence format or a
filesystem prototype. bbolt is compared using the common kernel counter
rather than a modeled page count.

"Logical bytes" means application data payload:

- random update and append: 4,096 bytes per operation;
- small file create: 128 bytes per operation;
- rename, chmod, and mkdir: zero data bytes.

Metadata-only amplification is mathematically undefined because the
denominator is zero. Those workloads are reported as physical KiB per
operation instead. Inventing a logical metadata-byte encoding would make the
ratio arbitrary.

All displayed values are medians of three runs. Standalone workloads contain
32 one-operation durable transactions. The mixed workload contains 100:
50 random 4 KiB writes, 20 appends, 10 128-byte creates, 10 renames, 5 chmods,
and 5 mkdirs. The maximum within-point range was 5.12% of the median.

## Fixtures and tree curve

Each fixture has one root directory and the stated number of files. Inode 2
starts empty for appends; the remaining files are 1 GiB sparse files, so tree
size is large without prewriting hundreds of GiB. Random writes choose files
and 4 KiB-aligned offsets deterministically. Every mutation is one transaction
for both engines.

| Files | PFT2 inode-index depth | PFT2 root-directory depth |
| ---: | ---: | ---: |
| 128 | 1 | 1 |
| 4,096 | 2 | 2 |
| 65,536 | 2 | 2 |
| 524,288 | 3 | 2 |

The curve is over natural PFT2 B+tree depth, not synthetic deep nodes.
Directory nesting depth was not varied.

## Canonical PFT2 path-copy cost

This table excludes append-log framing, filesystem allocation, and
replication. It is the exact total size of new canonical PFT2 objects divided
by application data bytes.

| Files | Depth (inode/dir) | Random 4 KiB | Append 4 KiB | Mixed |
| ---: | :---: | ---: | ---: | ---: |
| 128 | 1/1 | 2.40x | 2.54x | 3.33x |
| 4,096 | 2/2 | 15.70x | 17.26x | 27.15x |
| 65,536 | 2/2 | 17.52x | 17.78x | 30.72x |
| 524,288 | 3/2 | 19.83x | 20.55x | 35.46x |

The depth-2 step is the deciding structural observation: PFT2 path copying is
not free, and most of the physical amplification at larger sizes is already
present in canonical object bytes rather than append-log framing.

## Physical disk amplification before and after replication

Each cell is `one replica -> three durable replicas`. The three-way value is
the measured single-replica amplification multiplied by exactly three. It
does not include a separate consensus log, network framing, leader metadata,
or retries.

The proposed three-voter acknowledgement needs two full durable copies, so
the minimum aggregate bytes on the success path are twice the one-replica
number. Maintaining the third readable voter makes the steady group cost the
three-way value in the table, matching the exploration's cluster gates.

| Files | Depth | Random PFT2 | Random bbolt | Append PFT2 | Append bbolt | Mixed PFT2 | Mixed bbolt |
| ---: | :---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 128 | 1/1 | 4.94x -> 14.81x | 29.38x -> 88.12x | 5.06x -> 15.19x | 28.50x -> 85.50x | 8.25x -> 24.75x | 40.16x -> 120.49x |
| 4,096 | 2/2 | 18.31x -> 54.94x | 34.75x -> 104.25x | 20.19x -> 60.56x | 35.62x -> 106.88x | 32.38x -> 97.15x | 42.15x -> 126.46x |
| 65,536 | 2/2 | 20.03x -> 60.09x | 35.12x -> 105.38x | 20.25x -> 60.75x | 35.75x -> 107.25x | 35.53x -> 106.58x | 49.66x -> 148.99x |
| 524,288 | 3/2 | 22.56x -> 67.69x | 35.00x -> 105.00x | 23.09x -> 69.28x | 35.75x -> 107.25x | 39.45x -> 118.36x | 51.03x -> 153.09x |

At depth 3, one random 4 KiB write caused a median 92,416 physical bytes on
one PFT2 replica, or 277,248 bytes across three. bbolt wrote 143,360 bytes on
one replica, or 430,080 across three.

## Small file creates

The small-create denominator is the 128-byte file body. The large ratios are
real but should be read together with the per-operation size: PFT2 wrote
23 KiB per create at 128 files and 214 KiB per create at 524,288 files.

| Files | Depth | PFT2 | bbolt |
| ---: | :---: | ---: | ---: |
| 128 | 1/1 | 184x -> 552x | 912x -> 2,736x |
| 4,096 | 2/2 | 1,103x -> 3,309x | 1,272x -> 3,816x |
| 65,536 | 2/2 | 1,442x -> 4,326x | 1,272x -> 3,816x |
| 524,288 | 3/2 | 1,711x -> 5,133x | 1,400x -> 4,200x |

## Metadata-only operations

Each cell is `one replica -> three replicas`, in physical KiB per operation.

| Operation | Files | PFT2 KiB/op | bbolt KiB/op |
| :--- | ---: | ---: | ---: |
| rename | 128 | 15.9 -> 47.6 | 64.0 -> 192.0 |
| rename | 4,096 | 77.6 -> 232.9 | 96.0 -> 288.0 |
| rename | 65,536 | 80.0 -> 240.0 | 128.0 -> 384.0 |
| rename | 524,288 | 91.6 -> 274.9 | 144.0 -> 432.0 |
| chmod | 128 | 15.0 -> 45.0 | 64.0 -> 192.0 |
| chmod | 4,096 | 68.5 -> 205.5 | 80.0 -> 240.0 |
| chmod | 65,536 | 76.4 -> 229.1 | 96.0 -> 288.0 |
| chmod | 524,288 | 84.9 -> 254.6 | 96.0 -> 288.0 |
| mkdir | 128 | 18.6 -> 55.9 | 64.0 -> 192.0 |
| mkdir | 4,096 | 185.4 -> 556.1 | 112.5 -> 337.5 |
| mkdir | 65,536 | 193.5 -> 580.5 | 144.0 -> 432.0 |
| mkdir | 524,288 | 223.1 -> 669.4 | 160.0 -> 480.0 |

PFT2 is better for rename and chmod throughout this curve. bbolt is better
for mkdir once both PFT2 indexes reach depth 2.

## Interpretation

PFT2 wins relative to default bbolt on the workloads that dominate the stated
problem: scattered small data writes, append-heavy files, and the measured
mixed workload. Its margin persists at depth 3. That result rejects bbolt; it
does not select PFT2. A 39.45x mixed-workload result becomes 118.36x at three
replicas before consensus-log cost, and the sequential and random points fail
the format gates independently of the mixed workload.

The result argues for keeping immutable PFT2 history objects off an unbatched
per-operation live path. PFT2's existing verification and snapshot behavior
remain valuable at the export boundary, where the path-copy cost is paid per
snapshot rather than for every small acknowledged mutation.

The prior live read observations are useful targets, not comparable
denominators: 16.3 object fetches/MiB at roughly 230 ms each, and 541 MiB
materialized in 21 seconds for one warm history cut. This spike did not
measure reads, so it cannot establish that either PFT2 or bbolt beats those
numbers. A follow-up local read/scan benchmark must do so.

## Confidence and exclusions

Confidence in the measured curves is high for this harness: operations are
deterministic, PFT2 canonical byte totals are exact, every transaction is
synced, both engines use the same kernel disk-byte counter, all points have
three runs, and within-point physical spread is at most 5.12%.

Confidence in the format recommendation is medium because the harness does
not capture:

- long-running fragmentation, bbolt freelist evolution, or file reuse after
  thousands or millions of transactions;
- Pebble or another LSM, including foreground flush cost and compaction debt
  accumulated over time;
- cache effects or read amplification: the immutable PFT2 base is fetched
  from memory so only writes are under measurement;
- overwrites of densely populated file data: random updates materialize
  nonzero cells into sparse 1 GiB files;
- deep directory nesting or lookup cost before an inode-number mutation;
- transaction batching or concurrent writers;
- a production PFT2 local object layout: the synced append log isolates the
  tree's emitted bytes but is only a measurement sink;
- consensus WAL, checksums, allocator metadata, repair traffic, failed
  quorum attempts, network cost, and retry duplication;
- crash cut points or recovery correctness;
- raw SSD NAND/FTL amplification below the macOS kernel counter;
- filesystem portability beyond APFS.

## Reproduction and raw data

Measured on Apple M5 Max (`Mac17,7`), macOS 26.5 build 25F71, APFS on a
4,096-byte-block SSD, Go 1.26.5, repository commit `d6b865c5a495`.

```bash
cd vcs/spikes/direct-store-writeamp
/opt/homebrew/bin/go test ./...
/opt/homebrew/bin/go run . -out results.csv
```

The nested module pins bbolt 1.5.0 without changing production module
dependencies. `results.csv` contains all 168 raw rows and the exact logical,
canonical PFT2, append-path, kernel, duration, and three-way fields. Its SHA-256
is `1faf7202f131ed96ae15ac4e20e1db27446062f11de6c642665fae4677bf3406`.
