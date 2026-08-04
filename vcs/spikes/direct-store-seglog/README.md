# Segmented-log direct-store measurement spike

This is a measurement spike, not a filesystem prototype. It does not serve
`fsproto`, implement consensus, or change a production storage path.

It builds the Phase 1 on-replica storage format that the independent review
recommended after both Phase 0 candidates failed their gates: **a segmented
append-only mutation/value log as the durable readable representation, with a
rebuildable Pebble index over log offsets.** It then tries to break it.

The commit scheme implemented in `seglog/`:

- self-describing, CRC-32C checksummed records with sequence numbers;
- group commit at 1 ms or 1 MiB, whichever comes first, with explicit
  durability barriers committing immediately;
- one `writev(2)` plus one `File.Sync` per group, followed by a group trailer
  record so recovery can find the last complete group rather than the last
  structurally valid record;
- the in-memory index and the durable sequence advance after the sync, so every
  acknowledged record is exposed through an index pointing into the log;
- the persistent Pebble index is built asynchronously with the WAL disabled,
  because it is rebuildable from the log;
- a greedy segment cleaner relocates live records out of the emptiest sealed
  segments, makes the relocated index entries durable once per pass, and then
  reclaims the sources.

On Darwin the measured bytes are the delta of
`proc_pid_rusage(RUSAGE_INFO_V4).ri_diskio_byteswritten`; on Linux they are the
delta of `/proc/self/io`'s `write_bytes`. That is the same primary metric, the
same counter interval discipline, and the same fixture curve, workloads, key
encoding, and logical mutation sequence as
[`../direct-store-writeamp`](../direct-store-writeamp), so the rows line up.

## Running

```bash
cd vcs/spikes/direct-store-seglog
go vet ./...
go test ./...

# same table as the Phase 0 spike, plus a plain-Pebble control
go run . -mode table -sizes 128,4096,65536,524288 -reps 3 \
  -engines seglog,pebble -out results.csv

# the experiment the review called its own strongest counterargument
go run . -mode steady -live-cells 262144 -warmup-turns 2 -measure-turns 3 \
  -utilizations 0.7,0.8,0.9 -out steady.csv

# fsync floor, batch benefit, read latency, recovery, index footprint
go run . -mode micro -out micro.csv
```

## Files

| file | contents |
| :--- | :--- |
| `seglog/record.go` | record framing and checksum |
| `seglog/store.go` | segments, group commit, index, recovery |
| `seglog/cleaner.go` | greedy segment cleaning and reclamation |
| `index_pebble.go` | the rebuildable Pebble index over log offsets |
| `engine.go` | the logical filesystem mutations and the plain-Pebble control |
| `table.go` | the amplification table matching the Phase 0 spike |
| `steady.go` | steady-state cleaning and compaction amplification |
| `micro.go` | fsync floor, batching, read latency, recovery, index memory |

## Raw runs

| file | contents |
| :--- | :--- |
| `results.csv` | 168 rows, the same schema as `../direct-store-writeamp/results.csv` plus group, cleaning, index, store, and fsync-latency columns |
| `micro.csv` | fsync floor, batching curve, recovery on both paths, index footprint, read latency |
| `steady.csv` | segmented log in steady state at 70%, 80%, and 90% live-data occupancy |
| `steady-pebble.csv` | the plain-Pebble control over nine working-set turnovers |

The corrected Phase 4 amplification gates and the reasons they had to change are
in `docs/direct-store-exploration.md`, under "Corrections to the amplification
gates".

Headline: at 524,288 files a 4 KiB random overwrite cost 3.53x on one replica
against PFT2's 22.56x, and the curve is flat in tree size rather than rising
with it. In steady state under uniformly random overwrite of a 1 GiB live set,
one replica cost 1.93x at 70% occupancy, 2.74x at 80%, and 4.33x at 90%, with
the plain-Pebble control at 4.57x and 2.7x space amplification. At a 4 KiB
durable commit unit, APFS itself charges 2.5x before any format writes a byte.
