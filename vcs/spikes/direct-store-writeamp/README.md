# Direct-store write-amplification spike

This is a measurement spike, not a filesystem prototype. It does not serve
`fsproto`, implement consensus, or change a production storage path.

The command applies deterministic logical filesystem mutations to the real
`pft2.Editor` and to bbolt 1.5.0. PFT2 objects go to a synced append log with a
root-install record after every operation. bbolt uses its default durable
transaction and freelist behavior. Both engines start each repetition from the
same logical sparse namespace.

On Darwin, measured bytes are the delta of
`proc_pid_rusage(RUSAGE_INFO_V4).ri_diskio_byteswritten`; on Linux they are the
delta of `/proc/self/io`'s `write_bytes`. The counter interval excludes fixture
construction and includes one stable-storage sync per operation. PFT2 also
records canonical object bytes and bytes passed to its append-log write path as
cross-checks. Neither of those counters substitutes for kernel disk bytes.

Run the exact checked-in measurement with:

```bash
cd vcs/spikes/direct-store-writeamp
go test ./...
go run . \
  -sizes 128,4096,65536,524288 \
  -ops 32 \
  -reps 3 \
  -out /tmp/direct-store-writeamp-results.csv
```

The mixed workload always runs 100 operations: 50 random 4 KiB updates, 20
sequential 4 KiB appends, ten 128-byte creates, ten renames, five chmods, and
five mkdirs. Metadata-only amplification has a zero-byte denominator and is
therefore reported as bytes per operation, not as a finite ratio.

[`results.csv`](./results.csv) contains the raw 2026-08-03 Darwin/APFS run. The
decision and limitations are in [`REPORT.md`](./REPORT.md).
