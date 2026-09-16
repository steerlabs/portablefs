# Protocol 7 measurement summary

Product `5f76079` versus v6 `67c52ef`; full-size workloads, unchanged baseline
method, 4 CPU/8 GiB shared Docker VM. Wall times are not isolated comparisons
and should not be treated as speedup ratios. [Results](results.md) include
requests/op, direct XFS, opcode counts, close drains, and both raw records.

| PortableFS workload | v6 seconds | v7 run 1 / run 2 seconds | Request change, run 1 / run 2 |
| --- | ---: | ---: | ---: |
| Install 40,000 files, 1 worker | 386.762771 | 28.615024 / 25.340879 | +998 / +1,862 |
| Install 40,000 files, 8 workers | 273.738199 | 23.448464 / 17.336575 | −41,191 / −42,498 |
| Cold status, 20,000 files | 10.572948 | 1.349883 / 1.332196 | −255 / −271 |
| Warm status, 20,000 files | 2.042038 | 1.045073 / 1.134188 | −183 / −183 |
| Two-mount write/list/read, 2,000 files | 12.536042 | 1.863137 / 2.362157 | +10,571 / +8,797 |

Exact command, executed twice:

```sh
PORTABLEFS_PERFORMANCE_TEST=1 \
PORTABLEFS_GO_TEST_FLAGS='-run ^TestCoherenceBaseline$' \
bash scripts/xfs-fuse-integration.sh
```

Both tests passed (157.08/157.94 s). The wrapper exits 70 because focused
selection omits other required tests; logs: `/tmp/cv2-measure-run{1,2}.log`.

The install's three largest self CPU sites are syscall entry, `time.now`, and
`runtime.futex` on the daemon (31.27%, 3.65%, 2.23%); the Authority ranks syscall
entry, `runtime.futex`, then `time.now` (28.68%, 2.87%, 2.41%). Its three largest
allocation sites are `reflect.unsafe_New`, `signalSourceChangedLocked`, and
`mutationContext` on the daemon (12.80%, 7.09%, 5.62%); the Authority ranks
`canonicalPresentFields`, `CoherenceCoordinator.Poll`, then `reflect.unsafe_New`
(8.41%, 8.15%, 6.50%). Cold status also ranks syscall entry first on both sides
(28.79% daemon, 28.38% Authority). These percentages use each side's filtered
samples, not the whole process or elapsed time. [Profiles](profiles.md) supplies
the complete top-15 CPU/allocation tables for both workloads, source lines,
attribution rules, raw files, and interpretation limits. This is the first
recorded CPU/allocation profile set in the integration record.

Exact profile command:

```sh
PORTABLEFS_PERFORMANCE_TEST=1 \
PORTABLEFS_PROFILE_DIR=/tmp/cv2-measure-profiles \
PORTABLEFS_PROFILE_RUN=run1 \
PORTABLEFS_GO_TEST_FLAGS='-run ^TestCoherenceProfiles$' \
bash scripts/xfs-fuse-integration.sh
```

Profile test PASS: 117.77 s; wrapper exit 70; log:
`/tmp/cv2-measure-profile-run.log`. Profiled times are separate from the table.

The original shipping-capacity Git-add scenario completed with 65,536 name and
item capacities from initial attach: 20,000 tracked files, a successful
mount-root durability barrier, and clean status. It did not reproduce v6's
`ENOTCONN`. [Findings](measure-findings.md) records the regression and diagnostic
history. No product bug reproduced; no product code changed.

Exact standalone regression command:

```sh
PORTABLEFS_PERFORMANCE_TEST=1 \
PORTABLEFS_GO_TEST_FLAGS='-run ^TestShippingCapacityGitAddCompletes$' \
bash scripts/xfs-fuse-integration.sh
```

Regression PASS: 67.54 s (also passed in 81.42 s in the earlier combined run);
wrapper exit 70. Log: `/tmp/cv2-measure-git-add.log`.

Validation: `bash scripts/verify-local.sh` passed in default mode, including
native Go/race, Darwin and Linux builds/vet, Swift, and policy checks. The full
privileged suite and coherence matrix were not rerun by this measurement change.
