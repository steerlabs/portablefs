# Measurement findings at protocol 7

Product revision: `5f76079`. Workstream M changed measurement code and evidence
only; no product fix is included.

## Shipping-capacity Git setup

The v6 failure in [baseline.md](baseline.md) occurred while `git add .` prepared
20,000 distinct 1 KiB files in 100 directories on a fresh mount with 65,536 name
and item capacities. Git reported `unable to create temporary file: Transport
endpoint is not connected` at `src-014/file-002841.txt`; the FUSE log subsequently
reported an `ENOTCONN` LOOKUP write failure.

The v7 reproduction completed. `TestShippingCapacityGitAddCompletes` passed in
81.42 seconds in the first invocation and 67.54 seconds in a separate focused
repeat on the same 4 CPU, 8 GiB Docker VM and loop-backed XFS fixture.
Preparation used the shipping capacities from initial attach, with no
4,096-name-cache workaround and no remount before Git setup.

The test calls the unchanged `coherencebench.PrepareGit` workload, including its
1.1-second wait before add, isolated Git configuration, disabled automatic GC
and maintenance, `git add .`, and commit. A descriptor opened on the mount root
before preparation successfully completes the directory durability barrier;
`git ls-files -z` returns exactly 20,000 paths, and ordinary porcelain status
returns no changes. The test fails on any preparation, barrier, count, or status
error. The performance-test gate requires its PASS.

Exact standalone reproduction command:

```sh
PORTABLEFS_PERFORMANCE_TEST=1 \
PORTABLEFS_GO_TEST_FLAGS='-run ^TestShippingCapacityGitAddCompletes$' \
bash scripts/xfs-fuse-integration.sh
```

The standalone test passed in 67.54 seconds. The wrapper exited 70 for omitted
unrelated required tests, as it does for the documented focused baseline command.
Log: `/tmp/cv2-measure-git-add.log`.

Exact command for the first observation:

```sh
PORTABLEFS_PERFORMANCE_TEST=1 \
PORTABLEFS_PROFILE_DIR=/tmp/cv2-measure-profiles \
PORTABLEFS_PROFILE_RUN=run1 \
PORTABLEFS_GO_TEST_FLAGS='-run ^Test(ShippingCapacityGitAddCompletes|CoherenceProfiles)$' \
bash scripts/xfs-fuse-integration.sh
```

Log: `/tmp/cv2-measure-profiles.log`. That combined invocation passed the Git
regression, then exited 1 when the separate profile test could not write its
output executable through the host `/tmp` bind. The profile test had not begun
its workload. Colima's VM does not share that host path. The harness now writes
inside the container and copies artifacts out with `docker cp` after exit.
This artifact-export failure did not affect the mount. The subsequent standalone
profile run passed both workloads and exported all six profiles; its command and
log appear in [profiles.md](profiles.md).

Regression implementation:
`vcs/internal/fusev3/coherence_measurement_linux_test.go`,
`TestShippingCapacityGitAddCompletes`; workload:
`vcs/bench/coherencebench/benchmark.go`, `PrepareGit`. On a future failure the
harness records the exact Git error, mount fatal state, Authority request
counts, and all process goroutines. Mount and Authority share that process.

## Other observations

Both complete baseline runs passed at full size. Their two-mount workloads
reported zero `ESTALE`, incomplete-read, and vanished-read retries; the peer
validated 1,190 and 1,302 files before the respective writer finished.
No product bug reproduced in these measurements.

The old baseline meter counts every new v7 opcode, but its v6 filesystem/control
classifier treats new control opcodes as filesystem requests. [results.md](results.md)
keeps original JSON and total counts and explicitly reclassifies those opcodes
for its filesystem-only comparison. This does not change requests per operation.
