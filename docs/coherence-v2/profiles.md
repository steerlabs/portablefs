# Coherence v2 profiles

Product revision: `5f76079`. This is the first workload CPU and allocation profile in the integration record; `integration.md` contains no earlier hot-spot ranking.

## Method

The fixture runs the Linux FUSE frontend, loopback TLS transport, and in-process Authority in one `go test` process. Each raw profile is therefore a combined-process observation. The tables attribute a sample to the mount daemon or Authority when its stack matches the filters below. Percentages in each hot-spot table use `-relative_percentages`, so their denominator is the focused side rather than the whole process. Runtime work descended from a matched stack is charged to that side; runtime-only and other stacks that match neither filter remain unattributed. These are stack-filter shares, not exclusive process measurements. Intersection was measured by filtering the Authority profile protobuf through the daemon filter, and the residual uses `100 - daemon - Authority + intersection`.

The install profile covers the full 40,000-file, 2,000-directory, one-worker workload. The cold Git profile prepares and commits 20,000 files with the 4,096-name setup profile, recreates the complete Authority and mount at the shipping 65,536 name and item capacities, then runs the first clean `git status --porcelain=v1`. CPU capture remains active through asynchronous delegation application, release, and final Authority CLOSE drain. Allocation-space (`alloc_space`) results are sampled allocated bytes at Go's default 512 KiB memory-profile rate, not retained heap. They subtract a snapshot taken after two forced GCs immediately before the workload from another taken after two forced GCs following the CLOSE drain. The signed deltas contained no negative line samples, so no negative values were suppressed. Profiled wall times are not performance results.

CPU sampling uses 10 ms samples. The short cold-status window produced approximately 66 daemon and 74 Authority samples; its ranks are correspondingly coarse, and equal percentages are sampling ties.

The exact capture command was:

```sh
PORTABLEFS_PERFORMANCE_TEST=1 \
PORTABLEFS_PROFILE_DIR=/tmp/cv2-measure-profiles \
PORTABLEFS_PROFILE_RUN=run1 \
PORTABLEFS_GO_TEST_FLAGS='-run ^TestCoherenceProfiles$' \
bash scripts/xfs-fuse-integration.sh
```

`TestCoherenceProfiles` passed in 117.77 seconds; the focused wrapper then exited 70 because unrelated required tests were excluded by `-run`. The complete log is `/tmp/cv2-measure-profile-run.log`.

Authority focus: `authorityrpc\.\(\*Server\)|authorityrpc\.\(\*VolumeHandler\)|internal/volumeserver\.|internal/xfsstore\.`.

Mount-daemon focus: `fusev3\.\(\*|authorityrpc\.\(\*Client\)|go-fuse/v2/fuse\.|internal/writeback\.` with `-ignore=countingHandler|integrationFixture` so fixture-side Authority dispatch frames are not charged to the daemon.

Tables rank source lines by self cost (`-lines -top`). Repeated functions at different source lines are intentional; cumulative percentages are reported for the same line-level nodes.

Source paths under `internal/authorityrpc`, `internal/fusev3`, `internal/volumeserver`, `internal/writeback`, and `internal/xfsstore` are relative to `vcs/`; `third_party` paths are also relative to `vcs/`. Standard-library paths, including `runtime`, `internal/runtime`, `internal/sync`, `internal/chacha8rand`, `context`, and `time`, refer to the Go 1.26.6 source tree. Versioned module paths refer to the Go module cache.

## Focused share of the combined process

| Workload | Metric | Mount daemon | Authority | Filter intersection | Unattributed by filters |
| --- | --- | ---: | ---: | ---: | ---: |
| Install, 1 worker | CPU | 36.69% | 40.26% | 0.00% | 23.05% |
| Install, 1 worker | Allocation space delta | 43.55% | 55.90% | 0.00% | 0.55% |
| Cold Git status | CPU | 42.86% | 48.05% | 0.00% | 9.09% |
| Cold Git status | Allocation space delta | 50.74% | 48.25% | 0.00% | 1.01% |

## Ranked hot spots

### Install, 1 worker: Mount daemon, CPU

| Rank | Hot spot | File:line | Self | Cumulative | Why it is hot |
| ---: | --- | --- | ---: | ---: | --- |
| 1 | `internal/runtime/syscall/linux.Syscall6` | `internal/runtime/syscall/linux/asm_linux_arm64.s:17` | 31.27% | 31.27% | It enters the kernel for FUSE-device and loopback-RPC I/O on daemon stacks. |
| 2 | `time.now` | `runtime/timestub.go:27` | 3.65% | 3.65% | It reads clocks for request deadlines and coherence horizons. |
| 3 | `runtime.futex` | `runtime/sys_linux_arm64.s:666` | 2.23% | 2.23% | It executes synchronization and lock operations protecting concurrent request and coherence state. |
| 4 | `runtime.nanotime` | `runtime/time_nofake.go:33` | 2.03% | 2.03% | It reads clocks for request deadlines and coherence horizons. |
| 5 | `runtime.(*mspan).writeHeapBitsSmall` | `runtime/mbitmap.go:661` | 1.22% | 1.22% | It updates garbage-collector metadata for small heap allocations on the focused path. |
| 6 | `internal/runtime/maps.probeSeq.next` | `internal/runtime/maps/table.go:1290` | 1.02% | 1.02% | It probes Go hash tables used by request and coherence state. |
| 7 | `github.com/steerlabs/portablefs/vcs/internal/authorityrpc.wireTypeForKind` | `internal/authorityrpc/wire_validate.go:165` | 0.91% | 0.91% | It validates protobuf shape and wire types before decoding an RPC frame. |
| 8 | `internal/runtime/syscall/linux.Syscall6` | `internal/runtime/syscall/linux/asm_linux_arm64.s:16` | 0.91% | 0.91% | It enters the kernel for FUSE-device and loopback-RPC I/O on daemon stacks. |
| 9 | `github.com/steerlabs/portablefs/vcs/internal/authorityrpc.wireTypeForKind` | `internal/authorityrpc/wire_validate.go:171` | 0.61% | 0.61% | It validates protobuf shape and wire types before decoding an RPC frame. |
| 10 | `google.golang.org/protobuf/internal/impl.sizeBytesNoZero` | `google.golang.org/protobuf@v1.36.12/internal/impl/codec_gen.go:5468` | 0.51% | 0.51% | It encodes or decodes protocol-buffer request and reply frames. |
| 11 | `runtime.mallocgc` | `runtime/malloc.go:1189` | 0.51% | 0.51% | It allocates objects or grows buffers retained by this side's request path. |
| 12 | `google.golang.org/protobuf/internal/filedesc.(*Field).IsList` | `google.golang.org/protobuf@v1.36.12/internal/filedesc/desc.go:391` | 0.41% | 0.41% | It encodes or decodes protocol-buffer request and reply frames. |
| 13 | `internal/chacha8rand.(*State).Next` | `internal/chacha8rand/chacha8.go:55` | 0.41% | 0.41% | It advances the Go runtime's random state for hash-table seeding and scheduling. |
| 14 | `internal/sync.(*Mutex).Lock` | `internal/sync/mutex.go:63` | 0.41% | 0.41% | It executes synchronization and lock operations protecting concurrent request and coherence state. |
| 15 | `runtime.mallocgcSmallScanNoHeader` | `runtime/malloc.go:1581` | 0.41% | 0.61% | It allocates objects or grows buffers retained by this side's request path. |

### Install, 1 worker: Authority, CPU

| Rank | Hot spot | File:line | Self | Cumulative | Why it is hot |
| ---: | --- | --- | ---: | ---: | --- |
| 1 | `internal/runtime/syscall/linux.Syscall6` | `internal/runtime/syscall/linux/asm_linux_arm64.s:17` | 28.68% | 28.68% | It enters the kernel for loopback-RPC and descriptor-relative XFS I/O on Authority stacks. |
| 2 | `runtime.futex` | `runtime/sys_linux_arm64.s:666` | 2.87% | 2.87% | It executes synchronization and lock operations protecting concurrent request and coherence state. |
| 3 | `time.now` | `runtime/timestub.go:27` | 2.41% | 2.41% | It reads clocks for request deadlines and coherence horizons. |
| 4 | `runtime.nanotime` | `runtime/time_nofake.go:33` | 1.57% | 1.57% | It reads clocks for request deadlines and coherence horizons. |
| 5 | `runtime.pcvalue` | `runtime/symtab.go:1047` | 0.93% | 0.93% | It performs Go runtime stack walking and program-counter metadata lookup. |
| 6 | `runtime.step` | `runtime/symtab.go:1285` | 0.93% | 0.93% | It performs Go runtime stack walking and program-counter metadata lookup. |
| 7 | `runtime.step` | `runtime/symtab.go:1301` | 0.93% | 0.93% | It performs Go runtime stack walking and program-counter metadata lookup. |
| 8 | `google.golang.org/protobuf/internal/impl.pointer.AsValueOf` | `google.golang.org/protobuf@v1.36.12/internal/impl/pointer_unsafe.go:76` | 0.74% | 0.74% | It encodes or decodes protocol-buffer request and reply frames. |
| 9 | `runtime.(*moduledata).textAddr` | `runtime/symtab.go:699` | 0.74% | 0.74% | It performs Go runtime stack walking and program-counter metadata lookup. |
| 10 | `runtime.readvarint` | `runtime/symtab.go:1313` | 0.74% | 0.74% | It performs Go runtime stack walking and program-counter metadata lookup. |
| 11 | `github.com/steerlabs/portablefs/vcs/internal/authorityrpc.wireTypeForKind` | `internal/authorityrpc/wire_validate.go:165` | 0.65% | 0.65% | It validates protobuf shape and wire types before decoding an RPC frame. |
| 12 | `google.golang.org/protobuf/internal/impl.(*MessageInfo).sizePointerSlow` | `google.golang.org/protobuf@v1.36.12/internal/impl/encode.go:85` | 0.65% | 0.65% | It encodes or decodes protocol-buffer request and reply frames. |
| 13 | `runtime.step` | `runtime/symtab.go:1297` | 0.65% | 0.65% | It performs Go runtime stack walking and program-counter metadata lookup. |
| 14 | `runtime.step` | `runtime/symtab.go:1306` | 0.65% | 0.65% | It performs Go runtime stack walking and program-counter metadata lookup. |
| 15 | `internal/runtime/syscall/linux.Syscall6` | `internal/runtime/syscall/linux/asm_linux_arm64.s:16` | 0.56% | 0.56% | It enters the kernel for loopback-RPC and descriptor-relative XFS I/O on Authority stacks. |

### Install, 1 worker: Mount daemon, Allocation space delta

| Rank | Hot spot | File:line | Self | Cumulative | Why it is hot |
| ---: | --- | --- | ---: | ---: | --- |
| 1 | `reflect.unsafe_New` | `runtime/malloc.go:2178` | 12.80% | 12.80% | It allocates values requested through protocol-buffer reflection. |
| 2 | `github.com/steerlabs/portablefs/vcs/internal/fusev3.(*rawFileSystem).signalSourceChangedLocked` | `internal/fusev3/source_publication_linux.go:256` | 7.09% | 7.09% | It closes the old source-publication wake channel and allocates its replacement. |
| 3 | `github.com/steerlabs/portablefs/vcs/internal/fusev3.(*rawFileSystem).mutationContext` | `internal/fusev3/coherence_linux.go:207` | 5.62% | 5.62% | It creates the lifecycle context that tracks one kernel mutation through reply publication. |
| 4 | `github.com/steerlabs/portablefs/vcs/internal/authorityrpc.(*Client).readLoop` | `internal/authorityrpc/client.go:1928` | 3.53% | 3.53% | It receives and decodes Authority replies for the mount client. |
| 5 | `context.(*cancelCtx).propagateCancel` | `context/context.go:501` | 3.04% | 3.04% | It creates or links cancellation state for bounded RPC and FUSE operations. |
| 6 | `time.newTimer` | `runtime/time.go:390` | 2.72% | 2.72% | It allocates timers for request, polling, and repair deadlines. |
| 7 | `context.WithDeadlineCause` | `context/context.go:640` | 2.67% | 2.67% | It creates or links cancellation state for bounded RPC and FUSE operations. |
| 8 | `github.com/steerlabs/portablefs/vcs/internal/fusev3.(*rawFileSystem).reserveCacheCandidateLocked` | `internal/fusev3/raw_linux.go:697` | 2.62% | 2.62% | It records a candidate name-cache entry while enforcing the mount's capacity. |
| 9 | `github.com/steerlabs/portablefs/vcs/internal/fusev3.(*rawFileSystem).acquireSourcePublication` | `internal/fusev3/source_publication_linux.go:357` | 2.45% | 2.45% | It allocates the coordinate map used to acquire source-publication ownership. |
| 10 | `github.com/steerlabs/portablefs/vcs/internal/fusev3.(*rawFileSystem).registerReplyPublication` | `internal/fusev3/raw_linux.go:1462` | 2.33% | 2.33% | It records the cache coordinates that must settle before the FUSE reply is published. |
| 11 | `github.com/steerlabs/portablefs/vcs/internal/authorityrpc.(*Client).dispatchOwnedFrame` | `internal/authorityrpc/client.go:1518` | 2.23% | 2.23% | It routes an owned reply frame to the waiting mount request. |
| 12 | `github.com/steerlabs/portablefs/vcs/internal/authorityrpc.cloneProof` | `internal/authorityrpc/client.go:2053` | 2.18% | 2.18% | It copies the session proof attached to a mount RPC. |
| 13 | `github.com/steerlabs/portablefs/vcs/internal/fusev3.coordinatesForSourceGate` | `internal/fusev3/source_publication_linux.go:238` | 1.96% | 1.96% | It builds the publication-coordinate set guarded by a local mutation reply. |
| 14 | `github.com/steerlabs/portablefs/vcs/internal/writeback.(*Buffer).admit` | `internal/writeback/buffer.go:171` | 1.89% | 1.89% | It records a delegated mutation in the bounded writeback buffer. |
| 15 | `github.com/steerlabs/portablefs/vcs/internal/authorityrpc.writeFrame` | `internal/authorityrpc/frame.go:283` | 1.89% | 1.89% | It writes request frames, replies, or workload data on the focused path. |

### Install, 1 worker: Authority, Allocation space delta

| Rank | Hot spot | File:line | Self | Cumulative | Why it is hot |
| ---: | --- | --- | ---: | ---: | --- |
| 1 | `github.com/steerlabs/portablefs/vcs/internal/authorityrpc.canonicalPresentFields` | `internal/authorityrpc/protocol.go:592` | 8.41% | 8.41% | It builds the canonical present-field set used to validate each protocol message. |
| 2 | `github.com/steerlabs/portablefs/vcs/internal/volumeserver.(*CoherenceCoordinator).Poll` | `internal/volumeserver/subscription.go:413` | 8.15% | 8.15% | It materializes subscription changes returned by the Authority's control poll. |
| 3 | `reflect.unsafe_New` | `runtime/malloc.go:2178` | 6.50% | 6.50% | It allocates values requested through protocol-buffer reflection. |
| 4 | `time.NewTimer` | `time/sleep.go:144` | 3.92% | 3.92% | It allocates timers for request, polling, and repair deadlines. |
| 5 | `time.newTimer` | `runtime/time.go:390` | 3.32% | 3.32% | It allocates timers for request, polling, and repair deadlines. |
| 6 | `github.com/steerlabs/portablefs/vcs/internal/authorityrpc.acquireFramePayload` | `internal/authorityrpc/frame.go:116` | 3.29% | 3.29% | It acquires the bounded byte buffer that receives an RPC frame. |
| 7 | `github.com/steerlabs/portablefs/vcs/internal/authorityrpc.(*operationResolutionContext).open` | `internal/authorityrpc/operation_resolution_linux.go:87` | 3.17% | 3.17% | It records descriptor-relative namespace and item resolution for one Authority operation. |
| 8 | `github.com/steerlabs/portablefs/vcs/internal/authorityrpc.(*VolumeHandler).handleCoherencePoll` | `internal/authorityrpc/coherence_control_linux.go:507` | 3.14% | 3.14% | It constructs the reply for a protocol-7 subscription poll. |
| 9 | `github.com/steerlabs/portablefs/vcs/internal/authorityrpc.(*VolumeHandler).success` | `internal/authorityrpc/volume_handler_linux.go:3393` | 2.45% | 2.64% | It builds the successful Authority reply and attaches coherence metadata. |
| 10 | `github.com/steerlabs/portablefs/vcs/internal/authorityrpc.(*operationResolutionContext).namespace` | `internal/authorityrpc/operation_resolution_linux.go:106` | 2.22% | 2.22% | It records descriptor-relative namespace and item resolution for one Authority operation. |
| 11 | `github.com/steerlabs/portablefs/vcs/internal/authorityrpc.(*operationResolutionContext).item` | `internal/authorityrpc/operation_resolution_linux.go:66` | 2.20% | 2.20% | It records descriptor-relative namespace and item resolution for one Authority operation. |
| 12 | `github.com/steerlabs/portablefs/vcs/internal/volumeserver.cloneOutcome` | `internal/volumeserver/session.go:1374` | 1.97% | 1.97% | It copies a retained Authority outcome for replay-safe delivery. |
| 13 | `github.com/steerlabs/portablefs/vcs/internal/authorityrpc.(*Server).serveSession` | `internal/authorityrpc/server.go:436` | 1.83% | 1.83% | It allocates per-request server dispatch state for the authenticated RPC session. |
| 14 | `github.com/steerlabs/portablefs/vcs/internal/authorityrpc.coherenceChanges` | `internal/authorityrpc/coherence_mutation_linux.go:404` | 1.62% | 1.62% | It constructs the committed change set emitted by an Authority mutation. |
| 15 | `github.com/steerlabs/portablefs/vcs/internal/authorityrpc.(*VolumeHandler).mutateOperation` | `internal/authorityrpc/volume_handler_linux.go:3047` | 1.62% | 1.62% | It allocates the operation context used for Authority mutation admission and commit. |

### Cold Git status: Mount daemon, CPU

| Rank | Hot spot | File:line | Self | Cumulative | Why it is hot |
| ---: | --- | --- | ---: | ---: | --- |
| 1 | `internal/runtime/syscall/linux.Syscall6` | `internal/runtime/syscall/linux/asm_linux_arm64.s:17` | 28.79% | 28.79% | It enters the kernel for FUSE-device and loopback-RPC I/O on daemon stacks. |
| 2 | `internal/sync.(*Mutex).Lock` | `internal/sync/mutex.go:63` | 4.55% | 4.55% | It executes synchronization and lock operations protecting concurrent request and coherence state. |
| 3 | `runtime.nanotime` | `runtime/time_nofake.go:33` | 4.55% | 4.55% | It reads clocks for request deadlines and coherence horizons. |
| 4 | `time.now` | `runtime/timestub.go:27` | 4.55% | 4.55% | It reads clocks for request deadlines and coherence horizons. |
| 5 | `aeshashbody` | `runtime/asm_arm64.s:783` | 1.52% | 1.52% | It hashes Go map keys used by request and coherence state. |
| 6 | `context.parentCancelCtx` | `context/context.go:387` | 1.52% | 1.52% | It creates or links cancellation state for bounded RPC and FUSE operations. |
| 7 | `github.com/steerlabs/portablefs/vcs/internal/authorityrpc.(*Client).CallMutationWithIdentityRetained` | `internal/authorityrpc/client.go:1892` | 1.52% | 1.52% | It sends a mutating RPC while retaining its request identity through reply publication. |
| 8 | `github.com/steerlabs/portablefs/vcs/internal/authorityrpc.(*Client).transportIsLive` | `internal/authorityrpc/client_transport.go:563` | 1.52% | 1.52% | It checks the mount client's transport generation before admitting an RPC. |
| 9 | `github.com/steerlabs/portablefs/vcs/internal/authorityrpc.(*Client).writeRequest` | `internal/authorityrpc/client.go:1639` | 1.52% | 3.03% | It writes request frames, replies, or workload data on the focused path. |
| 10 | `github.com/steerlabs/portablefs/vcs/internal/authorityrpc.validateWireMessageDepth` | `internal/authorityrpc/wire_validate.go:51` | 1.52% | 1.52% | It validates protobuf shape and wire types before decoding an RPC frame. |
| 11 | `github.com/steerlabs/portablefs/vcs/internal/authorityrpc.validateWireMessageDepth` | `internal/authorityrpc/wire_validate.go:90` | 1.52% | 6.06% | It validates protobuf shape and wire types before decoding an RPC frame. |
| 12 | `github.com/steerlabs/portablefs/vcs/internal/authorityrpc.wireTypeForKind` | `internal/authorityrpc/wire_validate.go:171` | 1.52% | 1.52% | It validates protobuf shape and wire types before decoding an RPC frame. |
| 13 | `github.com/steerlabs/portablefs/vcs/internal/fusev3.(*rawFileSystem).PrepareReplyPayload` | `internal/fusev3/raw_linux.go:1537` | 1.52% | 4.55% | It serializes the FUSE reply after its cache-publication conditions are satisfied. |
| 14 | `github.com/steerlabs/portablefs/vcs/internal/fusev3.(*rawFileSystem).release` | `internal/fusev3/raw_linux.go:1900` | 1.52% | 1.52% | It drains file handles and any associated delegation state after the workload closes them. |
| 15 | `github.com/steerlabs/portablefs/vcs/internal/fusev3.(*subscriptionRegistry).stamp` | `internal/fusev3/subscription_linux.go:230` | 1.52% | 1.52% | It reads the current subscription coordinate attached to a cached entry. |

### Cold Git status: Authority, CPU

| Rank | Hot spot | File:line | Self | Cumulative | Why it is hot |
| ---: | --- | --- | ---: | ---: | --- |
| 1 | `internal/runtime/syscall/linux.Syscall6` | `internal/runtime/syscall/linux/asm_linux_arm64.s:17` | 28.38% | 28.38% | It enters the kernel for loopback-RPC and descriptor-relative XFS I/O on Authority stacks. |
| 2 | `google.golang.org/protobuf/internal/impl.(*MessageInfo).checkField` | `google.golang.org/protobuf@v1.36.12/internal/impl/message_reflect.go:430` | 2.70% | 2.70% | It encodes or decodes protocol-buffer request and reply frames. |
| 3 | `google.golang.org/protobuf/internal/impl.(*MessageInfo).sizePointerSlow` | `google.golang.org/protobuf@v1.36.12/internal/impl/encode.go:85` | 2.70% | 2.70% | It encodes or decodes protocol-buffer request and reply frames. |
| 4 | `internal/runtime/maps.probeSeq.next` | `internal/runtime/maps/table.go:1290` | 2.70% | 2.70% | It probes Go hash tables used by request and coherence state. |
| 5 | `runtime.step` | `runtime/symtab.go:1297` | 2.70% | 2.70% | It performs Go runtime stack walking and program-counter metadata lookup. |
| 6 | `syscall.RawSyscall6` | `syscall/syscall_linux.go:67` | 2.70% | 2.70% | It enters the kernel for loopback-RPC and descriptor-relative XFS I/O on Authority stacks. |
| 7 | `time.now` | `runtime/timestub.go:27` | 2.70% | 2.70% | It reads clocks for request deadlines and coherence horizons. |
| 8 | `aeshashbody` | `runtime/asm_arm64.s:769` | 1.35% | 1.35% | It hashes Go map keys used by request and coherence state. |
| 9 | `cmpbody` | `internal/bytealg/compare_arm64.s:117` | 1.35% | 1.35% | It compares byte strings used as protocol identities, names, or tokens. |
| 10 | `crypto/internal/fips140/aes/gcm.gcmAesData` | `crypto/internal/fips140/aes/gcm/gcm_arm64.s:253` | 1.35% | 1.35% | It encrypts or authenticates loopback TLS records for Authority RPC traffic. |
| 11 | `crypto/internal/sysrand.read` | `crypto/internal/sysrand/rand_getrandom.go:52` | 1.35% | 1.35% | It obtains cryptographic randomness used by the TLS connection. |
| 12 | `crypto/tls.(*Conn).write` | `crypto/tls/conn.go:948` | 1.35% | 1.35% | It encrypts or authenticates loopback TLS records for Authority RPC traffic. |
| 13 | `crypto/tls.(*halfConn).explicitNonceLen` | `crypto/tls/conn.go:256` | 1.35% | 1.35% | It encrypts or authenticates loopback TLS records for Authority RPC traffic. |
| 14 | `github.com/steerlabs/portablefs/vcs/internal/authorityrpc.(*frameSocket).Write` | `internal/authorityrpc/tls_conn.go:35` | 1.35% | 1.35% | It writes request frames, replies, or workload data on the focused path. |
| 15 | `github.com/steerlabs/portablefs/vcs/internal/volumeserver.(*CoherenceCoordinator).DataConsumed` | `internal/volumeserver/delegation.go:457` | 1.35% | 1.35% | It grants, applies, recalls, or releases protocol-7 delegated state. |

### Cold Git status: Mount daemon, Allocation space delta

| Rank | Hot spot | File:line | Self | Cumulative | Why it is hot |
| ---: | --- | --- | ---: | ---: | --- |
| 1 | `reflect.unsafe_New` | `runtime/malloc.go:2178` | 14.82% | 14.82% | It allocates values requested through protocol-buffer reflection. |
| 2 | `github.com/steerlabs/portablefs/vcs/internal/fusev3.(*rawFileSystem).signalSourceChangedLocked` | `internal/fusev3/source_publication_linux.go:256` | 6.19% | 6.19% | It closes the old source-publication wake channel and allocates its replacement. |
| 3 | `github.com/steerlabs/portablefs/vcs/internal/fusev3.(*rawFileSystem).mutationContext` | `internal/fusev3/coherence_linux.go:207` | 5.31% | 5.31% | It creates the lifecycle context that tracks one kernel mutation through reply publication. |
| 4 | `context.(*cancelCtx).propagateCancel` | `context/context.go:501` | 4.42% | 4.42% | It creates or links cancellation state for bounded RPC and FUSE operations. |
| 5 | `github.com/hanwen/go-fuse/v2/fuse.NewServer.func2` | `third_party/go-fuse/fuse/server.go:262` | 4.11% | 4.11% | It allocates go-fuse request buffers used to receive kernel operations. |
| 6 | `github.com/steerlabs/portablefs/vcs/internal/fusev3.(*rawFileSystem).reserveCacheCandidateLocked` | `internal/fusev3/raw_linux.go:697` | 3.76% | 3.76% | It records a candidate name-cache entry while enforcing the mount's capacity. |
| 7 | `github.com/steerlabs/portablefs/vcs/internal/fusev3.(*node).Lookup` | `internal/fusev3/fuse_linux.go:1424` | 3.32% | 18.36% | It resolves a pathname component and publishes or consumes its cache state. |
| 8 | `github.com/steerlabs/portablefs/vcs/internal/fusev3.(*rawFileSystem).settleReplyPublicationLocked` | `internal/fusev3/raw_linux.go:1437` | 2.87% | 2.87% | It removes publication coordinates after the kernel reply becomes safe to expose. |
| 9 | `github.com/steerlabs/portablefs/vcs/internal/fusev3.(*rawFileSystem).bindCachedNameLocked` | `internal/fusev3/raw_linux.go:654` | 2.82% | 2.82% | It allocates and installs the mount's positive name-cache binding. |
| 10 | `github.com/steerlabs/portablefs/vcs/internal/authorityrpc.(*Client).readLoop` | `internal/authorityrpc/client.go:1928` | 2.65% | 2.65% | It receives and decodes Authority replies for the mount client. |
| 11 | `context.withCancel` | `context/context.go:277` | 2.65% | 2.65% | It creates or links cancellation state for bounded RPC and FUSE operations. |
| 12 | `github.com/steerlabs/portablefs/vcs/internal/fusev3.(*rawFileSystem).bindCachedNameLocked` | `internal/fusev3/raw_linux.go:656` | 2.43% | 2.43% | It allocates and installs the mount's positive name-cache binding. |
| 13 | `github.com/steerlabs/portablefs/vcs/internal/fusev3.(*rawFileSystem).publishEntry` | `internal/fusev3/raw_linux.go:1071` | 2.43% | 2.43% | It constructs the FUSE entry and associates it with subscription state. |
| 14 | `github.com/steerlabs/portablefs/vcs/internal/fusev3.(*rawFileSystem).publishEntry` | `internal/fusev3/raw_linux.go:1080` | 2.21% | 2.21% | It constructs the FUSE entry and associates it with subscription state. |
| 15 | `context.(*cancelCtx).Done` | `context/context.go:457` | 1.99% | 1.99% | It creates or links cancellation state for bounded RPC and FUSE operations. |

### Cold Git status: Authority, Allocation space delta

| Rank | Hot spot | File:line | Self | Cumulative | Why it is hot |
| ---: | --- | --- | ---: | ---: | --- |
| 1 | `github.com/steerlabs/portablefs/vcs/internal/authorityrpc.canonicalPresentFields` | `internal/authorityrpc/protocol.go:592` | 10.47% | 10.47% | It builds the canonical present-field set used to validate each protocol message. |
| 2 | `reflect.unsafe_New` | `runtime/malloc.go:2178` | 7.67% | 7.67% | It allocates values requested through protocol-buffer reflection. |
| 3 | `github.com/steerlabs/portablefs/vcs/internal/volumeserver.(*mutationSequencer).enqueueFor` | `internal/volumeserver/mutation_sequencer.go:286` | 5.35% | 5.35% | It allocates dependency state used to order an Authority operation. |
| 4 | `github.com/steerlabs/portablefs/vcs/internal/volumeserver.cloneOutcome` | `internal/volumeserver/session.go:1374` | 4.23% | 4.23% | It copies a retained Authority outcome for replay-safe delivery. |
| 5 | `github.com/steerlabs/portablefs/vcs/internal/authorityrpc.(*VolumeHandler).coherenceDirectoryDependencies` | `internal/authorityrpc/coherence_reads_linux.go:422` | 4.21% | 4.21% | It builds the directory and item dependency set for an Authority read. |
| 6 | `github.com/steerlabs/portablefs/vcs/internal/volumeserver.newMutationDependencies` | `internal/volumeserver/mutation_sequencer.go:39` | 3.72% | 3.72% | It allocates dependency state used to order an Authority operation. |
| 7 | `time.NewTimer` | `time/sleep.go:144` | 3.02% | 3.02% | It allocates timers for request, polling, and repair deadlines. |
| 8 | `github.com/steerlabs/portablefs/vcs/internal/volumeserver.(*mutationSequencer).enqueueFor` | `internal/volumeserver/mutation_sequencer.go:284` | 3.02% | 3.02% | It allocates dependency state used to order an Authority operation. |
| 9 | `github.com/steerlabs/portablefs/vcs/internal/authorityrpc.writeFrame` | `internal/authorityrpc/frame.go:283` | 2.81% | 2.81% | It writes request frames, replies, or workload data on the focused path. |
| 10 | `github.com/steerlabs/portablefs/vcs/internal/authorityrpc.(*VolumeHandler).mutateOperation` | `internal/authorityrpc/volume_handler_linux.go:3047` | 2.79% | 2.79% | It allocates the operation context used for Authority mutation admission and commit. |
| 11 | `time.newTimer` | `runtime/time.go:390` | 2.79% | 2.79% | It allocates timers for request, polling, and repair deadlines. |
| 12 | `github.com/steerlabs/portablefs/vcs/internal/volumeserver.(*Authority).begin` | `internal/volumeserver/session.go:1105` | 2.79% | 2.79% | It performs Authority admission, ordering, or coherence bookkeeping. |
| 13 | `github.com/minio/highwayhash.NewDigest` | `github.com/minio/highwayhash@v1.0.4/highwayhash.go:59` | 2.56% | 2.56% | It computes protocol, identity, or payload hashes used by the focused path. |
| 14 | `github.com/steerlabs/portablefs/vcs/internal/authorityrpc.(*VolumeHandler).coherenceReadDir.func1` | `internal/authorityrpc/coherence_reads_linux.go:384` | 2.42% | 2.42% | It enumerates directory entries and carries their continuation and attributes. |
| 15 | `github.com/steerlabs/portablefs/vcs/internal/xfsstore.(*Volume).installObject` | `internal/xfsstore/volume_linux.go:675` | 2.26% | 2.26% | It translates the Authority operation into descriptor-relative XFS storage work. |

## Raw artifacts

Raw profiles smaller than 2 MiB are retained in the repository. The exact test executable is larger and remains under `/tmp`; its digest identifies the binary used for symbolization.

| Artifact | Bytes | SHA-256 | Preserved location |
| --- | ---: | --- | --- |
| `run1.git-status-cold.allocs.after.pprof` | 73670 | `e6d76e4e82b1bf29ff5b722a6b388dde1cd4631d7410bc92415b0448dc2d1c80` | `vcs/bench/coherencebench/testdata/profiles/run1.git-status-cold.allocs.after.pprof` |
| `run1.git-status-cold.allocs.before.pprof` | 72950 | `2457c6218731d01fb274269cb1be5c3320cb726c93c5cc0b368d0d6c5f06e0f2` | `vcs/bench/coherencebench/testdata/profiles/run1.git-status-cold.allocs.before.pprof` |
| `run1.git-status-cold.cpu.pprof` | 21196 | `c7f6bb2effb87f3d3d3351a3a4e1e7c5227f03558f09b0623910efb3092e12d0` | `vcs/bench/coherencebench/testdata/profiles/run1.git-status-cold.cpu.pprof` |
| `run1.install-1.allocs.after.pprof` | 45982 | `20bdf15f90228acbcc7662fb5cf1694d390f9345194a3cf096d54d3946920585` | `vcs/bench/coherencebench/testdata/profiles/run1.install-1.allocs.after.pprof` |
| `run1.install-1.allocs.before.pprof` | 3887 | `3cad9f342864f816c6beb15ceb68059b900b9d43ecb8b645a650ebd37b529080` | `vcs/bench/coherencebench/testdata/profiles/run1.install-1.allocs.before.pprof` |
| `run1.install-1.cpu.pprof` | 86431 | `9b40bf80eb366625f85ad6c13c44dd7991f5c7125538afff09eb1b75632163f1` | `vcs/bench/coherencebench/testdata/profiles/run1.install-1.cpu.pprof` |
| `run1.fusev3.test` | 12910857 | `75e13d2557d9a7ca0e521da0b1a82cc7f6ebb1fa5fdddf9329a664962b451db1` | `/tmp/cv2-measure-profiles/run1.fusev3.test` |

## Analysis commands

Each table was generated with the corresponding command below:

```sh
go tool pprof -top -lines -nodecount=15 -nodefraction=0 '-focus=fusev3\.\(\*|authorityrpc\.\(\*Client\)|go-fuse/v2/fuse\.|internal/writeback\.' -relative_percentages '-ignore=countingHandler|integrationFixture' /tmp/cv2-measure-profiles/run1.fusev3.test /tmp/cv2-measure-profiles/run1.install-1.cpu.pprof
go tool pprof -top -lines -nodecount=15 -nodefraction=0 '-focus=authorityrpc\.\(\*Server\)|authorityrpc\.\(\*VolumeHandler\)|internal/volumeserver\.|internal/xfsstore\.' -relative_percentages /tmp/cv2-measure-profiles/run1.fusev3.test /tmp/cv2-measure-profiles/run1.install-1.cpu.pprof
go tool pprof -top -lines -nodecount=15 -nodefraction=0 '-focus=fusev3\.\(\*|authorityrpc\.\(\*Client\)|go-fuse/v2/fuse\.|internal/writeback\.' -relative_percentages '-ignore=countingHandler|integrationFixture' -sample_index=alloc_space -base=/tmp/cv2-measure-profiles/run1.install-1.allocs.before.pprof /tmp/cv2-measure-profiles/run1.fusev3.test /tmp/cv2-measure-profiles/run1.install-1.allocs.after.pprof
go tool pprof -top -lines -nodecount=15 -nodefraction=0 '-focus=authorityrpc\.\(\*Server\)|authorityrpc\.\(\*VolumeHandler\)|internal/volumeserver\.|internal/xfsstore\.' -relative_percentages -sample_index=alloc_space -base=/tmp/cv2-measure-profiles/run1.install-1.allocs.before.pprof /tmp/cv2-measure-profiles/run1.fusev3.test /tmp/cv2-measure-profiles/run1.install-1.allocs.after.pprof
go tool pprof -top -lines -nodecount=15 -nodefraction=0 '-focus=fusev3\.\(\*|authorityrpc\.\(\*Client\)|go-fuse/v2/fuse\.|internal/writeback\.' -relative_percentages '-ignore=countingHandler|integrationFixture' /tmp/cv2-measure-profiles/run1.fusev3.test /tmp/cv2-measure-profiles/run1.git-status-cold.cpu.pprof
go tool pprof -top -lines -nodecount=15 -nodefraction=0 '-focus=authorityrpc\.\(\*Server\)|authorityrpc\.\(\*VolumeHandler\)|internal/volumeserver\.|internal/xfsstore\.' -relative_percentages /tmp/cv2-measure-profiles/run1.fusev3.test /tmp/cv2-measure-profiles/run1.git-status-cold.cpu.pprof
go tool pprof -top -lines -nodecount=15 -nodefraction=0 '-focus=fusev3\.\(\*|authorityrpc\.\(\*Client\)|go-fuse/v2/fuse\.|internal/writeback\.' -relative_percentages '-ignore=countingHandler|integrationFixture' -sample_index=alloc_space -base=/tmp/cv2-measure-profiles/run1.git-status-cold.allocs.before.pprof /tmp/cv2-measure-profiles/run1.fusev3.test /tmp/cv2-measure-profiles/run1.git-status-cold.allocs.after.pprof
go tool pprof -top -lines -nodecount=15 -nodefraction=0 '-focus=authorityrpc\.\(\*Server\)|authorityrpc\.\(\*VolumeHandler\)|internal/volumeserver\.|internal/xfsstore\.' -relative_percentages -sample_index=alloc_space -base=/tmp/cv2-measure-profiles/run1.git-status-cold.allocs.before.pprof /tmp/cv2-measure-profiles/run1.fusev3.test /tmp/cv2-measure-profiles/run1.git-status-cold.allocs.after.pprof
```
