#!/usr/bin/env python3
"""Deterministic executable model for the pinned PortableFS FUSE profile.

These tests do not pretend to replace a live patched-kernel qualification run.
They pin every private wire shape and exercise the ordering/error cases which
are otherwise difficult to force reproducibly through /dev/fuse.
"""

from __future__ import annotations

import dataclasses
import errno
import os
import pathlib
import random
import re
import threading
import unittest


U64_MAX = (1 << 64) - 1
S64_MAX = (1 << 63) - 1
BIT62 = 1 << 62
BIT63 = 1 << 63

FOPEN_DIRECT_IO = 1 << 0
FOPEN_KEEP_CACHE = 1 << 1
FOPEN_NONSEEKABLE = 1 << 2
FOPEN_CACHE_DIR = 1 << 3
FOPEN_STREAM = 1 << 4
FOPEN_NOFLUSH = 1 << 5
FOPEN_PARALLEL_DIRECT_WRITES = 1 << 6
FOPEN_PASSTHROUGH = 1 << 7
FOPEN_PFS_SHARED = 1 << 8
FOPEN_PFS_LOCAL = 1 << 9

ATTR_PFS_SHARED = 1 << 2
ATTR_PFS_LOCAL = 1 << 3
STATX_ATTR_IMMUTABLE = 0x00000010
STATX_ATTR_APPEND = 0x00000020
STATX_ATTR_NODUMP = 0x00000040
STATX_ATTR_ENCRYPTED = 0x00000800
STATX_ATTR_VERITY = 0x00100000
STATX_ATTR_DAX = 0x00200000
PFS_STATX_ATTRIBUTES = (
    STATX_ATTR_IMMUTABLE
    | STATX_ATTR_APPEND
    | STATX_ATTR_NODUMP
    | STATX_ATTR_ENCRYPTED
    | STATX_ATTR_VERITY
    | STATX_ATTR_DAX
)

WRITE_BEGUN = 1 << 0
WRITE_STAGED = 1 << 1
WRITE_COMMITTED = 1 << 2
WRITE_ABORTED = 1 << 3
WRITE_REJECTED = 1 << 4
WRITE_POSTAPPLY = 1 << 5
WRITE_REJECTED_RLIMIT = 1 << 6

RANGE_APPLIED = 1 << 0
RANGE_REJECTED = 1 << 1
RANGE_POSTAPPLY = 1 << 2
RANGE_REJECTED_RLIMIT = 1 << 3
RANGE_NOOP = 1 << 4

FALLOC_KEEP = 0x01
FALLOC_PUNCH = 0x02
FALLOC_COLLAPSE = 0x08
FALLOC_ZERO = 0x10
FALLOC_INSERT = 0x20
FALLOC_UNSHARE = 0x40
VALID_FALLOCATE_MODES = {
    0,
    FALLOC_KEEP,
    FALLOC_PUNCH | FALLOC_KEEP,
    FALLOC_ZERO,
    FALLOC_ZERO | FALLOC_KEEP,
    FALLOC_COLLAPSE,
    FALLOC_INSERT,
    FALLOC_UNSHARE,
    FALLOC_UNSHARE | FALLOC_KEEP,
}


class ProtocolError(Exception):
    pass


class TransportError(Exception):
    pass


@dataclasses.dataclass(frozen=True)
class WriteReply:
    txid: int
    committed_size: int = 0
    assigned_offset: int = 0
    post_size: int = 0
    sequence: int = 0
    flags: int = 0
    error: int = 0


@dataclasses.dataclass(frozen=True)
class RangeReply:
    result_size: int = 0
    post_size: int = 0
    sequence: int = 0
    flags: int = 0
    error: int = 0


def linux_errno(value: int) -> bool:
    return -4095 <= value <= -1


def next_txid(current: int) -> int:
    value = current + 1
    if value <= 0 or value > S64_MAX:
        raise OverflowError
    return value


def next_normal_unique(current: int) -> int:
    value = current + 2
    if not value or value & (BIT62 | BIT63):
        raise OverflowError
    return value


def next_publication_id(current: int) -> int:
    value = current + 2
    if value <= 0 or value > S64_MAX or value % 2 != 1:
        raise OverflowError
    return value


def write_shape(total: int, max_write: int, request_capacity: int) -> str:
    if total <= 0 or max_write <= 0 or request_capacity <= 0:
        raise ProtocolError("invalid write size boundary")
    return ("one-shot" if total <= max_write and total <= request_capacity
            else "transaction")


def buffered_write_plan(total: int, max_write: int, max_pages: int,
                        page_size: int, first_page_offset: int
                        ) -> tuple[str, list[int], int]:
    if (total <= 0 or max_write <= 0 or max_pages <= 0 or page_size <= 0 or
            first_page_offset < 0 or first_page_offset >= page_size):
        raise ProtocolError("invalid buffered write geometry")
    request_capacity = min(max_write,
                           max_pages * page_size - first_page_offset)
    shape = write_shape(total, max_write, request_capacity)
    if shape == "one-shot":
        return shape, [total], total

    remaining = total
    offset = first_page_offset
    fragments: list[int] = []
    while remaining:
        capacity = min(max_write, max_pages * page_size - offset)
        fragment = min(remaining, capacity)
        fragments.append(fragment)
        remaining -= fragment
        offset = (offset + fragment) % page_size
    return shape, fragments, sum(fragments)


def validate_write_reply(reply: WriteReply, txid: int, expected: int) -> str:
    if reply.txid != txid:
        raise ProtocolError("transaction identity mismatch")
    results = (
        reply.committed_size,
        reply.assigned_offset,
        reply.post_size,
        reply.sequence,
    )
    if expected == WRITE_COMMITTED and reply.flags in (
        WRITE_REJECTED,
        WRITE_REJECTED_RLIMIT,
    ):
        if any(results) or not linux_errno(reply.error):
            raise ProtocolError("malformed definite rejection")
        if reply.flags == WRITE_REJECTED_RLIMIT and reply.error != -errno.EFBIG:
            raise ProtocolError("RLIMIT rejection must be EFBIG")
        return "rlimit" if reply.flags == WRITE_REJECTED_RLIMIT else "rejected"
    if expected == WRITE_COMMITTED and reply.flags == (
        WRITE_COMMITTED | WRITE_POSTAPPLY
    ):
        if not linux_errno(reply.error):
            raise ProtocolError("post-apply error missing")
        outcome = "postapply"
    elif reply.flags == expected and reply.error == 0:
        outcome = "committed" if expected == WRITE_COMMITTED else "ack"
    else:
        raise ProtocolError("wrong write response shape")
    if expected != WRITE_COMMITTED:
        if any(results):
            raise ProtocolError("control ACK carried result")
    else:
        if reply.sequence <= 0 or reply.sequence > S64_MAX:
            raise ProtocolError("invalid visibility sequence")
        if reply.committed_size == 0:
            if outcome != "postapply" or reply.assigned_offset != 0:
                raise ProtocolError("zero-byte result was not attr postapply")
        elif (
            reply.assigned_offset + reply.committed_size > S64_MAX
            or reply.post_size < reply.assigned_offset + reply.committed_size
        ):
            raise ProtocolError("invalid committed tuple")
    return outcome


def validate_range_reply(
    reply: RangeReply,
    *,
    allow_noop: bool,
    fallocate_rlimit_pre_size: bool,
) -> str:
    if reply.flags == RANGE_REJECTED:
        if (
            reply.result_size
            or reply.post_size
            or reply.sequence
            or not linux_errno(reply.error)
        ):
            raise ProtocolError("malformed range rejection")
        return "rejected"
    if reply.flags == RANGE_REJECTED_RLIMIT:
        if (
            reply.result_size
            or reply.sequence
            or reply.error != -errno.EFBIG
            or (reply.post_size and not fallocate_rlimit_pre_size)
        ):
            raise ProtocolError("malformed range RLIMIT rejection")
        return "rlimit"
    if reply.flags == RANGE_NOOP:
        if not allow_noop or any(
            (reply.result_size, reply.post_size, reply.sequence, reply.error)
        ):
            raise ProtocolError("malformed NOOP")
        return "noop"
    if reply.flags == RANGE_APPLIED:
        if reply.error:
            raise ProtocolError("APPLIED carried error")
        outcome = "applied"
    elif reply.flags == RANGE_APPLIED | RANGE_POSTAPPLY:
        if not linux_errno(reply.error):
            raise ProtocolError("POSTAPPLY missing errno")
        outcome = "postapply"
    else:
        raise ProtocolError("unknown range flags")
    if reply.sequence <= 0 or reply.sequence > S64_MAX:
        raise ProtocolError("bad visibility sequence")
    if fallocate_rlimit_pre_size:
        if reply.result_size:
            raise ProtocolError("fallocate carried a byte count")
    elif outcome == "applied" and reply.result_size == 0:
        raise ProtocolError("clean copy must make byte progress")
    return outcome


def classify_attr(flags: int) -> str:
    bits = flags & (ATTR_PFS_SHARED | ATTR_PFS_LOCAL)
    if bits == ATTR_PFS_SHARED:
        return "shared"
    if bits == ATTR_PFS_LOCAL:
        return "local"
    raise ProtocolError("attr must carry exactly one class")


def validate_open(
    inode_class: str,
    flags: int,
    regular: bool = True,
    directory: bool = False,
) -> None:
    class_bits = flags & (FOPEN_PFS_SHARED | FOPEN_PFS_LOCAL)
    expected = FOPEN_PFS_SHARED if inode_class == "shared" else FOPEN_PFS_LOCAL
    if class_bits != expected:
        raise ProtocolError("open class mismatch")
    if regular and inode_class == "shared":
        # Under FUSE_PFS_CACHED_DATA the exact dialect retains the page cache.
        # FOPEN_DIRECT_IO is not merely unused here, it is refused: it would
        # route reads around the cache the DATA barrier is written against.
        if flags != FOPEN_KEEP_CACHE | FOPEN_PFS_SHARED:
            raise ProtocolError("shared regular OPEN is not the exact dialect")
    if directory and inode_class == "shared":
        if flags != FOPEN_PFS_SHARED:
            raise ProtocolError("shared OPENDIR may not cache directory data")


def lookup_requires_marker(
    parent: str, result: str | None, *, route_claimed: bool = False
) -> bool:
    if route_claimed:
        return False
    if result is None:
        return parent == "shared"
    return result == "shared"


DEFAULT_LOOKUP_SHAPE_RULES = (
    ("local-negative", False, ATTR_PFS_LOCAL, 0, False),
    ("shared-negative", False, 0, 32, True),
    ("local-positive", True, ATTR_PFS_LOCAL, 0, False),
    ("shared-positive", True, ATTR_PFS_SHARED, 32, True),
)


def lookup_shape_rules() -> tuple[tuple[str, bool, int, int, bool], ...]:
    tree = os.environ.get("PFS_PATCHED_KERNEL_TREE")
    if not tree:
        return DEFAULT_LOOKUP_SHAPE_RULES
    source = (pathlib.Path(tree) / "fs/fuse/dir.c").read_text()
    start = source.index("fuse_pfs_lookup_shape_rules[]")
    end = source.index("static bool fuse_pfs_local_negative_base", start)
    block = source[start:end]
    pattern = re.compile(
        r"\.shape = FUSE_PFS_LOOKUP_([A-Z_]+),\s*"
        r"\.positive = (true|false),\s*"
        r"\.class_bits = (FUSE_ATTR_PFS_LOCAL|FUSE_ATTR_PFS_SHARED|0),\s*"
        r"\.stamp_size = (sizeof\(struct fuse_pfs_cache_stamp\)|0),\s*"
        r"\.marked = (true|false),"
    )
    classes = {
        "0": 0,
        "FUSE_ATTR_PFS_LOCAL": ATTR_PFS_LOCAL,
        "FUSE_ATTR_PFS_SHARED": ATTR_PFS_SHARED,
    }
    rules = tuple(
        (
            shape.lower().replace("_", "-"),
            positive == "true",
            classes[class_bits],
            32 if stamp_size.startswith("sizeof") else 0,
            marked == "true",
        )
        for shape, positive, class_bits, stamp_size, marked
        in pattern.findall(block)
    )
    if not rules:
        raise ProtocolError("kernel LOOKUP classifier has no shape rules")
    return rules


def strict_lookup_shape(
    *, nodeid: int, attr_flags: int, stamp_size: int, marked: bool,
    generation: int = 0, entry_lifetime: int = 0,
    attr_lifetime: int = 0, other_attr_nonzero: bool = False,
) -> str:
    positive = nodeid != 0
    class_bits = attr_flags & (ATTR_PFS_SHARED | ATTR_PFS_LOCAL)
    for (
        shape, rule_positive, rule_class, rule_size, rule_marked
    ) in lookup_shape_rules():
        if ((positive, class_bits, stamp_size, marked) !=
                (rule_positive, rule_class, rule_size, rule_marked)):
            continue
        if not positive:
            if generation or attr_lifetime or other_attr_nonzero:
                raise ProtocolError("malformed negative base record")
            if shape == "local-negative" and entry_lifetime:
                raise ProtocolError("malformed LOCAL negative lifetime")
        return "shared" if shape.startswith("shared-") else "local"
    raise ProtocolError("LOOKUP did not match one complete kernel shape")


def strict_negative_lookup_shape(**kwargs: object) -> str:
    return strict_lookup_shape(nodeid=0, **kwargs)


def strict_revalidate_lookup(existing_class: str, **kwargs: object) -> str:
    result_class = strict_lookup_shape(**kwargs)
    if result_class != existing_class:
        raise ProtocolError("revalidation changed inode class")
    return result_class


@dataclasses.dataclass(frozen=True)
class DirPlusParseResult:
    linked: tuple[int, ...]
    force_forgotten: tuple[int, ...]
    session_released: tuple[int, ...]


def parse_marked_dirplus_page(
    nodeids: tuple[int, ...], *, link_failure: int | None = None,
    malformed_tail: int | None = None, teardown_during_drain: bool = False,
) -> DirPlusParseResult:
    """Model lookup ownership after an accepted marked page is parsed."""
    if any(nodeid <= 1 for nodeid in nodeids):
        raise ProtocolError("READDIRPLUS page carried an invalid nodeid")
    if link_failure is None:
        if malformed_tail is not None or teardown_during_drain:
            raise ProtocolError("failure controls require a link failure")
        return DirPlusParseResult(nodeids, (), ())
    if link_failure < 0 or link_failure >= len(nodeids):
        raise ProtocolError("link failure is outside the page")
    if malformed_tail is not None and malformed_tail <= link_failure:
        raise ProtocolError("malformed tail does not follow the failed record")

    linked = nodeids[:link_failure]
    drain_end = malformed_tail if malformed_tail is not None else len(nodeids)
    if teardown_during_drain:
        drain_end = link_failure + 1
    force_forgotten = nodeids[link_failure:drain_end]
    # A partial parser result has no receipt shape, so the connection becomes
    # terminal. Detach releases every capability not already force-forgotten,
    # including the linked prefix and any drain requests lost to teardown.
    released = tuple(
        nodeid for nodeid in nodeids if nodeid not in force_forgotten
    )
    return DirPlusParseResult(linked, force_forgotten, released)


REQUIRED_INIT = {
    "ATOMIC_O_TRUNC",
    "HANDLE_KILLPRIV_V2",
    "POSIX_LOCKS",
    "FLOCK_LOCKS",
    "PFS_STRICT",
    # The private bits are one profile revision. A daemon offering an
    # incomplete set was built against a different contract and must fail INIT
    # rather than disagree about the open flags or write shape after mount.
    "PFS_CACHED_DATA",
    # Single-fragment writes have one request shape only. This third revision
    # bit prevents an old daemon from interpreting ONE_SHOT as an unknown phase.
    "PFS_WRITE_ONESHOT",
    # Retained pages are withdrawn by the ordered DATA publication alone, so
    # invalidation is explicit; mtime heuristics would both drop a coherent
    # cache for nothing and put a GETATTR in front of every read.
    "EXPLICIT_INVAL_DATA",
}
FORBIDDEN_INIT = {
    "AUTO_INVAL_DATA",
    "WRITEBACK_CACHE",
    "DIRECT_IO_MMAP",
    "INODE_DAX",
    "EXPORT_SUPPORT",
    "SUBMOUNTS",
    "NO_OPEN",
    "NO_OPENDIR",
    "READDIRPLUS",
    "READDIRPLUS_AUTO",
    "POSIX_ACL",
    "PASSTHROUGH",
    "HAS_RESEND",
}

STRICT_NOTIFY_CODES = {
    "PFS_SIZE",
    "PFS_ATTR",
    "PFS_ENTRY",
}


FILESYSTEM_MAX_STACK_DEPTH = 2


def stacked_mount_depth(*layers: int) -> int:
    depth = max(layers) + 1
    if depth > FILESYSTEM_MAX_STACK_DEPTH:
        raise ProtocolError("maximum filesystem stacking depth exceeded")
    return depth


def finish_fuse_init(strict: bool, passthrough_depth: int = 0) -> int:
    provisional = FILESYSTEM_MAX_STACK_DEPTH
    if strict:
        return provisional
    return passthrough_depth


def finish_fuse_export_boundary(
    strict: bool, *, init_ok: bool = True
) -> tuple[bool, bool]:
    """Return (reply_publish, export_ops) after provisional closure."""
    if not init_ok or strict:
        return True, False
    return False, True


def ksmbd_open(reply_publish: bool) -> None:
    if reply_publish:
        raise ProtocolError("strict FUSE cannot back an SMB export")


def strict_notify(
    code: str,
    inode: KernelInode | None = None,
    *,
    nodeid: int = 1,
    child: int = 1,
    name: bytes = b"entry",
    off: int = -1,
    length: int = 0,
    flags: int = 0,
    padding: int = 0,
    sequence: int = 1,
    resident_child: KernelInode | None = None,
    record_nodeid: int | None = None,
    record_version: int | None = None,
    record_class: str = "shared",
    inode_flags: int | None = None,
    birth_time_ns: int | None = None,
    mode: int | None = None,
    uid: int | None = None,
    exact_size: int | None = None,
) -> str:
    if code not in STRICT_NOTIFY_CODES:
        raise ProtocolError("reverse notification outside strict dialect")
    if nodeid == 0:
        raise ProtocolError("zero reverse-notification identity")
    if code == "PFS_ENTRY" and flags == 1 and child == 0:
        raise ProtocolError("zero DELETE child identity")
    if code == "PFS_ENTRY" and (
        not name or b"\0" in name or b"/" in name or name in (b".", b"..")
    ):
        raise ProtocolError("invalid cached-child component")
    if code == "PFS_ENTRY" and (
        flags not in (0, 1) or (flags == 0 and child != 0)
    ):
        raise ProtocolError("invalid exact entry-repair shape")
    if not 0 < sequence <= S64_MAX:
        raise ProtocolError("repair sequence is outside signed authority range")
    if code in ("PFS_ATTR", "PFS_SIZE"):
        if record_nodeid is None:
            record_nodeid = nodeid
        if record_version is None:
            record_version = sequence
        if (record_nodeid != nodeid or not 0 < record_version <= sequence or
                record_class != "shared"):
            raise ProtocolError("invalid exact repair record")
    if inode is None:
        return "absent"
    if inode.pfs_class != "shared":
        raise ProtocolError("reverse repair targeted a LOCAL inode")
    if code == "PFS_ENTRY" and not inode.is_dir:
        raise ProtocolError("namespace repair parent is not a directory")
    if code == "PFS_ENTRY" and resident_child is not None:
        if resident_child.pfs_class != "shared":
            raise ProtocolError("namespace repair targeted a LOCAL child")
        if flags == 1 and child != resident_child.nodeid:
            raise ProtocolError("DELETE child identity mismatch")
        inode.cache_generation += 1
    if code == "PFS_SIZE":
        if inode.is_dir:
            raise ProtocolError("PFS_SIZE target is not a regular file")
        inode.exact_data(inode.size if exact_size is None else exact_size,
                         sequence)
    if code in ("PFS_ATTR", "PFS_SIZE"):
        inode.repair_attr(
            record_version,
            inode.inode_flags if inode_flags is None else inode_flags,
            inode.birth_time_ns if birth_time_ns is None else birth_time_ns,
            inode.mode if mode is None else mode,
            inode.uid if uid is None else uid,
        )
    return "dispatched"


def strict_init(minor: int, flags: set[str], default_permissions: bool) -> None:
    if minor != 42 or not default_permissions:
        raise ProtocolError("strict profile requires exact ABI 7.42")
    if not REQUIRED_INIT <= flags or FORBIDDEN_INIT & flags:
        raise ProtocolError("strict INIT capability mismatch")


@dataclasses.dataclass(frozen=True)
class FrozenWrite:
    total: int
    append: bool
    position: int
    rlimit: int
    file_max: int
    flags: int = 0
    write_flags: int = 0
    lock_owner: int = 0


@dataclasses.dataclass
class Tx:
    frozen: FrozenWrite
    staged: bytearray = dataclasses.field(default_factory=bytearray)
    result: WriteReply | None = None
    aborted: bool = False


class Authority:
    """In-memory authority with direct one-shots and one locked commit cut."""

    def __init__(self, initial: bytes = b"") -> None:
        self.contents = bytearray(initial)
        self.sequence = 0
        self.transactions: dict[int, Tx] = {}
        self.one_shot_results: dict[
            tuple[int, int], tuple[tuple[FrozenWrite, bytes], WriteReply]
        ] = {}
        self.lock = threading.Lock()

    def _apply(self, txid: int, frozen: FrozenWrite,
               payload: bytes) -> WriteReply:
        f = frozen
        with self.lock:
            assigned = len(self.contents) if f.append else f.position
            ceiling = min(f.rlimit, f.file_max)
            if assigned >= ceiling:
                flag = (
                    WRITE_REJECTED_RLIMIT
                    if f.rlimit != U64_MAX and assigned >= f.rlimit
                    else WRITE_REJECTED
                )
                return WriteReply(txid=txid, flags=flag, error=-errno.EFBIG)
            committed = min(len(payload), ceiling - assigned)
            end = assigned + committed
            if end > len(self.contents):
                self.contents.extend(b"\0" * (end - len(self.contents)))
            self.contents[assigned:end] = payload[:committed]
            self.sequence += 1
            return WriteReply(
                txid=txid,
                committed_size=committed,
                assigned_offset=assigned,
                post_size=len(self.contents),
                sequence=self.sequence,
                flags=WRITE_COMMITTED,
            )

    def one_shot(self, slot: int, sequence: int, frozen: FrozenWrite,
                 payload: bytes) -> WriteReply:
        if frozen.total <= 0 or len(payload) != frozen.total:
            raise ProtocolError("one-shot payload does not match geometry")
        identity = (slot, sequence)
        fingerprint = (frozen, payload)
        retained = self.one_shot_results.get(identity)
        if retained is not None:
            if retained[0] != fingerprint:
                raise ProtocolError("one-shot replay changed request")
            return retained[1]
        reply = self._apply(0, frozen, payload)
        self.one_shot_results[identity] = (fingerprint, reply)
        return reply

    def begin(self, txid: int, frozen: FrozenWrite) -> WriteReply:
        if txid <= 0 or frozen.total <= 0 or frozen.file_max <= 0:
            raise ProtocolError
        existing = self.transactions.get(txid)
        if existing is None:
            self.transactions[txid] = Tx(frozen=frozen)
        elif existing.frozen != frozen:
            raise ProtocolError("metadata changed after BEGIN")
        return WriteReply(txid=txid, flags=WRITE_BEGUN)

    def data(self, txid: int, offset: int, payload: bytes) -> WriteReply:
        tx = self.transactions[txid]
        if tx.aborted or tx.result is not None or not payload:
            raise ProtocolError
        end = offset + len(payload)
        if end > tx.frozen.total:
            raise ProtocolError
        if offset < len(tx.staged):
            if end > len(tx.staged) or tx.staged[offset:end] != payload:
                raise ProtocolError("non-idempotent DATA replay")
        elif offset == len(tx.staged):
            tx.staged.extend(payload)
        else:
            raise ProtocolError("DATA gap")
        return WriteReply(txid=txid, flags=WRITE_STAGED)

    def abort(self, txid: int) -> WriteReply:
        tx = self.transactions.get(txid)
        if tx is None:
            return WriteReply(txid=txid, flags=WRITE_ABORTED)
        if tx.result is not None:
            raise ProtocolError("cannot abort committed transaction")
        tx.staged.clear()
        tx.aborted = True
        return WriteReply(txid=txid, flags=WRITE_ABORTED)

    def commit(self, txid: int, staged_size: int) -> WriteReply:
        tx = self.transactions[txid]
        if tx.result is not None:
            return tx.result
        if tx.aborted or staged_size != len(tx.staged) or not tx.staged:
            raise ProtocolError("COMMIT prefix mismatch")
        tx.result = self._apply(txid, tx.frozen, bytes(tx.staged[:staged_size]))
        return tx.result


@dataclasses.dataclass
class KernelInode:
    size: int = 0
    sequence: int = 0
    cache_generation: int = 0
    pfs_class: str = "shared"
    is_dir: bool = False
    nodeid: int = 1
    nlink: int = 1
    object_version: int = 0
    inode_flags: int = 0
    birth_time_ns: int = 0
    mode: int = 0o644
    uid: int = 0

    def exact_data(self, size: int, sequence: int) -> str:
        if size < 0 or sequence <= 0 or sequence > S64_MAX:
            raise ProtocolError
        if sequence < self.sequence:
            return "old"
        if sequence == self.sequence:
            if size != self.size:
                raise ProtocolError("same sequence changed exact size")
            return "duplicate"
        self.size = size
        self.sequence = sequence
        self.cache_generation += 1
        return "applied"

    def withdraw_data(self) -> None:
        if self.pfs_class != "shared":
            raise ProtocolError("withdrawal is a SHARED-only primitive")
        self.cache_generation += 1

    def repair_attr(
        self, sequence: int, inode_flags: int, birth_time_ns: int,
        mode: int | None = None, uid: int | None = None,
    ) -> str:
        if sequence <= 0 or sequence > S64_MAX:
            raise ProtocolError("invalid exact attr repair sequence")
        if sequence <= self.object_version:
            return "old"
        self.object_version = sequence
        self.inode_flags = inode_flags
        self.birth_time_ns = birth_time_ns
        if mode is not None:
            self.mode = mode
        if uid is not None:
            self.uid = uid
        return "applied"

    def install_stamped_attr(
        self, object_version: int, snapshot_sequence: int,
        inode_flags: int, birth_time_ns: int, mode: int | None = None,
        uid: int | None = None,
    ) -> str:
        if (object_version <= 0 or object_version > snapshot_sequence or
                snapshot_sequence > S64_MAX):
            raise ProtocolError("invalid stamped attr")
        if object_version <= self.object_version:
            return "old"
        return self.repair_attr(
            object_version, inode_flags, birth_time_ns, mode, uid
        )

    def permission(self, mask: int) -> bool:
        return bool(self.mode & mask)

    def remote_execute_permission(self) -> bool:
        return bool(self.mode & 0o111)

    def coredump_safe(self, caller_uid: int) -> bool:
        return caller_uid == self.uid and not bool(self.mode & 0o022)

    def lsm_owner_rule(self, expected_uid: int) -> bool:
        return self.uid == expected_uid

    def audit_snapshot(self) -> tuple[int, int, int]:
        return self.uid, self.mode, self.inode_flags

    def fill_exact_statx(self) -> dict[str, int]:
        return {
            "birth_time_ns": self.birth_time_ns,
            "attributes": self.inode_flags,
            "attributes_mask": PFS_STATX_ATTRIBUTES,
        }


class PublicationGate:
    def __init__(self) -> None:
        self.original_written = False
        self.kernel_postprocessed = False
        self.ack_physically_written = False
        self.gate_released = False

    def original_reply(self) -> None:
        self.original_written = True

    def kernel_publish_request(self) -> None:
        if not self.original_written:
            raise ProtocolError
        self.kernel_postprocessed = True

    def daemon_ack_written(self) -> None:
        if not self.kernel_postprocessed:
            raise ProtocolError("PUBLISH before VFS postprocessing")
        self.ack_physically_written = True
        self.gate_released = True


def fallocate_expected_size(mode: int, old: int, offset: int, length: int) -> int:
    if mode not in VALID_FALLOCATE_MODES or offset < 0 or length <= 0:
        raise ValueError
    end = offset + length
    if mode == FALLOC_COLLAPSE:
        if end >= old:
            raise ValueError("collapse must end strictly before EOF")
        return old - length
    if mode == FALLOC_INSERT:
        if offset >= old:
            raise ValueError("insert offset must be before EOF")
        return old + length
    if mode & FALLOC_KEEP or mode == FALLOC_PUNCH | FALLOC_KEEP:
        return old
    return max(old, end)


def validate_fallocate_rlimit_proof(
    mode: int,
    offset: int,
    length: int,
    rlimit: int,
    file_max: int,
    pre_size: int,
) -> None:
    if rlimit == U64_MAX or pre_size > file_max:
        raise ProtocolError
    end = offset + length
    if mode == FALLOC_INSERT:
        new_size = pre_size + length
        if new_size > file_max or offset >= pre_size or new_size <= rlimit:
            raise ProtocolError
        return
    if mode not in (0, FALLOC_ZERO, FALLOC_UNSHARE):
        raise ProtocolError
    if not (pre_size < end and end > rlimit):
        raise ProtocolError


def xfs_fallocate_precheck(
    mode: int,
    pre_size: int,
    offset: int,
    length: int,
    rlimit: int,
    file_max: int,
    allocation_unit: int,
) -> str:
    """Relevant pinned-XFS rejection precedence before syscall dispatch."""
    end = offset + length
    if mode in (FALLOC_COLLAPSE, FALLOC_INSERT):
        if offset % allocation_unit or length % allocation_unit:
            return "EINVAL_ALIGNMENT"
    if mode == FALLOC_COLLAPSE:
        return "EINVAL_EOF" if end >= pre_size else "OK"
    if mode == FALLOC_INSERT:
        if pre_size + length > file_max:
            return "EFBIG_FILEMAX"
        if offset >= pre_size:
            return "EINVAL_EOF"
        if rlimit != U64_MAX and pre_size + length > rlimit:
            return "EFBIG_RLIMIT"
        return "OK"
    if mode in (0, FALLOC_ZERO, FALLOC_UNSHARE) and end > pre_size:
        if end > file_max:
            return "EFBIG_FILEMAX"
        if rlimit != U64_MAX and end > rlimit:
            return "EFBIG_RLIMIT"
    return "OK"


def validate_clean_fallocate_shape(
    mode: int,
    offset: int,
    length: int,
    post_size: int,
    rlimit: int,
    file_max: int,
) -> None:
    """Kernel-checkable invariants for a clean APPLIED result."""
    end = offset + length
    if post_size > file_max:
        raise ProtocolError
    if mode == FALLOC_INSERT:
        if post_size <= end or (rlimit != U64_MAX and post_size > rlimit):
            raise ProtocolError
    elif mode == FALLOC_COLLAPSE:
        # post=S-length and offset+length<S imply offset<post; S<=file_max
        # implies post<=file_max-length.
        if post_size <= offset or post_size > file_max - length:
            raise ProtocolError
    elif mode in (0, FALLOC_ZERO, FALLOC_UNSHARE) and post_size < end:
        raise ProtocolError


def validate_cfr_noop_limits(dst_offset: int, rlimit: int,
                             file_max: int) -> None:
    """A zero-byte result cannot bypass ordinary output-limit precedence."""
    if dst_offset >= file_max:
        raise ProtocolError
    if rlimit != U64_MAX and dst_offset >= rlimit:
        raise ProtocolError


def cfr_result(
    data: bytes,
    src_offset: int,
    dst_offset: int,
    requested: int,
    rlimit: int,
    file_max: int,
    same_inode: bool,
) -> tuple[str, int]:
    """Pinned ordering: EOF clip, then output limits, then overlap."""
    clipped = max(0, min(requested, len(data) - src_offset))
    if rlimit != U64_MAX and dst_offset >= rlimit:
        return "rlimit", 0
    if dst_offset >= file_max:
        return "filemax", 0
    clipped = min(clipped, file_max - dst_offset)
    if rlimit != U64_MAX:
        clipped = min(clipped, rlimit - dst_offset)
    if same_inode and clipped:
        src_end = src_offset + clipped
        dst_end = dst_offset + clipped
        if src_offset < dst_end and dst_offset < src_end:
            return "overlap", 0
    return ("noop", 0) if clipped == 0 else ("applied", clipped)


class AbiAndAdmissionTests(unittest.TestCase):
    def test_read_buffer_keeps_max_write_payload(self) -> None:
        header, stock, private, max_write = 40, 40, 80, 1 << 20
        self.assertEqual(header + private + max_write, 1_048_696)
        self.assertEqual(private - stock, 40)
        self.assertEqual(header + private + max_write - header - private,
                         max_write)

    def test_exact_minor_and_capability_suite(self) -> None:
        strict_init(42, set(REQUIRED_INIT), True)
        for minor in (28, 36, 40, 41, 43):
            with self.assertRaises(ProtocolError):
                strict_init(minor, set(REQUIRED_INIT), True)
        for missing in REQUIRED_INIT:
            with self.assertRaises(ProtocolError):
                strict_init(42, set(REQUIRED_INIT) - {missing}, True)
        for forbidden in FORBIDDEN_INIT:
            with self.assertRaises(ProtocolError):
                strict_init(42, set(REQUIRED_INIT) | {forbidden}, True)
        with self.assertRaises(ProtocolError):
            strict_init(42, set(REQUIRED_INIT), False)

    def test_strict_superblock_refuses_lower_and_upper_stacking(self) -> None:
        preinit_depth = FILESYSTEM_MAX_STACK_DEPTH
        with self.assertRaises(ProtocolError):
            stacked_mount_depth(preinit_depth)

        strict_depth = finish_fuse_init(True)
        with self.assertRaises(ProtocolError):
            stacked_mount_depth(strict_depth, 0)  # strict lower layer
        with self.assertRaises(ProtocolError):
            stacked_mount_depth(0, strict_depth)  # strict upper layer

        # A bind mount reuses the same superblock; it does not add a layer.
        self.assertEqual(strict_depth, FILESYSTEM_MAX_STACK_DEPTH)
        self.assertEqual(finish_fuse_init(False), 0)
        self.assertEqual(finish_fuse_init(False, 1), 1)

    def test_export_boundary_is_closed_before_init_and_for_strict(self) -> None:
        # An opener that races a delayed INIT observes the provisional closure.
        with self.assertRaises(ProtocolError):
            ksmbd_open(True)

        strict_publish, strict_export = finish_fuse_export_boundary(True)
        self.assertTrue(strict_publish)
        self.assertFalse(strict_export)
        with self.assertRaises(ProtocolError):
            ksmbd_open(strict_publish)

        failed_publish, failed_export = finish_fuse_export_boundary(
            False, init_ok=False
        )
        self.assertTrue(failed_publish)
        self.assertFalse(failed_export)

        stock_publish, stock_export = finish_fuse_export_boundary(False)
        self.assertFalse(stock_publish)
        self.assertTrue(stock_export)
        ksmbd_open(stock_publish)

    def test_nonwrapping_even_and_odd_identity_domains(self) -> None:
        self.assertEqual(next_normal_unique(0), 2)
        self.assertEqual(next_publication_id(-1), 1)
        for normal in range(2, 200, 2):
            self.assertEqual(normal & 1, 0)
            self.assertNotEqual(normal, next_publication_id(normal - 3))
        with self.assertRaises(OverflowError):
            next_normal_unique(BIT62 - 2)
        with self.assertRaises(OverflowError):
            next_publication_id(S64_MAX)
        with self.assertRaises(OverflowError):
            next_txid(S64_MAX)

    def test_dual_classification_and_exact_shared_open(self) -> None:
        self.assertEqual(classify_attr(ATTR_PFS_SHARED), "shared")
        self.assertEqual(classify_attr(ATTR_PFS_LOCAL), "local")
        for malformed in (0, ATTR_PFS_SHARED | ATTR_PFS_LOCAL):
            with self.assertRaises(ProtocolError):
                classify_attr(malformed)
        validate_open("shared", FOPEN_KEEP_CACHE | FOPEN_PFS_SHARED)
        validate_open("local", FOPEN_KEEP_CACHE | FOPEN_PFS_LOCAL)
        validate_open(
            "shared", FOPEN_PFS_SHARED, regular=False, directory=True
        )
        validate_open(
            "local",
            FOPEN_PFS_LOCAL | FOPEN_CACHE_DIR | FOPEN_KEEP_CACHE,
            regular=False,
            directory=True,
        )
        for forbidden in (
            FOPEN_DIRECT_IO,
            FOPEN_NONSEEKABLE,
            FOPEN_CACHE_DIR,
            FOPEN_STREAM,
            FOPEN_NOFLUSH,
            FOPEN_PARALLEL_DIRECT_WRITES,
            FOPEN_PASSTHROUGH,
        ):
            with self.assertRaises(ProtocolError):
                validate_open(
                    "shared", FOPEN_KEEP_CACHE | FOPEN_PFS_SHARED | forbidden
                )
        # The retired pair is gone entirely: kernel and daemon ship together,
        # so a handle offered in the old dialect is a version mismatch, not a
        # compatible peer.
        with self.assertRaises(ProtocolError):
            validate_open("shared", FOPEN_DIRECT_IO | FOPEN_PFS_SHARED)
        for forbidden in (FOPEN_CACHE_DIR, FOPEN_KEEP_CACHE):
            with self.assertRaises(ProtocolError):
                validate_open(
                    "shared",
                    FOPEN_PFS_SHARED | forbidden,
                    regular=False,
                    directory=True,
                )

    def test_shared_readdir_is_never_served_from_persistent_dir_cache(
        self,
    ) -> None:
        rpc_count = 0
        contents = ["before"]
        cached: list[str] | None = None

        def getdents(shared: bool) -> list[str]:
            nonlocal rpc_count, cached
            if shared or cached is None:
                rpc_count += 1
                result = list(contents)
                if not shared:
                    cached = result
                return result
            return list(cached)

        self.assertEqual(getdents(True), ["before"])
        contents.append("peer-created")
        # The peer's INVAL_ENTRY may report benign ENOENT locally.  A SHARED
        # directory still has no FOPEN_CACHE_DIR path to stale getdents data.
        self.assertEqual(getdents(True), ["before", "peer-created"])
        self.assertEqual(rpc_count, 2)

    def test_shared_willneed_prefetches_into_a_withdrawable_cache(self) -> None:
        """POSIX_FADV_WILLNEED is admitted again, and stays coherent.

        The advice used to be discarded on a SHARED handle because the page
        cache had to stay empty.  It now reaches page_cache_ra_unbounded(),
        which fills folios under mapping->invalidate_lock held shared -- the
        same lock the ordered DATA publication takes exclusively.  So a
        prefetched folio is withdrawn by the next DATA publication exactly like
        one a read(2) installed, and the model asserts that rather than
        asserting the advice was ignored.
        """
        authority = bytearray(b"old")
        inode = KernelInode(size=len(authority))
        cache: bytes | None = None
        read_folio_calls = 0

        def willneed() -> None:
            nonlocal cache, read_folio_calls
            if cache is not None:
                return
            read_folio_calls += 1
            cache = bytes(authority)

        def exact_data(size: int, sequence: int) -> str:
            # invalidate_inode_pages2() under the exclusive invalidate lock.
            nonlocal cache
            outcome = inode.exact_data(size, sequence)
            if outcome == "applied":
                cache = None
            return outcome

        willneed()
        self.assertEqual(cache, b"old")
        self.assertEqual(read_folio_calls, 1)

        # A same-length peer overwrite still withdraws the prefetched folio:
        # the publication is ordered by sequence, never by a size delta.
        authority[:] = b"new"
        self.assertEqual(exact_data(len(authority), 1), "applied")
        self.assertIsNone(cache)

        willneed()
        self.assertEqual(cache, b"new")
        self.assertEqual(read_folio_calls, 2)

        # A replayed sequence is a no-op and must not drop a valid cache.
        self.assertEqual(exact_data(len(authority), 1), "duplicate")
        self.assertEqual(cache, b"new")

    def test_lookup_marker_is_result_classified(self) -> None:
        matrix = {
            ("shared", "shared"): True,
            ("shared", "local"): False,
            ("local", "shared"): True,
            ("local", "local"): False,
            ("shared", None): True,
            ("local", None): False,
        }
        for key, required in matrix.items():
            self.assertEqual(lookup_requires_marker(*key), required)
        self.assertFalse(
            lookup_requires_marker("shared", None, route_claimed=True)
        )

    def test_local_and_shared_negatives_have_disjoint_exact_shapes(self) -> None:
        self.assertEqual(lookup_shape_rules(), DEFAULT_LOOKUP_SHAPE_RULES)
        self.assertEqual(
            strict_negative_lookup_shape(
                attr_flags=ATTR_PFS_LOCAL, stamp_size=0, marked=False
            ),
            "local",
        )
        self.assertEqual(
            strict_negative_lookup_shape(
                attr_flags=0, stamp_size=32, marked=True
            ),
            "shared",
        )
        for malformed in (
            {"attr_flags": ATTR_PFS_LOCAL, "stamp_size": 32, "marked": False},
            {"attr_flags": ATTR_PFS_LOCAL, "stamp_size": 0, "marked": True},
            {
                "attr_flags": ATTR_PFS_LOCAL,
                "stamp_size": 0,
                "marked": False,
                "entry_lifetime": 1,
            },
            {"attr_flags": 0, "stamp_size": 0, "marked": False},
            {"attr_flags": 0, "stamp_size": 32, "marked": False},
            {
                "attr_flags": ATTR_PFS_SHARED,
                "stamp_size": 32,
                "marked": True,
            },
        ):
            with self.subTest(malformed=malformed):
                with self.assertRaises(ProtocolError):
                    strict_negative_lookup_shape(**malformed)

        for stamp_size in (1, 31):
            for attr_flags, marked in (
                (ATTR_PFS_LOCAL, False),
                (0, True),
            ):
                with self.subTest(
                    polarity="negative",
                    stamp_size=stamp_size,
                    attr_flags=attr_flags,
                ):
                    with self.assertRaises(ProtocolError):
                        strict_negative_lookup_shape(
                            attr_flags=attr_flags,
                            stamp_size=stamp_size,
                            marked=marked,
                        )

        self.assertEqual(
            strict_lookup_shape(
                nodeid=2, attr_flags=ATTR_PFS_LOCAL,
                stamp_size=0, marked=False,
            ),
            "local",
        )
        self.assertEqual(
            strict_lookup_shape(
                nodeid=3, attr_flags=ATTR_PFS_SHARED,
                stamp_size=32, marked=True,
            ),
            "shared",
        )
        for stamp_size in (1, 31):
            for attr_flags, marked in (
                (ATTR_PFS_LOCAL, False),
                (ATTR_PFS_SHARED, True),
            ):
                with self.subTest(
                    polarity="positive",
                    stamp_size=stamp_size,
                    attr_flags=attr_flags,
                ):
                    with self.assertRaises(ProtocolError):
                        strict_lookup_shape(
                            nodeid=4,
                            attr_flags=attr_flags,
                            stamp_size=stamp_size,
                            marked=marked,
                        )
        for existing, result in (("local", "shared"), ("shared", "local")):
            with self.subTest(existing=existing, result=result):
                with self.assertRaises(ProtocolError):
                    strict_revalidate_lookup(
                        existing,
                        nodeid=4,
                        attr_flags=(
                            ATTR_PFS_SHARED if result == "shared"
                            else ATTR_PFS_LOCAL
                        ),
                        stamp_size=32 if result == "shared" else 0,
                        marked=result == "shared",
                    )


class TransactionTests(unittest.TestCase):
    def test_size_class_has_exactly_one_shape_at_max_write_boundary(self) -> None:
        max_write = 1 << 20
        self.assertEqual(write_shape(1, max_write, max_write), "one-shot")
        self.assertEqual(write_shape(max_write, max_write, max_write),
                         "one-shot")
        self.assertEqual(write_shape(max_write + 1, max_write, max_write),
                         "transaction")

    def test_buffered_write_larger_than_page_vector_completes_all_fragments(
            self) -> None:
        max_write = 1 << 20
        for first_page_offset in (208, 3184):
            with self.subTest(first_page_offset=first_page_offset):
                shape, fragments, completed = buffered_write_plan(
                    max_write, max_write, 256, 4096, first_page_offset)
                self.assertEqual(shape, "transaction")
                self.assertEqual(
                    fragments,
                    [max_write - first_page_offset, first_page_offset],
                )
                self.assertEqual(completed, max_write)

    def test_one_shot_append_replay_is_exact_and_uses_no_transaction_id(self) -> None:
        authority = Authority(b"prefix")
        frozen = FrozenWrite(4, True, 0, U64_MAX, S64_MAX)
        reply = authority.one_shot(2, 9, frozen, b"data")
        self.assertEqual(validate_write_reply(reply, 0, WRITE_COMMITTED),
                         "committed")
        self.assertEqual((reply.assigned_offset, reply.post_size), (6, 10))
        self.assertEqual(authority.contents, b"prefixdata")
        self.assertEqual(authority.transactions, {})
        self.assertEqual(authority.one_shot(2, 9, frozen, b"data"), reply)
        self.assertEqual(authority.sequence, 1)
        self.assertEqual(authority.contents, b"prefixdata")
        with self.assertRaises(ProtocolError):
            authority.one_shot(2, 9, frozen, b"date")

    def test_fragmented_append_is_one_visibility_cut(self) -> None:
        authority = Authority(b"prefix")
        frozen = FrozenWrite(9, True, 0, U64_MAX, S64_MAX)
        validate_write_reply(authority.begin(1, frozen), 1, WRITE_BEGUN)
        validate_write_reply(authority.data(1, 0, b"abc"), 1, WRITE_STAGED)
        self.assertEqual(authority.contents, b"prefix")
        validate_write_reply(authority.data(1, 3, b"defghi"), 1, WRITE_STAGED)
        reply = authority.commit(1, 9)
        self.assertEqual(validate_write_reply(reply, 1, WRITE_COMMITTED),
                         "committed")
        self.assertEqual((reply.assigned_offset, reply.post_size), (6, 15))
        self.assertEqual(authority.contents, b"prefixabcdefghi")
        self.assertEqual(authority.commit(1, 9), reply)

    def test_positioned_overwrite_keeps_larger_eof(self) -> None:
        authority = Authority(b"abcdefghij")
        frozen = FrozenWrite(3, False, 2, U64_MAX, S64_MAX)
        authority.begin(7, frozen)
        authority.data(7, 0, b"XYZ")
        reply = authority.commit(7, 3)
        self.assertEqual(reply.assigned_offset, 2)
        self.assertEqual(reply.post_size, 10)
        self.assertEqual(authority.contents, b"abXYZfghij")

    def test_frozen_metadata_and_exact_commit_prefix(self) -> None:
        authority = Authority()
        frozen = FrozenWrite(8, True, 0, U64_MAX, S64_MAX, flags=1)
        authority.begin(9, frozen)
        with self.assertRaises(ProtocolError):
            authority.begin(9, dataclasses.replace(frozen, flags=2))
        authority.data(9, 0, b"abcd")
        with self.assertRaises(ProtocolError):
            authority.commit(9, 3)

    def test_lost_begin_or_data_cleanup_is_idempotent(self) -> None:
        authority = Authority()
        frozen = FrozenWrite(4, True, 0, U64_MAX, S64_MAX)
        authority.begin(11, frozen)
        authority.data(11, 0, b"data")
        self.assertEqual(authority.abort(11).flags, WRITE_ABORTED)
        self.assertEqual(authority.abort(999).flags, WRITE_ABORTED)
        self.assertEqual(authority.contents, b"")

    def test_rlimit_zero_one_and_infinity(self) -> None:
        for limit, expected_flag, expected_size in (
            (0, WRITE_REJECTED_RLIMIT, 0),
            (1, WRITE_COMMITTED, 1),
            (U64_MAX, WRITE_COMMITTED, 3),
        ):
            authority = Authority()
            frozen = FrozenWrite(3, True, 0, limit, S64_MAX)
            authority.begin(1, frozen)
            authority.data(1, 0, b"abc")
            reply = authority.commit(1, 3)
            self.assertEqual(reply.flags, expected_flag)
            self.assertEqual(len(authority.contents), expected_size)

    def test_malformed_rejections_never_become_definite(self) -> None:
        malformed = (
            WriteReply(2, flags=WRITE_REJECTED, error=0),
            WriteReply(2, committed_size=1, flags=WRITE_REJECTED,
                       error=-errno.ENOSPC),
            WriteReply(2, flags=WRITE_REJECTED | WRITE_COMMITTED,
                       error=-errno.ENOSPC),
            WriteReply(3, flags=WRITE_REJECTED, error=-errno.ENOSPC),
        )
        for reply in malformed:
            with self.assertRaises(ProtocolError):
                validate_write_reply(reply, 2, WRITE_COMMITTED)

    def test_postapply_is_committed_and_must_publish(self) -> None:
        reply = WriteReply(
            4,
            committed_size=3,
            assigned_offset=10,
            post_size=13,
            sequence=8,
            flags=WRITE_COMMITTED | WRITE_POSTAPPLY,
            error=-errno.ENOSPC,
        )
        self.assertEqual(validate_write_reply(reply, 4, WRITE_COMMITTED),
                         "postapply")

    def test_zero_byte_postapply_publishes_attrs_without_position(self) -> None:
        reply = WriteReply(
            txid=19,
            committed_size=0,
            assigned_offset=0,
            post_size=4096,
            sequence=8,
            flags=WRITE_COMMITTED | WRITE_POSTAPPLY,
            error=-errno.EIO,
        )
        self.assertEqual(validate_write_reply(reply, 19, WRITE_COMMITTED),
                         "postapply")
        for bad in (
            dataclasses.replace(reply, assigned_offset=1),
            dataclasses.replace(reply, flags=WRITE_COMMITTED, error=0),
            dataclasses.replace(reply, sequence=0),
        ):
            with self.assertRaises(ProtocolError):
                validate_write_reply(bad, 19, WRITE_COMMITTED)

    def test_concurrent_append_stress_has_no_overlap(self) -> None:
        authority = Authority()
        expected: set[bytes] = set()
        expected_lock = threading.Lock()
        failures: list[BaseException] = []

        def writer(machine: int) -> None:
            try:
                for index in range(250):
                    payload = f"{machine:02d}:{index:04d}\n".encode()
                    txid = machine * 1000 + index + 1
                    frozen = FrozenWrite(len(payload), True, 0,
                                         U64_MAX, S64_MAX)
                    authority.begin(txid, frozen)
                    cut = 1 + index % (len(payload) - 1)
                    authority.data(txid, 0, payload[:cut])
                    authority.data(txid, cut, payload[cut:])
                    authority.commit(txid, len(payload))
                    with expected_lock:
                        expected.add(payload)
            except BaseException as exc:  # pragma: no cover - diagnostic
                failures.append(exc)

        threads = [threading.Thread(target=writer, args=(m,)) for m in range(8)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        self.assertFalse(failures)
        records = bytes(authority.contents).splitlines(keepends=True)
        self.assertEqual(len(records), 2000)
        self.assertEqual(set(records), expected)
        self.assertEqual(authority.sequence, 2000)


class PublicationAndNotifyTests(unittest.TestCase):
    def test_readdirplus_link_failure_drains_or_terminalizes_the_page(
        self,
    ) -> None:
        nodeids = (101, 102, 103, 104)

        success = parse_marked_dirplus_page(nodeids)
        self.assertEqual(success.linked, nodeids)
        self.assertEqual(success.force_forgotten, ())
        self.assertEqual(success.session_released, ())

        failed = parse_marked_dirplus_page(nodeids, link_failure=1)
        self.assertEqual(failed.linked, (101,))
        self.assertEqual(failed.force_forgotten, (102, 103, 104))
        self.assertEqual(failed.session_released, (101,))
        self.assertEqual(
            set(failed.force_forgotten) | set(failed.session_released),
            set(nodeids),
        )

        malformed = parse_marked_dirplus_page(
            nodeids, link_failure=1, malformed_tail=3
        )
        self.assertEqual(malformed.force_forgotten, (102, 103))
        self.assertEqual(
            set(malformed.force_forgotten) | set(malformed.session_released),
            set(nodeids),
        )

        teardown = parse_marked_dirplus_page(
            nodeids, link_failure=1, teardown_during_drain=True
        )
        self.assertEqual(teardown.force_forgotten, (102,))
        self.assertEqual(
            set(teardown.force_forgotten) | set(teardown.session_released),
            set(nodeids),
        )

    def test_attr_repair_installs_exact_state_without_an_inexact_interval(
        self,
    ) -> None:
        immutable = STATX_ATTR_IMMUTABLE
        inode = KernelInode()
        self.assertEqual(
            inode.install_stamped_attr(1, 1, immutable, 111, 0o644, 1000),
            "applied",
        )
        self.assertTrue(inode.permission(0o400))
        self.assertEqual((inode.inode_flags, inode.birth_time_ns),
                         (immutable, 111))

        self.assertEqual(
            strict_notify(
                "PFS_ATTR", inode, sequence=2, inode_flags=0,
                birth_time_ns=222, mode=0o700, uid=2000,
            ),
            "dispatched",
        )
        self.assertEqual(inode.object_version, 2)
        self.assertFalse(inode.permission(0o040))
        self.assertTrue(inode.remote_execute_permission())
        self.assertEqual(inode.audit_snapshot(), (2000, 0o700, 0))
        self.assertTrue(inode.lsm_owner_rule(2000))
        self.assertTrue(inode.coredump_safe(2000))
        self.assertEqual(
            inode.install_stamped_attr(1, 2, immutable, 111), "old"
        )

        self.assertEqual(
            strict_notify(
                "PFS_ATTR", inode, sequence=3, inode_flags=immutable,
                birth_time_ns=333, mode=0o644, uid=3000,
            ),
            "dispatched",
        )
        self.assertEqual(
            (inode.object_version, inode.inode_flags, inode.uid),
            (3, immutable, 3000),
        )
        self.assertFalse(inode.lsm_owner_rule(2000))
        self.assertFalse(inode.coredump_safe(2000))

        # A namespace-only COMPLETE may carry an unchanged exact object whose
        # version predates the outer visibility stamp.
        self.assertEqual(
            strict_notify(
                "PFS_ATTR", inode, sequence=5, record_version=4,
                inode_flags=0, birth_time_ns=444, mode=0o600, uid=4000,
            ),
            "dispatched",
        )
        self.assertEqual((inode.object_version, inode.uid), (4, 4000))

    def test_size_repair_invalidates_data_and_installs_the_same_exact_record(
        self,
    ) -> None:
        inode = KernelInode(size=10)
        self.assertEqual(
            strict_notify(
                "PFS_SIZE", inode, sequence=4, exact_size=20,
                inode_flags=STATX_ATTR_NODUMP, birth_time_ns=444,
                mode=0o600, uid=4000,
            ),
            "dispatched",
        )
        self.assertEqual((inode.size, inode.sequence, inode.cache_generation),
                         (20, 4, 1))
        self.assertEqual(
            (inode.object_version, inode.inode_flags, inode.birth_time_ns,
             inode.mode, inode.uid),
            (4, STATX_ATTR_NODUMP, 444, 0o600, 4000),
        )

    def test_synchronous_statx_fill_uses_installed_exact_record(self) -> None:
        inode = KernelInode()
        flags = STATX_ATTR_NODUMP | STATX_ATTR_IMMUTABLE
        self.assertEqual(
            strict_notify(
                "PFS_ATTR", inode, sequence=7, inode_flags=flags,
                birth_time_ns=1_725_000_000_123,
            ),
            "dispatched",
        )
        self.assertEqual(
            inode.fill_exact_statx(),
            {
                "birth_time_ns": 1_725_000_000_123,
                "attributes": flags,
                "attributes_mask": PFS_STATX_ATTRIBUTES,
            },
        )

    def test_strict_reverse_notify_whitelist_blocks_cache_injection(self) -> None:
        inode = KernelInode(size=11)
        parent = KernelInode(is_dir=True)
        queued_replies: list[str] = []
        before = (inode.size, inode.sequence, inode.cache_generation)

        for forbidden in (
            "INVAL_INODE",
            "INVAL_ENTRY",
            "DELETE",
            "STORE",
            "RETRIEVE",
            "POLL",
            "RESEND",
            "FUTURE",
        ):
            with self.assertRaises(ProtocolError):
                strict_notify(forbidden, inode)
        self.assertEqual(
            (inode.size, inode.sequence, inode.cache_generation), before
        )
        self.assertEqual(queued_replies, [])

        self.assertEqual(strict_notify("PFS_SIZE", inode), "dispatched")
        self.assertEqual(strict_notify("PFS_ATTR", inode), "dispatched")
        self.assertEqual(
            strict_notify("PFS_ENTRY", parent, child=0, flags=0),
            "dispatched",
        )
        self.assertEqual((inode.size, inode.sequence), (11, 1))

    def test_stamped_reverse_repairs_require_exact_shape_and_shared_target(
        self,
    ) -> None:
        shared_file = KernelInode(size=4096)
        shared_dir = KernelInode(is_dir=True)
        local_file = KernelInode(size=4096, pfs_class="local")
        local_dir = KernelInode(pfs_class="local", is_dir=True)

        for code, target in (
            ("PFS_SIZE", local_file),
            ("PFS_ATTR", local_file),
            ("PFS_ENTRY", local_dir),
        ):
            with self.assertRaises(ProtocolError):
                strict_notify(code, target)
        for code in STRICT_NOTIFY_CODES:
            kwargs = {"child": 0} if code == "PFS_ENTRY" else {}
            self.assertEqual(strict_notify(code, None, **kwargs), "absent")

        for code in STRICT_NOTIFY_CODES:
            with self.assertRaises(ProtocolError):
                strict_notify(code, None, nodeid=0)
        for code in STRICT_NOTIFY_CODES:
            with self.assertRaises(ProtocolError):
                strict_notify(code, None, sequence=0)
        with self.assertRaises(ProtocolError):
            strict_notify("PFS_ENTRY", None, child=1, flags=0)
        with self.assertRaises(ProtocolError):
            strict_notify("PFS_ENTRY", None, child=0, flags=1)
        self.assertEqual(strict_notify("PFS_ATTR", None, nodeid=987654), "absent")

        for malformed in (b"", b".", b"..", b"a/b", b"a\0b"):
            with self.assertRaises(ProtocolError):
                strict_notify(
                    "PFS_ENTRY", shared_dir, name=malformed, child=0, flags=0
                )
        self.assertEqual(
            strict_notify(
                "PFS_ENTRY", shared_dir, name=b"\xff", child=0, flags=0
            ),
            "dispatched",
        )

        local_graft = KernelInode(pfs_class="local", nodeid=77)
        before = (
            shared_dir.cache_generation,
            local_graft.nlink,
            local_graft.pfs_class,
        )
        for child, flags in ((0, 0), (local_graft.nodeid, 1)):
            with self.assertRaises(ProtocolError):
                strict_notify(
                    "PFS_ENTRY",
                    shared_dir,
                    child=child,
                    flags=flags,
                    resident_child=local_graft,
                )
            self.assertEqual(
                (
                    shared_dir.cache_generation,
                    local_graft.nlink,
                    local_graft.pfs_class,
                ),
                before,
            )

        shared_child = KernelInode(nodeid=88)
        before = (shared_dir.cache_generation, shared_child.nlink)
        with self.assertRaises(ProtocolError):
            strict_notify(
                "PFS_ENTRY",
                shared_dir,
                child=89,
                flags=1,
                resident_child=shared_child,
            )
        self.assertEqual(
            (shared_dir.cache_generation, shared_child.nlink), before
        )

        strict_notify(
            "PFS_ENTRY",
            shared_dir,
            child=shared_child.nodeid,
            flags=1,
            resident_child=shared_child,
        )
        self.assertEqual(shared_dir.cache_generation, before[0] + 1)
        self.assertEqual(
            shared_child.nlink,
            before[1],
            "peer repair expires the binding but does not synthesize a local unlink",
        )

    def test_create_snapshots_every_gate_before_installing_parent(self) -> None:
        versions = {"parent": 0, "child": 0}
        snapshot_sequence = 7
        records = {"parent": 7, "child": 7}

        # Step 3 is a transaction-wide snapshot. Installing the parent before
        # comparing the dentry gate would make this create reject its own name
        # because the dentry cursor equals the parent record's version.
        prior = dict(versions)
        attr_install = {
            identity: version > prior[identity]
            for identity, version in records.items()
        }
        entry_install = snapshot_sequence > prior["parent"]
        for identity, install in attr_install.items():
            if install:
                versions[identity] = records[identity]

        self.assertEqual(versions, records)
        self.assertTrue(entry_install)

    def test_revocation_withdrawal_drops_pages_without_taking_a_sequence(
        self,
    ) -> None:
        inode = KernelInode(size=6)
        self.assertEqual(inode.exact_data(6, 4), "applied")
        before = (inode.size, inode.sequence, inode.cache_generation)

        inode.withdraw_data()
        self.assertEqual((inode.size, inode.sequence), before[:2])
        self.assertEqual(inode.cache_generation, before[2] + 1)

        # A publication that was already in flight when the mount revoked is
        # still installable afterwards, because the withdrawal took no sequence.
        self.assertEqual(inode.exact_data(6, 5), "applied")

        local = KernelInode(pfs_class="local")
        with self.assertRaises(ProtocolError):
            local.withdraw_data()

    def test_shared_splice_reads_reuse_a_barrier_withdrawn_page_cache(
        self,
    ) -> None:
        """filemap_splice_read on a SHARED handle, with exact withdrawal.

        The splice used to be forced through copy_splice_read so a SHARED
        handle could neither populate nor consume the page cache.  It now uses
        the ordinary filemap path: reuse is what the retained cache is for, and
        the same ordered DATA publication that withdraws a read(2) folio
        withdraws a spliced one, because both live in the one mapping the
        publication invalidates.

        The payload lengths are deliberately equal across the overwrite.  A
        withdrawal driven by an EOF delta would do nothing here; only the
        sequence-ordered whole-mapping invalidation is enough.
        """
        authority = {"contents": b"before", "fuse_reads": 0}
        cached: bytes | None = None
        inode = KernelInode(size=len(authority["contents"]))

        def splice_read() -> bytes:
            nonlocal cached
            if cached is None:
                authority["fuse_reads"] += 1
                cached = authority["contents"]
            return cached

        def exact_data(size: int, sequence: int) -> str:
            nonlocal cached
            outcome = inode.exact_data(size, sequence)
            if outcome == "applied":
                cached = None
            return outcome

        self.assertEqual(splice_read(), b"before")
        self.assertEqual(splice_read(), b"before")
        self.assertEqual(authority["fuse_reads"], 1)

        authority["contents"] = b"after!"
        self.assertEqual(len(authority["contents"]), 6)
        self.assertEqual(exact_data(len(authority["contents"]), 1), "applied")
        self.assertIsNone(cached)
        self.assertEqual(splice_read(), b"after!")
        self.assertEqual(splice_read(), b"after!")
        self.assertEqual(authority["fuse_reads"], 2)
        self.assertEqual((inode.size, inode.sequence), (6, 1))

    def test_splice_child_scope_publishes_without_finishing_parent(self) -> None:
        parent = {
            "active": True,
            "tokens": ["outer-operation"],
        }
        child = {
            "active": True,
            "parent": parent,
            "tokens": ["splice-fragment"],
        }
        published: list[str] = []

        # An always-child splice scope cuts this transaction before another
        # write_iter may run, while restoring the compatible outer scope.
        published.extend(child["tokens"])
        child["tokens"].clear()
        child["active"] = False
        current = child["parent"]

        self.assertEqual(published, ["splice-fragment"])
        self.assertIs(current, parent)
        self.assertTrue(parent["active"])
        self.assertEqual(parent["tokens"], ["outer-operation"])

    def test_physical_reply_is_not_publication_boundary(self) -> None:
        gate = PublicationGate()
        gate.original_reply()
        self.assertFalse(gate.gate_released)
        gate.kernel_publish_request()
        self.assertFalse(gate.gate_released)
        gate.daemon_ack_written()
        self.assertTrue(gate.gate_released)

    def test_publish_can_arrive_before_daemon_reply_callback(self) -> None:
        gate = PublicationGate()
        gate.original_reply()
        # Kernel request wakeup may beat the daemon's ReplyWritten callback.
        gate.kernel_publish_request()
        gate.daemon_ack_written()
        self.assertTrue(gate.ack_physically_written)

    def test_exact_size_sequence_and_same_eof_invalidation(self) -> None:
        inode = KernelInode(size=10)
        self.assertEqual(inode.exact_data(10, 1), "applied")
        self.assertEqual(inode.cache_generation, 1)
        self.assertEqual(inode.exact_data(10, 1), "duplicate")
        self.assertEqual(inode.cache_generation, 1)
        self.assertEqual(inode.exact_data(10, 2), "applied")
        self.assertEqual(inode.cache_generation, 2)
        self.assertEqual(inode.exact_data(4, 3), "applied")
        self.assertEqual(inode.exact_data(99, 2), "old")
        with self.assertRaises(ProtocolError):
            inode.exact_data(5, 3)

    def test_fifo_lower_source_higher_proof(self) -> None:
        inode = KernelInode(size=100)
        self.assertEqual(inode.exact_data(80, 10), "applied")
        # Source SETATTR/O_TRUNC owns the FIFO after all lower COMPLETE ACKs.
        inode.size = 20
        # A later peer PREPARE waits for source PUBLISH and has a higher seq.
        self.assertEqual(inode.exact_data(60, 11), "applied")
        self.assertEqual((inode.size, inode.sequence), (60, 11))
        self.assertEqual(inode.exact_data(999, 9), "old")


class FallocateTests(unittest.TestCase):
    def test_closed_mode_set(self) -> None:
        self.assertEqual(len(VALID_FALLOCATE_MODES), 9)
        invalid = (
            FALLOC_PUNCH,
            FALLOC_COLLAPSE | FALLOC_KEEP,
            FALLOC_INSERT | FALLOC_KEEP,
            FALLOC_ZERO | FALLOC_UNSHARE,
            0x04,
            0x80,
        )
        for mode in invalid:
            self.assertNotIn(mode, VALID_FALLOCATE_MODES)

    def test_mode_specific_exact_sizes(self) -> None:
        old, off, length = 16384, 4096, 4096
        expected = {
            0: old,
            FALLOC_KEEP: old,
            FALLOC_PUNCH | FALLOC_KEEP: old,
            FALLOC_ZERO: old,
            FALLOC_ZERO | FALLOC_KEEP: old,
            FALLOC_COLLAPSE: old - length,
            FALLOC_INSERT: old + length,
            FALLOC_UNSHARE: old,
            FALLOC_UNSHARE | FALLOC_KEEP: old,
        }
        for mode, size in expected.items():
            self.assertEqual(fallocate_expected_size(mode, old, off, length),
                             size)
        self.assertEqual(fallocate_expected_size(0, 1, 4096, 4096), 8192)
        self.assertEqual(
            fallocate_expected_size(FALLOC_UNSHARE, 1, 4096, 4096), 8192
        )
        self.assertEqual(
            fallocate_expected_size(FALLOC_UNSHARE | FALLOC_KEEP,
                                     1, 4096, 4096),
            1,
        )

    def test_collapse_and_insert_authoritative_eof_rules(self) -> None:
        with self.assertRaises(ValueError):
            fallocate_expected_size(FALLOC_COLLAPSE, 8192, 4096, 4096)
        with self.assertRaises(ValueError):
            fallocate_expected_size(FALLOC_INSERT, 4096, 4096, 4096)

    def test_clean_collapse_reply_proves_strict_end_before_old_eof(self) -> None:
        validate_clean_fallocate_shape(
            FALLOC_COLLAPSE, 4096, 4096, 8192, U64_MAX, S64_MAX
        )
        for impossible_post_size in (0, 4096):
            with self.assertRaises(ProtocolError):
                validate_clean_fallocate_shape(
                    FALLOC_COLLAPSE, 4096, 4096, impossible_post_size,
                    U64_MAX, S64_MAX
                )

    def test_clean_collapse_reply_proves_pre_eof_within_file_max(self) -> None:
        file_max = 16384
        length = 4096
        validate_clean_fallocate_shape(
            FALLOC_COLLAPSE, 4096, length, file_max - length,
            U64_MAX, file_max,
        )
        with self.assertRaises(ProtocolError):
            validate_clean_fallocate_shape(
                FALLOC_COLLAPSE, 4096, length, file_max - length + 1,
                U64_MAX, file_max,
            )

    def test_rlimit_proof_uses_authoritative_pre_size(self) -> None:
        validate_fallocate_rlimit_proof(
            FALLOC_INSERT, 4096, 4096, 17000, 1 << 20, 16384
        )
        validate_fallocate_rlimit_proof(0, 8192, 4096, 10000, 1 << 20, 8192)
        validate_fallocate_rlimit_proof(
            FALLOC_UNSHARE, 8192, 4096, 10000, 1 << 20, 8192
        )
        invalid = (
            (FALLOC_COLLAPSE, 0, 4096, 1, 1 << 20, 8192),
            (FALLOC_KEEP, 0, 4096, 1, 1 << 20, 0),
            (FALLOC_INSERT, 16384, 4096, 17000, 1 << 20, 16384),
            (0, 0, 4096, 4096, 1 << 20, 8192),
            (0, 8192, 4096, U64_MAX, 1 << 20, 8192),
        )
        for args in invalid:
            with self.assertRaises(ProtocolError):
                validate_fallocate_rlimit_proof(*args)

    def test_xfs_alignment_and_structure_precede_rlimit(self) -> None:
        args = dict(
            mode=FALLOC_INSERT,
            pre_size=16384,
            offset=1,
            length=4096,
            rlimit=1,
            file_max=1 << 20,
            allocation_unit=4096,
        )
        self.assertEqual(xfs_fallocate_precheck(**args), "EINVAL_ALIGNMENT")
        args["offset"] = 16384
        self.assertEqual(xfs_fallocate_precheck(**args), "EINVAL_EOF")
        args["offset"] = 4096
        self.assertEqual(xfs_fallocate_precheck(**args), "EFBIG_RLIMIT")
        args.update(pre_size=(1 << 20) - 4096, rlimit=U64_MAX)
        self.assertEqual(xfs_fallocate_precheck(**args), "OK")
        args["length"] = 8192
        self.assertEqual(xfs_fallocate_precheck(**args), "EFBIG_FILEMAX")

    def test_fallocate_rlimit_reply_is_only_rejection_with_pre_size(self) -> None:
        reply = RangeReply(
            post_size=16384,
            flags=RANGE_REJECTED_RLIMIT,
            error=-errno.EFBIG,
        )
        self.assertEqual(
            validate_range_reply(reply, allow_noop=False,
                                 fallocate_rlimit_pre_size=True),
            "rlimit",
        )
        with self.assertRaises(ProtocolError):
            validate_range_reply(reply, allow_noop=True,
                                 fallocate_rlimit_pre_size=False)

    def test_postdispatch_errno_accepts_partial_exact_eof(self) -> None:
        reply = RangeReply(
            post_size=4096,
            sequence=3,
            flags=RANGE_APPLIED | RANGE_POSTAPPLY,
            error=-errno.ENOSPC,
        )
        self.assertEqual(
            validate_range_reply(reply, allow_noop=False,
                                 fallocate_rlimit_pre_size=True),
            "postapply",
        )


class CopyRangeTests(unittest.TestCase):
    def test_authoritative_eof_clip_precedes_same_inode_overlap(self) -> None:
        data = b"x" * 100
        # Requested source [90,110) appears to overlap destination [105,125),
        # but authoritative EOF clips it to [90,100), so it is valid.
        self.assertEqual(cfr_result(data, 90, 105, 20, U64_MAX, S64_MAX, True),
                         ("applied", 10))
        self.assertEqual(cfr_result(data, 80, 90, 20, U64_MAX, S64_MAX, True),
                         ("overlap", 0))

    def test_zero_and_eof_noop_still_obey_output_limit_precedence(self) -> None:
        data = b"x" * 10
        self.assertEqual(cfr_result(data, 10, 5, 0, U64_MAX, 100, False),
                         ("noop", 0))
        self.assertEqual(cfr_result(data, 10, 5, 100, U64_MAX, 100, False),
                         ("noop", 0))
        self.assertEqual(cfr_result(data, 10, 10, 0, 10, 100, False),
                         ("rlimit", 0))
        self.assertEqual(cfr_result(data, 10, 100, 0, U64_MAX, 100, False),
                         ("filemax", 0))

    def test_malformed_noop_cannot_suppress_output_limits(self) -> None:
        validate_cfr_noop_limits(9, 10, 100)
        validate_cfr_noop_limits(99, U64_MAX, 100)
        for dst_offset, rlimit, file_max in (
            (10, 10, 100),
            (11, 10, 100),
            (100, U64_MAX, 100),
            (101, U64_MAX, 100),
        ):
            with self.assertRaises(ProtocolError):
                validate_cfr_noop_limits(dst_offset, rlimit, file_max)

    def test_cross_class_is_exdev_and_never_fallback(self) -> None:
        def route(src: str, dst: str) -> str:
            if src != dst:
                return "EXDEV"
            return "PFS_CFR" if src == "shared" else "LOCAL_CFR"

        self.assertEqual(route("shared", "shared"), "PFS_CFR")
        self.assertEqual(route("local", "local"), "LOCAL_CFR")
        self.assertEqual(route("shared", "local"), "EXDEV")
        self.assertEqual(route("local", "shared"), "EXDEV")

    def test_postapply_with_bytes_returns_positive_count(self) -> None:
        reply = RangeReply(
            result_size=4096,
            post_size=8192,
            sequence=7,
            flags=RANGE_APPLIED | RANGE_POSTAPPLY,
            error=-errno.ENOTCONN,
        )
        self.assertEqual(
            validate_range_reply(reply, allow_noop=True,
                                 fallocate_rlimit_pre_size=False),
            "postapply",
        )
        # Kernel returns this count after PUBLISH, never the retryable errno.
        self.assertEqual(reply.result_size, 4096)

    def test_zero_byte_postapply_publishes_attrs_and_returns_errno(self) -> None:
        reply = RangeReply(
            result_size=0,
            post_size=4096,
            sequence=8,
            flags=RANGE_APPLIED | RANGE_POSTAPPLY,
            error=-errno.EIO,
        )
        self.assertEqual(
            validate_range_reply(reply, allow_noop=True,
                                 fallocate_rlimit_pre_size=False),
            "postapply",
        )
        self.assertEqual(reply.error, -errno.EIO)
        with self.assertRaises(ProtocolError):
            validate_range_reply(
                dataclasses.replace(reply, flags=RANGE_APPLIED, error=0),
                allow_noop=True,
                fallocate_rlimit_pre_size=False,
            )


class NoFallbackTests(unittest.TestCase):
    def test_strict_daemon_enosys_is_centrally_fatal(self) -> None:
        mandatory = {
            "LOOKUP", "GETATTR", "SETATTR", "READLINK", "MKNOD",
            "MKDIR", "UNLINK", "RMDIR", "SYMLINK", "RENAME2", "LINK",
            "OPEN", "READ", "FLUSH", "RELEASE", "FSYNC", "OPENDIR",
            "READDIR", "RELEASEDIR", "FSYNCDIR", "GETLK", "SETLK",
            "SETLKW", "CREATE", "INTERRUPT", "GETXATTR", "LISTXATTR",
            "REMOVEXATTR", "FALLOCATE_LOCAL", "CFR_LOCAL", "SYNCFS",
            "TMPFILE", "PFS_WRITE", "PFS_FALLOCATE", "PFS_CFR",
            "PFS_PUBLISH",
        }
        local_or_predispatch = {"ACCESS", "POLL", "LSEEK", "SETXATTR",
                                "STATX", "READDIRPLUS", "IOCTL_SHARED"}
        self.assertFalse(mandatory & local_or_predispatch)
        self.assertIn("SYNCFS", mandatory)
        self.assertIn("INTERRUPT", mandatory)

    def test_stock_write_or_splice_cfr_on_shared_is_protocol_error(self) -> None:
        def shared_dispatch(opcode: str) -> str:
            if opcode in {"FUSE_WRITE", "COPY_FILE_SPLICE"}:
                raise ProtocolError
            return opcode

        for opcode in ("FUSE_WRITE", "COPY_FILE_SPLICE"):
            with self.assertRaises(ProtocolError):
                shared_dispatch(opcode)

    def test_splice_prior_prefix_survives_later_preapply_error(self) -> None:
        def final_result(prefix: int, later_error: int,
                         publish_failed_after_apply: bool) -> int:
            if prefix and not publish_failed_after_apply:
                return prefix
            return later_error

        for later_error in (-errno.ENOMEM, -errno.EFAULT, -errno.ENOSPC,
                            -errno.ENOTCONN):
            self.assertEqual(final_result(65536, later_error, False), 65536)
        self.assertEqual(final_result(65536, -errno.ENOTCONN, True),
                         -errno.ENOTCONN)


if __name__ == "__main__":
    unittest.main(verbosity=2)
