#!/usr/bin/env python3
"""Positive structural checks of the current PortableFS architecture.

Each check asserts what the tree must contain now: the exact protocol
versions, the frontend profile set, the shape of both schemas, the shared
fixtures, the production wiring between components, and that maintained
documentation agrees with the code and links only to files that exist. None of
them scans for retired identifiers. A retired mechanism cannot come back
without breaking one of these assertions, because the assertions describe the
complete current shape rather than a list of names that must stay absent.

The expected values below are the architecture manifest. Changing one is a
deliberate contract change: it must land with the code and with
COMPATIBILITY.md in the same change.

  python3 scripts/check-current-architecture.py           # run every check
  python3 scripts/check-current-architecture.py --list    # name the checks
  python3 scripts/check-current-architecture.py --only authority-version

Standard library only; Python 3.9 or newer.
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import subprocess
import sys
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Set, Tuple

ROOT = pathlib.Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# The architecture manifest.
# ---------------------------------------------------------------------------

AUTHORITY_MAJOR = 8
AUTHORITY_PACKAGE = "portablefs.authority.v1"
PFSLOCAL_VERSION = (2, 0)
PFSLOCAL_PACKAGE = "pfslocal.v1"
CONTROL_PROTOCOL = 2
CONTROL_HEADER = "X-PortableFS-Control-Protocol"
LIFECYCLE_PROTOCOL = 1
IDENTITY_SCHEMA = 1
LIFECYCLE_PATHS = (
    "/lifecycle/v1/identity",
    "/lifecycle/v1/inventory",
    "/lifecycle/v1/stop-if-idle",
)
MEMBERSHIP_FILENAME = "mount.membership"
MEMBERSHIP_HEADER = "PFS-MEMBERSHIP-1"
MEMBERSHIP_PROFILES = ("linux", "fskit-exclusive", "cacheless")
FUSE_FLOOR = (7, 31)
AUTHORITY_KERNEL_FLOOR = (5, 17)

FRONTEND_PROFILES = (
    ("FRONTEND_PROFILE_UNSPECIFIED", 0),
    ("FRONTEND_PROFILE_LINUX", 1),
    ("FRONTEND_PROFILE_FSKIT_EXCLUSIVE", 2),
    ("FRONTEND_PROFILE_CACHELESS_READER", 3),
)

# The handshake messages carry the whole session contract. Their exact field
# sets are pinned here as well as in the generated descriptor manifest so that
# the shape of the handshake is reviewed as architecture, not only as codegen.
HANDSHAKE_FIELDS = {
    "HelloRequest": {"protocol_major": 1, "role": 3, "connection_set_id": 4, "frontend_profile": 10},
    "HelloReply": {
        "protocol_major": 1,
        "max_frame_bytes": 3,
        "max_read_bytes": 4,
        "max_write_bytes": 5,
        "max_in_flight": 6,
        "role": 7,
        "connection_set_id": 8,
        "frontend_profile": 10,
    },
    "AttachRequest": {
        "volume_id": 1,
        "access_token": 2,
        "replay_slots": 4,
        "routes_revision": 8,
        "attach_attempt_id": 10,
        "purpose": 11,
        "frontend_profile": 12,
    },
    "ActivateRequest": {"attach_attempt_id": 1, "data_binding_generation": 2, "control_binding_generation": 3},
    "ActivateReply": {
        "root": 1,
        "session_lease_milliseconds": 3,
        "routes_revision": 5,
        "authorization_deadline_unix_nanos": 6,
        "state": 7,
        "purpose": 9,
        "frontend_profile": 10,
    },
    "MkdirReply": {"item": 1, "child_search_permitted": 2},
}

# The complete private frontend grammar: every Envelope body arm, the bound
# Resolve result, and the numeric capability limits.
PFSLOCAL_ENVELOPE_BODY = {
    "hello": 10, "resolve": 11, "lookup": 12, "get_attr": 14, "set_attr": 15,
    "open": 16, "close": 17, "read": 18, "write": 19, "create": 20, "mkdir": 21,
    "remove": 22, "rename": 23, "symlink": 24, "readlink": 25, "xattr_get": 26,
    "xattr_list": 28, "xattr_remove": 29, "statfs": 30, "reclaim": 32,
    "subscribe_events": 33, "hard_link": 34, "sync_volume": 35,
    "publication_ack": 36, "resource_reply_disposition": 39,
    "enumerate_entries": 40,
    "hello_reply": 60, "resolve_reply": 61, "lookup_reply": 62,
    "get_attr_reply": 64, "set_attr_reply": 65, "open_reply": 66,
    "close_reply": 67, "read_reply": 68, "write_reply": 69, "create_reply": 70,
    "mkdir_reply": 71, "remove_reply": 72, "rename_reply": 73,
    "symlink_reply": 74, "readlink_reply": 75, "xattr_get_reply": 76,
    "xattr_list_reply": 78, "xattr_remove_reply": 79, "statfs_reply": 80,
    "reclaim_reply": 82, "subscribe_events_reply": 83, "hard_link_reply": 84,
    "sync_volume_reply": 85, "enumerate_entries_reply": 88,
    "error": 90, "event": 91,
}
PFSLOCAL_RESOLVE_REPLY = {"root": 1, "root_attr": 2, "volume_id": 3, "volume_name": 5, "capabilities": 6}
PFSLOCAL_CAPABILITIES = {"max_name_bytes": 5, "max_file_size": 6, "preferred_io_bytes": 7}

# Every product executable. A new command is an intentional review event.
PRODUCT_COMMANDS = {
    "portablefs",
    "portablefs-archiver",
    "portablefs-authority",
    "portablefs-authority-launcher",
    "portablefs-cell-agent",
    "portablefs-cell-helper",
    "portablefs-files",
    "portablefs-hydrator",
    "portablefs-manager",
    "portablefs-mount-v3",
    "portablefsd",
    "portablefs-workspaced",
}
GO_MODULES = {"vcs/go.mod", "vcs/third_party/go-fuse/go.mod"}
SWIFT_PACKAGES = {"swift/PortableFSKit/Package.swift"}
SWIFT_ROOTS = {"PortableFSApp", "PortableFSKit", "PortableFSKitDev", "README.md"}
XCODE_PROJECTS = {
    "swift/PortableFSApp/PortableFSApp.xcodeproj",
    "swift/PortableFSKitDev/PortableFSKitDev.xcodeproj",
}
# The repository carries no JavaScript packages. The npm soak workload's
# manifest is test input, not a package of this repository.
JAVASCRIPT_MANIFEST_ROOT = "vcs/test/soak/testdata/"

# Which production frontend may name which authority profile. The authority
# and the generated binding are the only owners of the whole enum; every other
# production package either names exactly its own profile or none.
PROFILE_OWNERS = (
    "vcs/internal/authorityrpc/",
    "vcs/internal/authoritypb/",
    "vcs/internal/volumeserver/",
)
PROFILE_FRONTENDS = {
    "vcs/internal/mountv3/": {"FRONTEND_PROFILE_LINUX"},
    "vcs/cmd/portablefs-mount-v3/": {"FRONTEND_PROFILE_LINUX"},
    "vcs/internal/portablefsd/": {"FRONTEND_PROFILE_FSKIT_EXCLUSIVE"},
    "vcs/readonlyfs/": {"FRONTEND_PROFILE_CACHELESS_READER"},
}
# Packages that may select a frontend's profile on its behalf without being
# required to (the CLI launches the Linux mount in-process).
PROFILE_OPTIONAL = {
    "vcs/cmd/portablefs/": {"FRONTEND_PROFILE_LINUX", "FRONTEND_PROFILE_FSKIT_EXCLUSIVE"},
    "vcs/test/": {"FRONTEND_PROFILE_LINUX", "FRONTEND_PROFILE_FSKIT_EXCLUSIVE", "FRONTEND_PROFILE_CACHELESS_READER"},
    "vcs/internal/tierede2e/": {"FRONTEND_PROFILE_LINUX"},
    "vcs/bench/": {"FRONTEND_PROFILE_LINUX", "FRONTEND_PROFILE_FSKIT_EXCLUSIVE", "FRONTEND_PROFILE_CACHELESS_READER"},
}

# The three package-owned privileged inventories the XFS/FUSE suite enforces.
REQUIRED_TEST_LISTS = (
    "scripts/xfs-required-authority-tests.txt",
    "scripts/xfs-required-fuse-tests.txt",
    "scripts/xfs-required-tiered-tests.txt",
)

# The privileged suite's root invocation: the cell helper's root-owned volume
# provisioning proved against real XFS project quota, and the shared-cell
# writeback-domain fault proof, and the FUSE probe's private-mount-namespace
# prerequisite proof, plus the root-owned workspace gate and its complete
# entry/publication inventory. The invocation is provisioned for exactly these
# packages, so every root entry must name a top-level test in one of them.
ROOT_TEST_PACKAGES = {
    "github.com/steerlabs/portablefs/vcs/cmd/portablefs/internal/cli",
    "github.com/steerlabs/portablefs/vcs/internal/cellhost",
    "github.com/steerlabs/portablefs/vcs/internal/xfsstore",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3",
    "github.com/steerlabs/portablefs/vcs/internal/workspaceclock",
    "github.com/steerlabs/portablefs/vcs/internal/workspacemount",
    "github.com/steerlabs/portablefs/vcs/internal/workspaceadmission",
}
ROOT_REQUIRED = {
  "github.com/steerlabs/portablefs/vcs/internal/workspacemount:TestRootLocalConnectChargesSaturatedBacklog",
  "github.com/steerlabs/portablefs/vcs/internal/workspacemount:TestRootRecreatesOnlyProtectedColdTarget",
    "github.com/steerlabs/portablefs/vcs/internal/workspacemount:TestRootStableBackingAndAcknowledgedMetadata",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceFinalizationRetainsTerminalOutcomeAndRefusesCleanupDebt",
    "github.com/steerlabs/portablefs/vcs/cmd/portablefs/internal/cli:TestWorkspaceClockRefusalLatchesServingUntilFreshClosedPermit",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceClockDeniesEntryBeforeRootObservation",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceClockDeniesCapacityWaitBeforeRootObservation",
    "github.com/steerlabs/portablefs/vcs/cmd/portablefs/internal/cli:TestWorkspaceReconcileIndependentCommitsAndLostAcknowledgment",
    "github.com/steerlabs/portablefs/vcs/internal/workspacemount:TestRootLostInstallResponseKeepsOriginalFailedINITOwner",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestManagedKernelFailedINITRetainsExactRemovalOwner",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestManagedKernelRejectsForeignBootstrapDescriptions",
    "github.com/steerlabs/portablefs/vcs/internal/workspaceclock:TestSharedClockConcurrentCheckAndCloseJoinsReaders",
    "github.com/steerlabs/portablefs/vcs/internal/workspacemount:TestRootSuspendForwardsRemainingBudgetAndJoinsLocalOwner",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspacePersistenceFailureSurvivesPermitLoss",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceZeroEntryLossTicketRecorded",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceManagedResumePermitLoss",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceLifecycleDrainsAcceptedDirtyCut",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceFailedReleaseRetainsDurabilityOutcome",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspacePersistenceCannotPublishStaleClock",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceOvertakenColdRetainsLoss",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceRecoveryClassifiesTerminalEvidence",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceLifecycleControlCutDrainsAck",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceLifecycleJoinsInFlightRenewal",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceLifecycleColdRecover",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceLifecycleRetryBeyond45Seconds",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceColdFailureRetainsLossAndNotificationOwner",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceLifecycleCancellationKeepsPhysicalOwner",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceClosedFlushReobservesResetLoss",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestKernelWorkspaceControlledPause",
    "github.com/steerlabs/portablefs/vcs/internal/workspaceclock:TestSharedClockReadOnlyGenerationAndFreshness",
    "github.com/steerlabs/portablefs/vcs/internal/workspaceclock:TestSharedClockSeqlockCannotMixAuthorization",
    "github.com/steerlabs/portablefs/vcs/internal/workspaceclock:TestSharedClockChildCannotForgePage",
    "github.com/steerlabs/portablefs/vcs/internal/workspaceclock:TestSharedClockClosedOwnerAndIdempotentReaderClose",
    "github.com/steerlabs/portablefs/vcs/internal/workspacemount:TestIdentityPrivateToWorkspaceUser",
    "github.com/steerlabs/portablefs/vcs/internal/workspaceadmission:TestClosedStartAndExactPreparedCAS",
    "github.com/steerlabs/portablefs/vcs/internal/workspaceadmission:TestReadOnlyHandoffAndDescriptorSeals",
    "github.com/steerlabs/portablefs/vcs/internal/workspaceadmission:TestHandoffRejectsWritableOrUnboundDescriptors",
    "github.com/steerlabs/portablefs/vcs/internal/workspaceadmission:TestOwnerEOFIsIndependentAndPermanent",
    "github.com/steerlabs/portablefs/vcs/internal/workspaceadmission:TestStalledChildCloseAndSoleWriter",
    "github.com/steerlabs/portablefs/vcs/internal/workspaceadmission:TestCloseSerialExhaustionAndGenerationFloor",
    "github.com/steerlabs/portablefs/vcs/internal/workspaceadmission:TestRetireInterruptsOwnerReadWhileSupervisorLives",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceFastAnswersCloseBeforeServing",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceCachedReplyRollbackAndFixedCohort",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceEmptyPublicationsRetainOwner",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceLatePhysicalReadPurgesAfterWrite",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceClosedCleanupAndFlushUnlock",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceRecoveryAndDrainAreNotServing",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceCapacityWaitChecksActualAcceptance",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceScratchOpenLoopStopsOnClose",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceAcceptedCreateAndWriteKeepPhysicalOwner",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceInitialSubscribeLosesToPark",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceCloseAfterLastInstallationCheckIsInert",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceSlowHelperCannotInventServingAdmission",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceEveryGraftBranchChecksEntry",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceStaticRefusalsDoNotAcquireServingOwner",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceCloseHandoffReleasesEpochFenceBeforeQueueCapacity",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestKernelWorkspaceGateAndOwnerLifetime",
    "github.com/steerlabs/portablefs/vcs/internal/cellhost:TestProvisionedVolumeEnforcesXFSProjectQuotaAndConfinement",
    "github.com/steerlabs/portablefs/vcs/internal/xfsstore:TestSharedXFSWritebackDomain",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestKernelFUSEProbeRejectsHiddenFusectl",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR1CancelledRecoverThenSuspend",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR1CycleLeaks",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR1DuplicateSuspendAfterCold",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR1InterruptedInitialPrepareThenSuspend",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR1KernelChurn",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR1KernelClockReadiness",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR1KernelFrozenLeasePause",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR1KernelInterruptedRecover",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR1KernelLeaseExpiry",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR1KernelSessionExpired",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR1LookupAfterRecover",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR1LossAggregationLatchesFailure",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR1RetryAfterCanceledWithdrawal",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR1StickyAbandonedRefusesCold",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR2ClockFlapDuringRecover",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR2IncompleteSuspendThenLaterTransition",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR2KernelCancelledSleep",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR2KernelClockDiag",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR2KernelIncompleteSuspend",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR2PreparedUnservedReacknowledgeEvidence",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR3GateCloseBeforeFrameDuringPublication",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR3KernelLateApplyCoherence",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR3KernelLongGapAccounted",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR3KernelStressIntegrity",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceKernelAssignedWriteColdCut",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceKernelReadinessBudget10Seconds",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceKernelReadinessBudget45Seconds",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceKernelReparkResnapshotsRealCleanup",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceKernelUnassignedWriteColdCut",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceOvertakenBeforeInitialCut",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceOwnerCloseAtPermitBoundaries",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceCloseDuringRecoveryValidation",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceKernelReadinessReturnsDuringDrain",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceKernelRecoverCompletesCanceledCut",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceOwnerRenewalCutoffSurvivesClose",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceObservationTerminal",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceOwnerCloseDuringPublication",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspacePollFailureSurvivesPark",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspacePublicationRenewsAgedProofInOriginalJob",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceRealSemanticPollFailureSurvivesPark",
    "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceRetirementFenceIsUnsubmitted",
}

# The device-level power-cut harness must cover both durability contracts:
# fsync-gated Linux writes and every acknowledged FSKit mutation.
POWERLOSS_REQUIRED = {
    "TestFsyncedWritesSurvivePowerLoss",
    "TestFSKitAcknowledgedMutationsSurvivePowerLoss",
}
MODULE_PREFIX = "github.com/steerlabs/portablefs/"

# Executables whose command lines appear in scripts, docs and the launcher.
# Every flag those command lines pass must be one the executable defines.
FLAG_CONSUMERS = {
    "portablefs-authority": "vcs/cmd/portablefs-authority",
    "portablefs-mount-v3": "vcs/cmd/portablefs-mount-v3",
}

# Text that is not maintained by this repository.
VENDORED = ("vcs/third_party/",)


class CheckFailure(Exception):
    """One or more assertions of a check did not hold."""

    def __init__(self, problems: List[str]):
        super().__init__("\n".join(problems))
        self.problems = problems


# ---------------------------------------------------------------------------
# Tree access.
# ---------------------------------------------------------------------------


def read(relative: str) -> str:
    path = ROOT / relative
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        raise CheckFailure([f"{relative}: required file is missing"])


def tree_files() -> List[str]:
    """Tracked plus untracked-but-not-ignored files, repository-relative."""
    try:
        output = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
            check=True,
            capture_output=True,
        ).stdout
        files = [name for name in output.decode("utf-8").split("\0") if name]
    except (OSError, subprocess.CalledProcessError):
        files = []
        for directory, subdirectories, names in os.walk(ROOT):
            subdirectories[:] = [name for name in subdirectories if name != ".git"]
            for name in names:
                files.append(os.path.relpath(os.path.join(directory, name), ROOT))
    # A deleted-but-unstaged path is still listed by --cached; only existing
    # files describe the tree being checked.
    return sorted(name for name in set(files) if (ROOT / name).is_file())


_FILES: Optional[List[str]] = None


def files() -> List[str]:
    global _FILES
    if _FILES is None:
        _FILES = tree_files()
    return _FILES


def maintained(name: str) -> bool:
    return not name.startswith(VENDORED)


GENERATED = re.compile(r"^// Code generated .* DO NOT EDIT\.$", re.MULTILINE)


def production_go(prefix: str) -> Iterator[Tuple[str, str]]:
    """Non-test, non-generated Go sources below prefix."""
    for name in files():
        if not name.startswith(prefix) or not name.endswith(".go") or name.endswith("_test.go"):
            continue
        text = read(name)
        if GENERATED.search(text[:2048]):
            continue
        yield name, text


def go_const(text: str, name: str) -> Optional[str]:
    """The literal of a Go constant declared as `name = literal` or `name T = literal`."""
    match = re.search(rf"(?m)^\s*(?:const\s+)?{re.escape(name)}(?:\s+[A-Za-z0-9_.]+)?\s*=\s*(\"[^\"]*\"|[0-9]+)\s*(?://.*)?$", text)
    if not match:
        return None
    literal = match.group(1)
    return literal[1:-1] if literal.startswith('"') else literal


# ---------------------------------------------------------------------------
# Protobuf source parsing (only the subset these schemas use).
# ---------------------------------------------------------------------------


def strip_proto_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)
    return re.sub(r"//[^\n]*", "", text)


def proto_block(text: str, keyword: str, name: str) -> str:
    """Body of the first top-level `keyword name { ... }`, braces balanced."""
    match = re.search(rf"\b{keyword}\s+{re.escape(name)}\s*\{{", text)
    if not match:
        raise CheckFailure([f"{keyword} {name} is not declared"])
    depth = 1
    index = match.end()
    while depth and index < len(text):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
        index += 1
    return text[match.end():index - 1]


FIELD = re.compile(r"(?:repeated\s+)?[A-Za-z_][A-Za-z0-9_.]*\s+([a-z_][a-z0-9_]*)\s*=\s*([0-9]+)\s*;")


def proto_fields(block: str, *, include_nested: bool = False) -> Dict[str, int]:
    """Field name to number for one message body; nested declarations skipped."""
    if not include_nested:
        block = _drop_nested(block)
    fields: Dict[str, int] = {}
    for match in FIELD.finditer(block):
        fields[match.group(1)] = int(match.group(2))
    return fields


def _drop_nested(block: str) -> str:
    out = []
    depth = 0
    index = 0
    while index < len(block):
        nested = re.match(r"\s*(?:message|enum)\s+\w+\s*\{", block[index:]) if depth == 0 else None
        if nested:
            depth = 1
            index += nested.end()
            continue
        char = block[index]
        if depth:
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
        else:
            out.append(char)
        index += 1
    return "".join(out)


def proto_enum(block: str) -> List[Tuple[str, int]]:
    return [(m.group(1), int(m.group(2))) for m in re.finditer(r"([A-Z][A-Z0-9_]*)\s*=\s*([0-9]+)\s*;", block)]


def proto_oneof(block: str, name: str) -> Dict[str, int]:
    return proto_fields(proto_block(block, "oneof", name))


# ---------------------------------------------------------------------------
# Wire fixture decoding (protobuf varints, length-delimited fields).
# ---------------------------------------------------------------------------


def varint(data: bytes, offset: int) -> Tuple[int, int]:
    value = 0
    shift = 0
    while True:
        if offset >= len(data):
            raise ValueError("truncated varint")
        byte = data[offset]
        offset += 1
        value |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return value, offset
        shift += 7
        if shift > 63:
            raise ValueError("overlong varint")


def protobuf_fields(data: bytes) -> List[Tuple[int, int, object]]:
    """(field number, wire type, value) for one encoded message."""
    fields = []
    offset = 0
    while offset < len(data):
        key, offset = varint(data, offset)
        number, wire = key >> 3, key & 7
        if wire == 0:
            value, offset = varint(data, offset)
            fields.append((number, wire, value))
        elif wire == 2:
            length, offset = varint(data, offset)
            if offset + length > len(data):
                raise ValueError("truncated length-delimited field")
            fields.append((number, wire, data[offset:offset + length]))
            offset += length
        else:
            raise ValueError(f"unexpected wire type {wire}")
    return fields


def pfslocal_frame(hex_text: str) -> bytes:
    data = bytes.fromhex(hex_text.strip())
    if len(data) < 4:
        raise ValueError("frame shorter than its length prefix")
    length = int.from_bytes(data[:4], "little")
    if length != len(data) - 4:
        raise ValueError(f"length prefix {length} does not match {len(data) - 4} payload bytes")
    return data[4:]


def hello_version(envelope: bytes, body_field: int) -> Tuple[int, int]:
    for number, wire, value in protobuf_fields(envelope):
        if number == body_field and wire == 2:
            major = minor = 0
            for inner_number, inner_wire, inner in protobuf_fields(value):  # type: ignore[arg-type]
                if inner_number == 1 and inner_wire == 0:
                    major = int(inner)  # type: ignore[arg-type]
                if inner_number == 2 and inner_wire == 0:
                    minor = int(inner)  # type: ignore[arg-type]
            return major, minor
    raise ValueError(f"envelope has no body field {body_field}")


# ---------------------------------------------------------------------------
# Markdown links.
# ---------------------------------------------------------------------------

LINK = re.compile(r"(?<!\!)\[[^\]]*\]\(([^)\s]+)(?:\s+\"[^\"]*\")?\)")
FENCE = re.compile(r"^(```|~~~)")


def markdown_without_code(text: str) -> str:
    out = []
    fenced = False
    for line in text.splitlines():
        if FENCE.match(line.strip()):
            fenced = not fenced
            out.append("")
            continue
        out.append("" if fenced else re.sub(r"`[^`]*`", "", line))
    return "\n".join(out)


def heading_anchors(text: str) -> Set[str]:
    """GitHub-style heading slugs, with -1, -2 suffixes for repeats."""
    anchors: Set[str] = set()
    counts: Dict[str, int] = {}
    fenced = False
    for line in text.splitlines():
        if FENCE.match(line.strip()):
            fenced = not fenced
            continue
        if fenced:
            continue
        match = re.match(r"^#{1,6}\s+(.*?)\s*#*\s*$", line)
        if not match:
            continue
        title = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", match.group(1))
        slug = re.sub(r"[^\w\- ]", "", title.lower()).replace(" ", "-")
        count = counts.get(slug, 0)
        counts[slug] = count + 1
        anchors.add(slug if count == 0 else f"{slug}-{count}")
    return anchors


# ---------------------------------------------------------------------------
# Command-line flag extraction.
# ---------------------------------------------------------------------------

GO_FLAG = re.compile(
    r"\b(?:flag|fs|flags|set|flagSet)\.(?:String|Bool|Int|Int64|Uint|Uint64|Float64|Duration|Text)(?:Var)?\(\s*(?:&[^,]+,\s*)?\"([a-z][a-z0-9-]*)\""
)
GO_FLAG_VAR = re.compile(r"\b(?:flag|fs|flags|set|flagSet)\.(?:Var|Func|BoolFunc)\(\s*(?:[^,\"]+,\s*)?\"([a-z][a-z0-9-]*)\"")
SHELL_FLAG = re.compile(r"(?:^|\s)--?([a-z][a-z0-9-]*)(?==|\s|$)")


def defined_flags(directory: str) -> Set[str]:
    names: Set[str] = set()
    for _, text in production_go(directory + "/"):
        names.update(GO_FLAG.findall(text))
        names.update(GO_FLAG_VAR.findall(text))
    return names


def command_lines(text: str, executable: str) -> Iterator[Tuple[int, str]]:
    """(line number, joined command) for each invocation of executable.

    An invocation is a line naming the executable as a command word (not as a
    build path such as ./cmd/<name>, a unit name, or prose), joined with its
    backslash continuations.
    """
    lines = text.splitlines()
    word = re.compile(rf"(?:^|[\s/\"'])(?<!cmd/){re.escape(executable)}(?=\s+\\?$|\s+-)")
    index = 0
    while index < len(lines):
        line = lines[index]
        found = word.search(line)
        if found and "cmd/" + executable not in line:
            start = index
            joined = line.rstrip()
            while joined.endswith("\\") and index + 1 < len(lines):
                index += 1
                joined = joined[:-1] + " " + lines[index].strip()
            # The joined command begins with the first line unchanged, so the
            # executable's position there is its position in the whole command.
            yield start + 1, joined[found.end():]
        index += 1


# ---------------------------------------------------------------------------
# Checks.
# ---------------------------------------------------------------------------

CHECKS: List[Tuple[str, str, Callable[[], None]]] = []


def check(name: str, summary: str) -> Callable[[Callable[[], None]], Callable[[], None]]:
    def register(function: Callable[[], None]) -> Callable[[], None]:
        CHECKS.append((name, summary, function))
        return function

    return register


def require(problems: List[str], condition: bool, message: str) -> None:
    if not condition:
        problems.append(message)


def finish(problems: List[str]) -> None:
    if problems:
        raise CheckFailure(problems)


@check("authority-version", "authority major and ALPN are the exact current generation")
def check_authority_version() -> None:
    problems: List[str] = []
    text = read("vcs/internal/authorityrpc/protocol.go")
    major = go_const(text, "ProtocolMajor")
    alpn = go_const(text, "ProtocolALPN")
    require(problems, major == str(AUTHORITY_MAJOR), f"authorityrpc.ProtocolMajor is {major!r}, want {AUTHORITY_MAJOR}")
    require(problems, alpn == f"portablefs-authority-v{AUTHORITY_MAJOR}",
            f"authorityrpc.ProtocolALPN is {alpn!r}, want portablefs-authority-v{AUTHORITY_MAJOR}")
    finish(problems)


@check("authority-grammar", "authority schema holds only current declarations, four profiles and the exact handshake")
def check_authority_grammar() -> None:
    problems: List[str] = []
    source = strip_proto_comments(read("proto/authority/v1/authority.proto"))
    require(problems, re.search(rf"\bpackage\s+{re.escape(AUTHORITY_PACKAGE)}\s*;", source) is not None,
            f"authority.proto must declare package {AUTHORITY_PACKAGE}")
    require(problems, re.search(r"\breserved\b", source) is None,
            "authority.proto declares `reserved`; the schema holds only current declarations")
    profiles = proto_enum(proto_block(source, "enum", "FrontendProfile"))
    require(problems, profiles == list(FRONTEND_PROFILES), f"FrontendProfile is {profiles}, want {list(FRONTEND_PROFILES)}")
    for message, want in HANDSHAKE_FIELDS.items():
        got = proto_fields(proto_block(source, "message", message))
        require(problems, got == want, f"{message} fields are {got}, want {want}")
    response_body = proto_oneof(proto_block(source, "message", "Response"), "body")
    require(problems, response_body.get("mkdir") == 73, "Response.body must carry `MkdirReply mkdir = 73`")
    require(problems, re.search(r"\bMkdirReply\s+mkdir\s*=\s*73\s*;", source) is not None,
            "Response.mkdir must have type MkdirReply")

    manifest_path = "vcs/internal/authoritypb/testdata/protocol8-schema.json"
    try:
        manifest = json.loads(read(manifest_path))
    except json.JSONDecodeError as error:
        raise CheckFailure([f"{manifest_path}: invalid JSON: {error}"])
    require(problems, manifest.get("name") == "proto/authority/v1/authority.proto",
            f"{manifest_path} must describe proto/authority/v1/authority.proto")
    require(problems, manifest.get("package") == AUTHORITY_PACKAGE, f"{manifest_path} must describe package {AUTHORITY_PACKAGE}")

    def reserved(node: object) -> bool:
        if isinstance(node, dict):
            return any(key in ("reserved_range", "reserved_name") or reserved(value) for key, value in node.items())
        if isinstance(node, list):
            return any(reserved(value) for value in node)
        return False

    require(problems, not reserved(manifest), f"{manifest_path} records reserved ranges or names")
    enums = {entry.get("name"): entry for entry in manifest.get("enum_type", [])}
    manifest_profiles = [(value.get("name"), value.get("number", 0)) for value in enums.get("FrontendProfile", {}).get("value", [])]
    require(problems, manifest_profiles == list(FRONTEND_PROFILES),
            f"{manifest_path} FrontendProfile is {manifest_profiles}, want {list(FRONTEND_PROFILES)}")
    messages = {entry.get("name"): entry for entry in manifest.get("message_type", [])}
    for message, want in HANDSHAKE_FIELDS.items():
        got = {field.get("name"): field.get("number") for field in messages.get(message, {}).get("field", [])}
        require(problems, got == want, f"{manifest_path} {message} fields are {got}, want {want}")
    finish(problems)


@check("local-grammar", "pfslocal schema is exactly the current 2.0 grammar")
def check_local_grammar() -> None:
    problems: List[str] = []
    raw = read("pfslocal/pfslocal.proto")
    source = strip_proto_comments(raw)
    require(problems, re.search(rf"\bpackage\s+{re.escape(PFSLOCAL_PACKAGE)}\s*;", source) is not None,
            f"pfslocal.proto must declare package {PFSLOCAL_PACKAGE}")
    require(problems, re.search(r"\breserved\b", source) is None,
            "pfslocal.proto declares `reserved`; the schema holds only current declarations")
    major, minor = PFSLOCAL_VERSION
    require(problems, raw.lstrip().startswith(f"// pfslocal {major}.{minor} "),
            f"pfslocal.proto must open by naming pfslocal {major}.{minor}")
    body = proto_oneof(proto_block(source, "message", "Envelope"), "body")
    require(problems, body == PFSLOCAL_ENVELOPE_BODY, _dict_delta("Envelope.body", body, PFSLOCAL_ENVELOPE_BODY))
    resolve = proto_fields(proto_block(source, "message", "ResolveReply"))
    require(problems, resolve == PFSLOCAL_RESOLVE_REPLY, _dict_delta("ResolveReply", resolve, PFSLOCAL_RESOLVE_REPLY))
    capabilities = proto_fields(proto_block(source, "message", "Capabilities"))
    require(problems, capabilities == PFSLOCAL_CAPABILITIES, _dict_delta("Capabilities", capabilities, PFSLOCAL_CAPABILITIES))
    finish(problems)


def _dict_delta(label: str, got: Dict[str, int], want: Dict[str, int]) -> str:
    extra = sorted(set(got.items()) - set(want.items()))
    missing = sorted(set(want.items()) - set(got.items()))
    return f"{label} differs from the current grammar: unexpected {extra}, missing {missing}"


def swift_version_literals(text: str, field: str) -> List[int]:
    """Integer literals assigned to, compared with, or declared as field.

    Covers `hello.protocolMajor = 2`, `reply.protocolMajor == 2`, and
    `static let protocolMajor: UInt32 = 2`; a symbolic assignment such as
    `= Self.protocolMajor` carries no literal and is covered by its declaration.
    """
    pattern = re.compile(rf"(?:\.|\b(?:let|var)\s+){field}\s*(?::\s*[A-Za-z0-9_]+)?\s*(?:==|=)\s*([0-9]+)\b")
    return [int(match.group(1)) for match in pattern.finditer(text)]


@check("local-pairing", "Go codec, Swift frontend and shared fixtures agree on exact pfslocal 2.0")
def check_local_pairing() -> None:
    problems: List[str] = []
    major, minor = PFSLOCAL_VERSION
    types = read("vcs/internal/pfslocal/types.go")
    require(problems, go_const(types, "ProtocolMajor") == str(major), f"pfslocal.ProtocolMajor must be {major}")
    require(problems, go_const(types, "ProtocolMinor") == str(minor), f"pfslocal.ProtocolMinor must be {minor}")

    swift_sources = [
        name for name in files()
        if name.startswith("swift/PortableFSKit/Sources/") and name.endswith(".swift") and "/Generated/" not in name
    ]
    for field, want in (("protocolMajor", major), ("protocolMinor", minor)):
        literals = []
        for name in swift_sources:
            for match in swift_version_literals(read(name), field):
                literals.append((name, match))
        require(problems, any(value == want for _, value in literals),
                f"no handwritten Swift source sets or checks {field} = {want}")
        for name, value in literals:
            require(problems, value == want, f"{name}: {field} literal {value}, want {want}")

    golden_dirs = ("pfslocal/testdata", "swift/PortableFSKit/Tests/PortableFSKitTests/Goldens")
    shared = sorted(
        pathlib.Path(name).name for name in files()
        if name.startswith(golden_dirs[0] + "/") and name.endswith(".hex")
    )
    swift_goldens = sorted(
        pathlib.Path(name).name for name in files()
        if name.startswith(golden_dirs[1] + "/") and name.endswith(".hex")
    )
    require(problems, shared == swift_goldens, f"shared golden sets differ: Go {shared}, Swift {swift_goldens}")
    for name in sorted(set(shared) & set(swift_goldens)):
        go_bytes = read(f"{golden_dirs[0]}/{name}").strip()
        swift_bytes = read(f"{golden_dirs[1]}/{name}").strip()
        require(problems, go_bytes == swift_bytes, f"golden {name} differs between {golden_dirs[0]} and {golden_dirs[1]}")
    for name, body_field in (("hello_request.hex", 10), ("hello_reply.hex", 60)):
        try:
            version = hello_version(pfslocal_frame(read(f"{golden_dirs[0]}/{name}")), body_field)
        except (ValueError, CheckFailure) as error:
            problems.append(f"{golden_dirs[0]}/{name}: {error}")
            continue
        require(problems, version == PFSLOCAL_VERSION, f"{name} encodes pfslocal {version}, want {PFSLOCAL_VERSION}")
    finish(problems)


@check("control-lifecycle", "daemon control 2 and lifecycle v1 are declared once and wired on both sides")
def check_control_lifecycle() -> None:
    problems: List[str] = []
    identity = read("vcs/internal/daemonctl/identity.go")
    lifecycle = read("vcs/internal/daemonctl/lifecycle.go")
    expectations = (
        (identity, "IdentitySchemaVersion", str(IDENTITY_SCHEMA)),
        (identity, "ControlProtocolVersion", str(CONTROL_PROTOCOL)),
        (identity, "ControlProtocolHeader", CONTROL_HEADER),
        (identity, "ControlPathPrefix", f"/v{CONTROL_PROTOCOL}/"),
        (lifecycle, "LifecycleProtocolVersion", str(LIFECYCLE_PROTOCOL)),
        (lifecycle, "LifecycleIdentityPath", LIFECYCLE_PATHS[0]),
        (lifecycle, "LifecycleInventoryPath", LIFECYCLE_PATHS[1]),
        (lifecycle, "LifecycleStopIfIdlePath", LIFECYCLE_PATHS[2]),
    )
    for text, name, want in expectations:
        got = go_const(text, name)
        require(problems, got == want, f"daemonctl.{name} is {got!r}, want {want!r}")

    daemon = "\n".join(text for _, text in production_go("vcs/internal/portablefsd/"))
    for route in ("Identity", "Inventory", "StopIfIdle"):
        require(problems, re.search(rf"\bdaemonctl\.Lifecycle{route}(?:Route|Path)\b", daemon) is not None,
                f"portablefsd does not serve daemonctl.Lifecycle{route}Route")
    require(problems, "daemonctl.ControlPathPrefix" in daemon or f"\"/v{CONTROL_PROTOCOL}/" in daemon,
            f"portablefsd does not serve operational control under /v{CONTROL_PROTOCOL}/")

    swift = "\n".join(
        read(name) for name in files()
        if name.startswith("swift/PortableFSKit/Sources/PortableFSAppCore/") and name.endswith(".swift")
    )
    for path in (LIFECYCLE_PATHS[0], LIFECYCLE_PATHS[2]):
        require(problems, path in swift, f"the app's service coordinator does not use lifecycle route {path}")
    # The app delegates inventory to its paired CLI while retaining the
    # install guard; identity and stop remain direct authenticated requests.
    require(problems, '["lifecycle", "hold-install-exclusive", "--json"]' in swift
            and "process.arguments = inventoryGuardArguments(outgoing: outgoing)" in swift,
            "the app does not invoke its lifecycle inventory guard")
    cli = read("vcs/cmd/portablefs/internal/cli/lifecyclecmd.go")
    control = read("vcs/cmd/portablefs/internal/cli/fskitmount.go")
    require(problems, "e.daemonLifecycleInventory(expectedIdentity)" in cli
            and "daemonctl.LifecycleInventoryPath" in control,
            "the CLI inventory guard does not request the shared lifecycle inventory route")
    finish(problems)


@check("macos-build-contract", "macOS builds require Xcode 27.1 and the macOS 27 SDK while deploying to macOS 26")
def check_macos_build_contract() -> None:
    problems: List[str] = []
    for project in sorted(XCODE_PROJECTS):
        targets = re.findall(r"\bMACOSX_DEPLOYMENT_TARGET\s*=\s*([^;]+);", read(project + "/project.pbxproj"))
        require(problems, bool(targets) and set(targets) == {"26.0"}, f"{project}: deployment targets must all remain 26.0")
    require(problems, ".macOS(.v26)" in read("swift/PortableFSKit/Package.swift"), "Swift package must deploy to macOS 26")
    for filename in ("AGENTS.md", "COMPATIBILITY.md", "docs/local-dev.md", "docs/release-identity.md"):
        source = read(filename)
        for statement in ("Xcode 27.1", "27A9275", "macOS 27 SDK"):
            require(problems, statement in source, f"{filename}: missing macOS build requirement {statement}")
    finish(problems)


@check("macos-cli-layouts", "each Darwin CLI selects one compiled product contract and both variants stay gated")
def check_macos_cli_layouts() -> None:
    problems: List[str] = []
    prefix = "vcs/cmd/portablefs/internal/cli/"
    records = {
        "installlayout_production_darwin.go": (
            "darwin && !portablefs_devhost", "PortableFS.app", "PortableFS.next", "PortableFS", "PortableFSExt", "", "macOSInstallDeveloperIDRelease",
        ),
        "installlayout_devhost_darwin.go": (
            "darwin && portablefs_devhost", "PortableFSKitDev.app", "PortableFSKitDev.next", "PortableFSKitDev", "PortableFSDev", "dev.portablefs.oss.KitDev", "macOSInstallDevelopmentHost",
        ),
    }
    definitions = set()
    for name, source in production_go(prefix):
        if re.search(r"var\s+compiledMacOSInstallLayout\s*=", source):
            definitions.add(pathlib.Path(name).name)
    require(problems, definitions == set(records), f"compiled CLI layout definitions differ: {definitions}")
    for filename, (tag, app, staged, host, extension, app_id, policy) in records.items():
        source = read(prefix + filename)
        require(problems, source.startswith("//go:build " + tag + "\n"), f"{filename}: wrong build constraint")
        for name, value in (("macOSAppName", app), ("macOSStagedAppName", staged), ("macOSAppExecutable", host), ("macOSExtensionExecutable", extension)):
            require(problems, go_const(source, name) == value, f"{filename}: {name} differs from {value!r}")
        for field, value in (("appName", "macOSAppName"), ("stagedAppName", "macOSStagedAppName"), ("appExecutable", "macOSAppExecutable"), ("extensionExecutable", "macOSExtensionExecutable"), ("serviceMinimumOS", '\"26.0\"'), ("requiredAppID", json.dumps(app_id)), ("codeIdentity", policy)):
            require(problems, re.search(rf"\b{field}:\s*{re.escape(value)}\s*,", source) is not None, f"{filename}: compiled {field} differs")
        require(problems, "os.Getenv" not in source and "os.LookupEnv" not in source, f"{filename}: layout has runtime input")
    embed = read("swift/PortableFSApp/Scripts/embed-portablefs-tools.sh")
    for contract in ('case "${TARGET_NAME:-}" in', "PortableFSApp)", "PortableFSKitDev)", "cli_build_tags=portablefs_devhost", '[ "$tool" = portablefs ]', 'build_tags=$cli_build_tags', '-trimpath -tags "$build_tags"', '[ "$PRODUCT_BUNDLE_IDENTIFIER" != dev.portablefs.oss.KitDev ]', '[ "$FULL_PRODUCT_NAME" != PortableFSKitDev.app ]', '[ "$EXECUTABLE_NAME" != PortableFSKitDev ]', '[ "$MACOSX_DEPLOYMENT_TARGET" != 26.0 ]'):
        require(problems, contract in embed, f"embedding lacks {contract}")
    gate = read("scripts/test-macos-cli-layouts.sh")
    for contract in ("python3 scripts/test_embed_portablefs_tools.py", "for variant in production development", "tags=portablefs_devhost", 'build -tags "$tags"', 'vet -tags "$tags"', 'test -count=1 -tags "$tags"', 'test -race -count=1 -tags "$tags"'):
        require(problems, contract in gate, f"CLI variant gate lacks {contract}")
    for filename in ("scripts/verify-local.sh", ".github/workflows/ci.yml"):
        require(problems, "bash scripts/test-macos-cli-layouts.sh" in read(filename), f"{filename}: compiled CLI variants are not gated")
    finish(problems)


# A readiness route segment appears either alone ("frontend-ready", as a daemon
# dispatch case) or as a path suffix ("/frontend-ready", in a CLI request URL).
READINESS_ROUTE = re.compile(r"\"/?([a-z-]*ready)\"")


@check("readiness-wiring", "daemon and CLI agree on the one frontend-ready attestation route")
def check_readiness_wiring() -> None:
    problems: List[str] = []
    daemon = {match for _, text in production_go("vcs/internal/portablefsd/") for match in READINESS_ROUTE.findall(text)}
    cli = {match for _, text in production_go("vcs/cmd/portablefs/") for match in READINESS_ROUTE.findall(text)}
    require(problems, "frontend-ready" in daemon, "portablefsd does not serve the frontend-ready attestation")
    require(problems, "frontend-ready" in cli, "the CLI does not request the frontend-ready attestation")
    readiness = {name for name in daemon | cli if name.endswith("frontend-ready")}
    require(problems, readiness == {"frontend-ready"}, f"readiness attestations named {sorted(readiness)}, want only frontend-ready")
    finish(problems)


@check("membership-codec", "one mount-membership codec, imported by the authority and the cell host")
def check_membership_codec() -> None:
    problems: List[str] = []
    codec = read("vcs/internal/mountmembership/membership.go")
    require(problems, go_const(codec, "Filename") == MEMBERSHIP_FILENAME, f"mountmembership.Filename must be {MEMBERSHIP_FILENAME}")
    require(problems, go_const(codec, "Header") == MEMBERSHIP_HEADER, f"mountmembership.Header must be {MEMBERSHIP_HEADER}")
    declared = re.findall(r"Profile\s*=\s*\"([a-z-]+)\"", codec)
    require(problems, tuple(declared) == MEMBERSHIP_PROFILES, f"mountmembership profiles are {declared}, want {list(MEMBERSHIP_PROFILES)}")
    importer = '"github.com/steerlabs/portablefs/vcs/internal/mountmembership"'
    for consumer in ("vcs/internal/volumeserver/", "vcs/internal/cellhost/"):
        require(problems, any(importer in text for _, text in production_go(consumer)),
                f"{consumer} does not import the shared mountmembership codec")
    for name, text in production_go("vcs/"):
        if name.startswith("vcs/internal/mountmembership/"):
            continue
        for literal in (MEMBERSHIP_HEADER, MEMBERSHIP_FILENAME):
            require(problems, f"\"{literal}\"" not in text, f"{name} redeclares the membership literal {literal!r}; use the codec")
        for match in re.finditer(r"\"PFS-[A-Z]+-[0-9]+\"", text):
            problems.append(f"{name} declares its own format header {match.group(0)}; mount membership has one codec")
    finish(problems)


@check("profile-wiring", "each production frontend selects exactly its own authority profile")
def check_profile_wiring() -> None:
    problems: List[str] = []
    reference = re.compile(r"\bFrontendProfile_(FRONTEND_PROFILE_[A-Z_]+)\b")
    seen: Dict[str, Set[str]] = {}
    for name, text in production_go("vcs/"):
        if name.startswith(PROFILE_OWNERS):
            continue
        found = set(reference.findall(text))
        if not found:
            continue
        frontend = next((prefix for prefix in PROFILE_FRONTENDS if name.startswith(prefix)), None)
        optional = next((prefix for prefix in PROFILE_OPTIONAL if name.startswith(prefix)), None)
        if frontend is not None:
            seen.setdefault(frontend, set()).update(found)
            extra = found - PROFILE_FRONTENDS[frontend]
            require(problems, not extra, f"{name} names {sorted(extra)}; {frontend} is {sorted(PROFILE_FRONTENDS[frontend])} only")
        elif optional is not None:
            extra = found - PROFILE_OPTIONAL[optional]
            require(problems, not extra, f"{name} names {sorted(extra)}, outside {sorted(PROFILE_OPTIONAL[optional])}")
        else:
            problems.append(f"{name} names authority profiles {sorted(found)} but is not a declared frontend")
    for frontend, want in PROFILE_FRONTENDS.items():
        require(problems, seen.get(frontend) == want, f"{frontend} must select {sorted(want)}; found {sorted(seen.get(frontend, set()))}")
    finish(problems)


@check("product-layout", "the product is exactly the current executables, modules and Swift packages")
def check_product_layout() -> None:
    problems: List[str] = []
    commands = {pathlib.Path(name).parts[2] for name in files() if name.startswith("vcs/cmd/") and len(pathlib.Path(name).parts) > 3}
    require(problems, commands == PRODUCT_COMMANDS, _set_delta("vcs/cmd executables", commands, PRODUCT_COMMANDS))
    modules = {name for name in files() if pathlib.Path(name).name == "go.mod"}
    require(problems, modules == GO_MODULES, _set_delta("Go modules", modules, GO_MODULES))
    packages = {name for name in files() if pathlib.Path(name).name == "Package.swift"}
    require(problems, packages == SWIFT_PACKAGES, _set_delta("Swift packages", packages, SWIFT_PACKAGES))
    roots = {pathlib.Path(name).parts[1] for name in files() if name.startswith("swift/") and len(pathlib.Path(name).parts) > 1}
    require(problems, roots == SWIFT_ROOTS, _set_delta("swift/ entries", roots, SWIFT_ROOTS))
    projects = {
        "/".join(pathlib.Path(name).parts[:3]) for name in files()
        if name.startswith("swift/") and len(pathlib.Path(name).parts) > 3 and pathlib.Path(name).parts[2].endswith(".xcodeproj")
    }
    require(problems, projects == XCODE_PROJECTS, _set_delta("Xcode projects", projects, XCODE_PROJECTS))
    javascript = {name for name in files() if pathlib.Path(name).name == "package.json" and not name.startswith(JAVASCRIPT_MANIFEST_ROOT)}
    require(problems, not javascript, f"JavaScript package manifests outside workload fixtures: {sorted(javascript)}")
    finish(problems)


def _set_delta(label: str, got: Set[str], want: Set[str]) -> str:
    return f"{label} differ: unexpected {sorted(got - want)}, missing {sorted(want - got)}"


@check("flag-wiring", "every command line in the launcher, scripts and docs uses flags the executable defines")
def check_flag_wiring() -> None:
    problems: List[str] = []
    definitions = {executable: defined_flags(directory) for executable, directory in FLAG_CONSUMERS.items()}
    for executable, names in definitions.items():
        require(problems, bool(names), f"no flags found for {executable}; the flag parser in this check is out of date")

    launcher = read("vcs/internal/cellhost/config.go")
    try:
        body = launcher[launcher.index("func AuthorityArguments"):]
        body = body[:body.index("\n}\n")]
    except ValueError:
        raise CheckFailure(["vcs/internal/cellhost/config.go no longer declares AuthorityArguments"])
    for flag in re.findall(r"\"-{1,2}([a-z][a-z0-9-]*)\"", body):
        require(problems, flag in definitions["portablefs-authority"],
                f"cellhost.AuthorityArguments passes -{flag}, which portablefs-authority does not define")

    for name in files():
        if not maintained(name) or not (name.endswith(".sh") or name.endswith(".md")):
            continue
        text = read(name)
        if name.endswith(".md"):
            text = _fenced_code(text)
        for executable, flags in definitions.items():
            for line, command in command_lines(text, executable):
                for flag in SHELL_FLAG.findall(command):
                    require(problems, flag in flags, f"{name}:{line}: {executable} has no flag --{flag}")
    finish(problems)


def _fenced_code(text: str) -> str:
    """Markdown with everything outside fenced code blocks blanked, line numbers kept."""
    out = []
    fenced = False
    for line in text.splitlines():
        if FENCE.match(line.strip()):
            fenced = not fenced
            out.append("")
            continue
        out.append(line if fenced else "")
    return "\n".join(out)


@check("required-inventories", "the privileged suite reads exactly the three package-owned required-test lists")
def check_required_inventories() -> None:
    problems: List[str] = []
    suite = read("scripts/xfs-fuse-integration.sh")
    for listed in REQUIRED_TEST_LISTS:
        require(problems, (ROOT / listed).is_file(), f"{listed} is missing")
        require(problems, pathlib.Path(listed).name in suite, f"scripts/xfs-fuse-integration.sh does not read {listed}")
    lists_named = set(re.findall(r"xfs-required-[a-z]+-tests\.txt", suite))
    require(problems, lists_named == {pathlib.Path(name).name for name in REQUIRED_TEST_LISTS},
            f"scripts/xfs-fuse-integration.sh names required lists {sorted(lists_named)}")
    problems.extend(root_inventory_problems(suite))
    gate = read("scripts/verify-local.sh")
    require(problems, "scripts/check-current-architecture.py" in gate, "scripts/verify-local.sh does not run this check")
    finish(problems)


def shell_array(text: str, name: str) -> List[str]:
    """Quoted or bare words of a top-level bash array assignment NAME=( ... )."""
    match = re.search(rf"(?m)^{re.escape(name)}=\(\s*\n(.*?)^\)", text, re.DOTALL)
    if not match:
        return []
    words = []
    for line in match.group(1).splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            words.append(line.strip('"'))
    return words


def root_inventory_problems(suite: str) -> List[str]:
    """Problems with the root invocation's inventory in the suite's text.

    The root invocation derives its -run selector from REQUIRED_ROOT_TESTS, so
    an empty or missing list would select nothing and require nothing.
    """
    problems: List[str] = []
    if not re.search(r"(?m)^REQUIRED_ROOT_TESTS=\(", suite):
        return ["scripts/xfs-fuse-integration.sh declares no REQUIRED_ROOT_TESTS"]
    entries = shell_array(suite, "REQUIRED_ROOT_TESTS")
    require(problems, bool(entries), "scripts/xfs-fuse-integration.sh REQUIRED_ROOT_TESTS is empty")
    require(problems, len(entries) == len(set(entries)), "scripts/xfs-fuse-integration.sh REQUIRED_ROOT_TESTS repeats an entry")
    for entry in entries:
        package, _, test = entry.partition(":")
        require(problems, package in ROOT_TEST_PACKAGES and re.fullmatch(r"Test[A-Za-z0-9_]+", test) is not None,
                f"root required entry {entry!r} is not a top-level test in {sorted(ROOT_TEST_PACKAGES)}")
    missing = ROOT_REQUIRED - set(entries)
    require(problems, not missing, f"scripts/xfs-fuse-integration.sh does not require root obligations {sorted(missing)}")
    require(problems, "validate_root_tests" in suite and re.search(r"(?m)^\s+validate_root_tests$", suite) is not None,
            "scripts/xfs-fuse-integration.sh does not validate its root inventory before running it")
    return problems


def required_list_entries(text: str) -> List[str]:
    """package:Test entries of a required-test list, without qualifiers."""
    entries = []
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        entries.append(line.split(" ", 1)[1] if " " in line else line)
    return entries


def defined_tests(directory: str) -> Set[str]:
    names: Set[str] = set()
    for name in files():
        if name.startswith(directory + "/") and name.endswith("_test.go") and "/" not in name[len(directory) + 1:]:
            names.update(re.findall(r"(?m)^func (Test[A-Za-z0-9_]*)\(t \*testing\.T\)", read(name)))
    return names


@check("required-tests-defined", "every privileged and power-loss required test names a test that exists")
def check_required_tests_defined() -> None:
    problems: List[str] = []
    entries: List[str] = []
    for listed in REQUIRED_TEST_LISTS:
        entries.extend(required_list_entries(read(listed)))
    entries.extend(shell_array(read("scripts/xfs-fuse-integration.sh"), "REQUIRED_ROOT_TESTS"))
    powerloss = shell_array(read("scripts/run-powerloss.sh"), "REQUIRED_TESTS")
    require(problems, bool(powerloss), "scripts/run-powerloss.sh declares no REQUIRED_TESTS")
    missing_contracts = POWERLOSS_REQUIRED - set(powerloss)
    require(problems, not missing_contracts, f"scripts/run-powerloss.sh does not require {sorted(missing_contracts)}")
    entries.extend(f"{MODULE_PREFIX}vcs/test/powerloss:{name}" for name in powerloss)
    cache: Dict[str, Set[str]] = {}
    for entry in entries:
        package, _, test = entry.partition(":")
        if not package.startswith(MODULE_PREFIX) or not test:
            problems.append(f"required entry {entry!r} is not <module package>:<Test>")
            continue
        directory = package[len(MODULE_PREFIX):]
        if directory not in cache:
            cache[directory] = defined_tests(directory)
        parent = test.split("/", 1)[0]
        require(problems, parent in cache[directory], f"required test {entry} is not defined in {directory}")
    finish(problems)


@check("contract-agreement", "COMPATIBILITY.md states each surface version and the kernel floors match code")
def check_contract_agreement() -> None:
    problems: List[str] = []
    contract = read("COMPATIBILITY.md")
    major, minor = PFSLOCAL_VERSION
    statements = (
        f"`portablefs-authority-v{AUTHORITY_MAJOR}`",
        f"| `{AUTHORITY_MAJOR}` |",
        f"| 2.0 |" if (major, minor) == (2, 0) else f"| {major}.{minor} |",
        f"| `{CONTROL_PROTOCOL}` |",
        f"| `{LIFECYCLE_PROTOCOL}` |",
        f"schema `{IDENTITY_SCHEMA}`",
        f"`{MEMBERSHIP_FILENAME}`, header `{MEMBERSHIP_HEADER}`",
        f"protocol {FUSE_FLOOR[0]}.{FUSE_FLOOR[1]} or newer",
        f"Linux {AUTHORITY_KERNEL_FLOOR[0]}.{AUTHORITY_KERNEL_FLOOR[1]} final or newer",
    )
    for statement in statements:
        require(problems, statement in contract, f"COMPATIBILITY.md does not state {statement!r}")
    for path in LIFECYCLE_PATHS:
        require(problems, path in contract, f"COMPATIBILITY.md does not list lifecycle route {path}")
    fuse = read("vcs/internal/fusev3/fuse_linux.go")
    require(problems, go_const(fuse, "portableFuseMajor") == str(FUSE_FLOOR[0]) and go_const(fuse, "portableFuseMinor") == str(FUSE_FLOOR[1]),
            f"fusev3 must declare the FUSE {FUSE_FLOOR[0]}.{FUSE_FLOOR[1]} floor")
    kernel = read("vcs/internal/xfsstore/kernel_linux.go")
    floor_major, floor_minor = AUTHORITY_KERNEL_FLOOR
    floor = (f'major > {floor_major} || major == {floor_major} && '
             f'(minor > {floor_minor} || minor == {floor_minor} && !strings.Contains(parts[2], "-rc"))')
    require(problems, floor in " ".join(kernel.split()),
            f"xfsstore must enforce the Linux {AUTHORITY_KERNEL_FLOOR[0]}.{AUTHORITY_KERNEL_FLOOR[1]} authority floor")

    finish(problems)


@check("doc-links", "every relative link in maintained Markdown resolves, including heading anchors")
def check_doc_links() -> None:
    problems: List[str] = []
    anchors_cache: Dict[str, Set[str]] = {}

    def anchors(relative: str) -> Set[str]:
        if relative not in anchors_cache:
            anchors_cache[relative] = heading_anchors(read(relative))
        return anchors_cache[relative]

    for name in files():
        if not maintained(name) or not name.endswith(".md"):
            continue
        text = markdown_without_code(read(name))
        for line_number, line in enumerate(text.splitlines(), 1):
            for target in LINK.findall(line):
                if re.match(r"^[a-z][a-z0-9+.-]*:", target):
                    continue
                path_part, _, anchor = target.partition("#")
                if path_part:
                    resolved = os.path.normpath(os.path.join(os.path.dirname(name), path_part))
                    if resolved.startswith(".."):
                        problems.append(f"{name}:{line_number}: link {target} leaves the repository")
                        continue
                    if not (ROOT / resolved).exists():
                        problems.append(f"{name}:{line_number}: link {target} names a missing file")
                        continue
                else:
                    resolved = name
                if anchor and resolved.endswith(".md") and (ROOT / resolved).is_file():
                    if anchor not in anchors(resolved):
                        problems.append(f"{name}:{line_number}: link {target} names a missing heading")
    finish(problems)


# ---------------------------------------------------------------------------


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--list", action="store_true", help="print the check names and exit")
    parser.add_argument("--only", action="append", default=[], help="run only the named check (repeatable)")
    arguments = parser.parse_args(argv)
    if arguments.list:
        for name, summary, _ in CHECKS:
            print(f"{name:22} {summary}")
        return 0
    known = {name for name, _, _ in CHECKS}
    unknown = [name for name in arguments.only if name not in known]
    if unknown:
        print(f"check-current-architecture: unknown check(s): {', '.join(unknown)}", file=sys.stderr)
        return 2
    selected = [entry for entry in CHECKS if not arguments.only or entry[0] in arguments.only]
    failed = 0
    for name, summary, function in selected:
        try:
            function()
        except CheckFailure as failure:
            failed += 1
            print(f"FAIL {name}: {summary}", file=sys.stderr)
            for problem in failure.problems:
                print(f"     {problem}", file=sys.stderr)
        else:
            print(f"ok   {name}")
    if failed:
        print(f"check-current-architecture: {failed} of {len(selected)} checks failed", file=sys.stderr)
        return 1
    print(f"check-current-architecture: all {len(selected)} checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
