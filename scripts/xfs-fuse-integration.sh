#!/usr/bin/env bash
# Runs the privileged Linux integration suite (real XFS with project quotas plus
# real kernel FUSE mounts) inside a throwaway privileged container.
#
# The same script is the CI entry point and the local reproduction, so a green
# CI run and a developer run execute byte-identical provisioning. Every gate is
# fail-closed: a filesystem that cannot be provisioned, a test that skips, and a
# required test that never ran are all hard failures, because a silently skipped
# privileged test is exactly how this coverage gap survived unnoticed.
#
#   scripts/xfs-fuse-integration.sh                 # host side (needs docker)
#   scripts/xfs-fuse-integration.sh --in-container  # container side (needs root)
set -euo pipefail

# Digest-pinned like every other third-party image in this repository.
# Evidence: golang:1.26.10-bookworm (matches the toolchain in vcs/go.mod).
: "${PORTABLEFS_CI_IMAGE:=golang@sha256:fe3da92a5cb2881e4aa75e625cb0b7c50571632fb4cf340cbe53e6ccdcffdd51}"
: "${PORTABLEFS_XFS_IMAGE_SIZE:=1G}"
: "${PORTABLEFS_SERVICE_UID:=200001}"
: "${PORTABLEFS_SERVICE_GID:=200001}"
: "${PORTABLEFS_PROJECT_ID:=42001}"
: "${PORTABLEFS_VOLUME_NAME:=ci-volume}"
# The second service-owned project on the same XFS cell that the busy-neighbor
# barrier measurement dirties while it times this volume's handleless
# mutations. Provisioned only for PORTABLEFS_PERFORMANCE_TEST=1.
: "${PORTABLEFS_NEIGHBOR_VOLUME_NAME:=latency-neighbor}"
: "${PORTABLEFS_NEIGHBOR_PROJECT_ID:=42002}"

# Every test that must actually run and pass, loaded by load_required_tests
# from the three package-owned inventories beside this script. A rename or
# deletion there fails the job instead of quietly shrinking privileged coverage.
REQUIRED_TESTS=()

# Tests that need root, run in their own invocation after the unprivileged
# data-plane suite:
#   - the cell helper's root-owned volume provisioning: it assigns the XFS
#     project and hard block/inode quotas, sets the inherit flag, ownership and
#     mode, and verifies the result against the real filesystem, with privileges
#     the authority service identity never holds;
#   - the shared-cell writeback domain: on its own loop-backed XFS filesystems
#     it injects a real device-mapper write error under one volume's data and
#     requires a second volume on the same filesystem to observe the shared
#     error at its next syncfs and fence, while a volume on a separate
#     filesystem stays healthy. It needs losetup, dmsetup and the production
#     provisioner;
#   - the FUSE probe's missing-fusectl prerequisite: a child private mount
#     namespace hides fusectl without changing the service suite's mounts.
# The sealed-page and gated raw-entry tests also require a real root supervisor;
# keep them in this required lane rather than letting the service-UID suite
# silently stand in for those proofs.
# Keeping an exact, nonempty required list prevents a renamed, skipped or
# deleted test from masquerading as qualification; validate_root_tests refuses
# an empty or malformed list before any test selector is built.
REQUIRED_ROOT_TESTS=(
  "github.com/steerlabs/portablefs/vcs/internal/workspacemount:TestRootRegistrationObservationCannotBlockClockClosure"
  "github.com/steerlabs/portablefs/vcs/internal/workspacemount:TestRootLocalConnectChargesSaturatedBacklog"
  "github.com/steerlabs/portablefs/vcs/internal/workspacemount:TestRootRecreatesOnlyProtectedColdTarget"
  "github.com/steerlabs/portablefs/vcs/internal/workspacemount:TestRootStableBackingAndAcknowledgedMetadata"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceFinalizationRetainsTerminalOutcomeAndRefusesCleanupDebt"
  "github.com/steerlabs/portablefs/vcs/cmd/portablefs/internal/cli:TestWorkspaceReconcileIndependentCommitsAndLostAcknowledgment"
  "github.com/steerlabs/portablefs/vcs/internal/workspacemount:TestRootLostInstallResponseKeepsOriginalFailedINITOwner"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestManagedKernelFailedINITRetainsExactRemovalOwner"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestManagedKernelRejectsForeignBootstrapDescriptions"
  "github.com/steerlabs/portablefs/vcs/cmd/portablefs/internal/cli:TestWorkspaceClockRefusalLatchesServingUntilFreshClosedPermit"
  "github.com/steerlabs/portablefs/vcs/internal/workspaceclock:TestSharedClockConcurrentCheckAndCloseJoinsReaders"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceClockDeniesEntryBeforeRootObservation"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceClockDeniesCapacityWaitBeforeRootObservation"
	"github.com/steerlabs/portablefs/vcs/internal/workspacemount:TestRootSuspendForwardsRemainingBudgetAndJoinsLocalOwner"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestManagedKernelProtectedBootstrapAndExactRemoval"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestManagedKernelVoluntaryEBUSYRetainsOriginalOwner"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestManagedKernelExternalUnmountNeedsIndependentAbsence"
  "github.com/steerlabs/portablefs/vcs/internal/workspaceclock:TestSharedClockReadOnlyGenerationAndFreshness"
  "github.com/steerlabs/portablefs/vcs/internal/workspaceclock:TestSharedClockSeqlockCannotMixAuthorization"
  "github.com/steerlabs/portablefs/vcs/internal/workspaceclock:TestSharedClockChildCannotForgePage"
  "github.com/steerlabs/portablefs/vcs/internal/workspaceclock:TestSharedClockClosedOwnerAndIdempotentReaderClose"
  "github.com/steerlabs/portablefs/vcs/internal/workspacemount:TestIdentityPrivateToWorkspaceUser"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceZeroEntryLossTicketRecorded"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspacePersistenceFailureSurvivesPermitLoss"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceManagedResumePermitLoss"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceKeepAliveParkRetainsIndependentFailure"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestReviewCancelledRecoverThenSuspend"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestReviewCycleLeaks"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestReviewDuplicateSuspendAfterCold"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestReviewInterruptedInitialPrepareThenSuspend"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestReviewKernelChurn"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestReviewKernelClockReadiness"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestReviewKernelFrozenLeasePause"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestReviewKernelInterruptedRecover"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestReviewKernelLeaseExpiry"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestReviewKernelSessionExpired"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestReviewLookupAfterRecover"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestReviewLossAggregationLatchesFailure"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestReviewRetryAfterCanceledWithdrawal"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestReviewStickyAbandonedRefusesCold"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceBoundLossFailureRetainsEvidence"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceCleanupDebtCountsObligationsOnce"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceColdPOSIXFlushIsPrompt"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceControlHandoffHasNoPermissionGap"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceKeepAliveParkJoinsDisposition"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceLifecycleResultRetainsIndependentFailure"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspacePersistenceRecordsPublicationRefusal"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspacePersistenceRetryKeepsPhysicalColdCut"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceRealClientRetriesUnusableSubscribe"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceRealVisibilityOwnerOutlivesPark"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceRetainedSizeAndAttributesBeforeReset"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceLifecycleDrainsAcceptedDirtyCut"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceFailedReleaseRetainsDurabilityOutcome"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspacePersistenceCannotPublishStaleClock"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceOvertakenColdRetainsLoss"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceRecoveryClassifiesTerminalEvidence"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceLifecycleControlCutDrainsAck"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceLifecycleJoinsInFlightRenewal"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceLifecycleColdRecover"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceLifecycleRetryBeyond45Seconds"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceColdFailureRetainsLossAndNotificationOwner"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceLifecycleCancellationKeepsPhysicalOwner"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceClosedFlushReobservesResetLoss"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestKernelWorkspaceControlledPause"
  "github.com/steerlabs/portablefs/vcs/internal/workspaceadmission:TestClosedStartAndExactPreparedCAS"
  "github.com/steerlabs/portablefs/vcs/internal/workspaceadmission:TestReadOnlyHandoffAndDescriptorSeals"
  "github.com/steerlabs/portablefs/vcs/internal/workspaceadmission:TestHandoffRejectsWritableOrUnboundDescriptors"
  "github.com/steerlabs/portablefs/vcs/internal/workspaceadmission:TestOwnerEOFIsIndependentAndPermanent"
  "github.com/steerlabs/portablefs/vcs/internal/workspaceadmission:TestStalledChildCloseAndSoleWriter"
  "github.com/steerlabs/portablefs/vcs/internal/workspaceadmission:TestCloseSerialExhaustionAndGenerationFloor"
  "github.com/steerlabs/portablefs/vcs/internal/workspaceadmission:TestRetireInterruptsOwnerReadWhileSupervisorLives"
  "github.com/steerlabs/portablefs/vcs/internal/workspaceadmission:TestReviewChildCannotObtainWritableWord"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceAdmittedFsyncKeepsDirtyCut"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceRetainsDirtyReadOwnership"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceAdmittedReadKeepsOverlayAndEOF"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceCohortJoinsTerminalSettlement"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceCohortIncludesWrittenSettlement"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceSetattrRefusalKeepsNoChangeOwner"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceDrainKeepsWithdrawalLead"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceRenewLoopSkipsClosedControl"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceClosedCleanFlushSucceeds"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOrdinaryEntrySkipsWorkspaceAndPreservesRefusals"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestReviewGateChurnStress"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceFastAnswersCloseBeforeServing"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceCachedReplyRollbackAndFixedCohort"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceEmptyPublicationsRetainOwner"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceLatePhysicalReadPurgesAfterWrite"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceClosedCleanupAndFlushUnlock"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceRecoveryAndDrainAreNotServing"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceCapacityWaitChecksActualAcceptance"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceScratchOpenLoopStopsOnClose"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceAcceptedCreateAndWriteKeepPhysicalOwner"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceInitialSubscribeLosesToPark"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceCloseAfterLastInstallationCheckIsInert"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceSlowHelperCannotInventServingAdmission"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceEveryGraftBranchChecksEntry"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceStaticRefusalsDoNotAcquireServingOwner"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceCloseHandoffReleasesEpochFenceBeforeQueueCapacity"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestKernelWorkspaceGateAndOwnerLifetime"
  "github.com/steerlabs/portablefs/vcs/internal/cellhost:TestProvisionedVolumeEnforcesXFSProjectQuotaAndConfinement"
  "github.com/steerlabs/portablefs/vcs/internal/xfsstore:TestSharedXFSWritebackDomain"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestKernelFUSEProbeRejectsHiddenFusectl"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR1CancelledRecoverThenSuspend"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR1CycleLeaks"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR1DuplicateSuspendAfterCold"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR1InterruptedInitialPrepareThenSuspend"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR1KernelChurn"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR1KernelClockReadiness"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR1KernelFrozenLeasePause"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR1KernelInterruptedRecover"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR1KernelLeaseExpiry"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR1KernelSessionExpired"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR1LookupAfterRecover"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR1LossAggregationLatchesFailure"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR1RetryAfterCanceledWithdrawal"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR1StickyAbandonedRefusesCold"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR2ClockFlapDuringRecover"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR2IncompleteSuspendThenLaterTransition"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR2KernelCancelledSleep"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR2KernelClockDiag"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR2KernelIncompleteSuspend"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR2PreparedUnservedReacknowledgeEvidence"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR3GateCloseBeforeFrameDuringPublication"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR3KernelLateApplyCoherence"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR3KernelLongGapAccounted"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestOpusR3KernelStressIntegrity"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceKernelAssignedWriteColdCut"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceKernelReadinessBudget10Seconds"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceKernelReadinessBudget45Seconds"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceKernelReparkResnapshotsRealCleanup"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceKernelUnassignedWriteColdCut"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceOvertakenBeforeInitialCut"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceOwnerCloseAtPermitBoundaries"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceCloseDuringRecoveryValidation"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceKernelReadinessReturnsDuringDrain"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceKernelRecoverCompletesCanceledCut"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceOwnerRenewalCutoffSurvivesClose"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceObservationTerminal"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceOwnerCloseDuringPublication"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspacePollFailureSurvivesPark"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspacePublicationRenewsAgedProofInOriginalJob"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceRealSemanticPollFailureSurvivesPark"
  "github.com/steerlabs/portablefs/vcs/internal/fusev3:TestWorkspaceRetirementFenceIsUnsubmitted"
)

fail() {
  echo "xfs-fuse-integration: $1" >&2
  exit "${2:-1}"
}

repository_root() {
  cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd
}

# load_required_tests reads the union of scripts/xfs-required-authority-tests.txt,
# xfs-required-fuse-tests.txt and xfs-required-tiered-tests.txt into
# REQUIRED_TESTS. Each list may name only its owner's packages, which are
# exactly the packages the two suite slices run. A line starting with `#` is a
# comment; every other line must be exactly
#
#   github.com/steerlabs/portablefs/vcs/internal/<package>:Test<Name>[/<subtest>...]
#
# optionally prefixed by `performance `, which requires that entry only when
# PORTABLEFS_PERFORMANCE_TEST=1. Anything else (a blank, indented, CRLF or
# trailing-space line) is refused rather than skipped: a malformed entry that is
# silently dropped is a required test that quietly stopped being required.
#
# Test names must be unique across the whole union, not merely as entries:
# verify_exact_tests matches the PASS line by name, so two entries sharing a
# name would both be satisfied by one PASS.
load_required_tests() {
  local scripts owner packages list pattern line number entries duplicates
  local -a listed=()
  scripts=$(repository_root)/scripts
  REQUIRED_TESTS=()
  for owner in authority fuse tiered; do
    case $owner in
      authority) packages='authorityrpc|xfsstore|archiver|hydrator|restoremode' ;;
      fuse) packages='fusev3' ;;
      tiered) packages='tierede2e' ;;
    esac
    list=$scripts/xfs-required-$owner-tests.txt
    [[ -f $list ]] || fail "required test list is missing: $list"
    pattern='^(performance )?(github\.com/steerlabs/portablefs/vcs/internal/('"$packages"'):(Test[A-Z0-9_][A-Za-z0-9_]*(/[A-Za-z0-9_.-]+)*))$'
    number=0
    entries=0
    while IFS= read -r line || [[ -n $line ]]; do
      number=$((number + 1))
      if [[ $line == '#'* ]]; then
        continue
      fi
      [[ $line =~ $pattern ]] ||
        fail "${list}:${number}: invalid required test entry '${line}' (packages here: ${packages//|/, })"
      entries=$((entries + 1))
      listed+=("${BASH_REMATCH[4]}")
      if [[ -z ${BASH_REMATCH[1]} || ${PORTABLEFS_PERFORMANCE_TEST:-} == 1 ]]; then
        REQUIRED_TESTS+=("${BASH_REMATCH[2]}")
      fi
    done <"$list"
    [[ $entries -gt 0 ]] || fail "required test list names no tests: $list"
  done
  duplicates=$(printf '%s\n' "${listed[@]}" | LC_ALL=C sort | uniq -d)
  [[ -z $duplicates ]] || fail "required test names listed more than once: ${duplicates//$'\n'/, }"
}

# validate_root_tests fails closed on an empty, malformed or duplicated root
# inventory. The root invocation derives both its packages and its -run
# selector from this list, so an empty list would otherwise select no test and
# "pass" zero requirements. Only the packages whose root-only tests the
# invocation is provisioned for may appear.
validate_root_tests() {
  local entry seen=" "
  [[ ${#REQUIRED_ROOT_TESTS[@]} -gt 0 ]] ||
    fail "REQUIRED_ROOT_TESTS is empty; the root boundary must require at least one test" 70
  for entry in "${REQUIRED_ROOT_TESTS[@]}"; do
    [[ $entry =~ ^github\.com/steerlabs/portablefs/vcs/(internal/(cellhost|xfsstore|fusev3|workspaceadmission|workspaceclock|workspacemount)|cmd/portablefs/internal/cli):Test[A-Za-z0-9_]+$ ]] ||
      fail "REQUIRED_ROOT_TESTS entry is not a provisioned root-package top-level test: $entry" 70
    [[ $seen != *" ${entry} "* ]] ||
      fail "REQUIRED_ROOT_TESTS names a test twice: $entry" 70
    seen="${seen}${entry} "
  done
}

run_host() {
  # Refuse a malformed inventory before spending a container run on it; the
  # container validates its own read-only copy again before the suite.
  load_required_tests
  validate_root_tests
  command -v docker >/dev/null || fail "docker is required to run the privileged integration suite" 69
  local root
  root=$(repository_root)
  local profile_root=""
  local -a profile_options=() docker_action=(run --rm) soak_options=()
  if [[ ${PORTABLEFS_SOAK_TEST:-} == 1 ]]; then
    soak_options=(--memory=2g --memory-swap=2g --cpus=2)
  fi
  if [[ -n "${PORTABLEFS_PROFILE_DIR:-}" ]]; then
    mkdir -p -- "$PORTABLEFS_PROFILE_DIR"
    profile_root=$(cd -- "$PORTABLEFS_PROFILE_DIR" && pwd)
    profile_options=(-e PORTABLEFS_PROFILE_DIR=/profiles)
    docker_action=(create)
  fi
  echo "xfs-fuse-integration: launching ${PORTABLEFS_CI_IMAGE}"
  # The working tree is mounted read-only: the container provisions its own XFS
  # image and must never be able to mutate the checkout it is testing.
  launch_container() {
    docker "${docker_action[@]}" --privileged "${soak_options[@]}" \
      --tmpfs /var/tmp:exec,mode=1777 \
      -v "${root}/vcs:/work/vcs:ro" \
      -v "${root}/scripts:/work/scripts:ro" \
      "$@" "${profile_options[@]}" \
      -e "PORTABLEFS_XFS_IMAGE_SIZE=${PORTABLEFS_XFS_IMAGE_SIZE}" \
      -e "PORTABLEFS_SERVICE_UID=${PORTABLEFS_SERVICE_UID}" \
      -e "PORTABLEFS_SERVICE_GID=${PORTABLEFS_SERVICE_GID}" \
      -e "PORTABLEFS_PROJECT_ID=${PORTABLEFS_PROJECT_ID}" \
      -e "PORTABLEFS_VOLUME_NAME=${PORTABLEFS_VOLUME_NAME}" \
      -e "PORTABLEFS_GO_TEST_FLAGS=${PORTABLEFS_GO_TEST_FLAGS:-}" \
      -e "PORTABLEFS_FUSE_DEBUG=${PORTABLEFS_FUSE_DEBUG:-}" \
      -e "PORTABLEFS_PERFORMANCE_TEST=${PORTABLEFS_PERFORMANCE_TEST:-}" \
      -e "PORTABLEFS_SOAK_TEST=${PORTABLEFS_SOAK_TEST:-}" \
      -e "PORTABLEFS_PROFILE_RUN=${PORTABLEFS_PROFILE_RUN:-}" \
      -w /work \
      "${PORTABLEFS_CI_IMAGE}" \
      bash /work/scripts/xfs-fuse-integration.sh --in-container
  }
  run_container() {
    if [[ -z "$profile_root" ]]; then
      launch_container "$@"
      return
    fi
    # Copy after the run instead of bind-mounting a host path: remote Docker
    # contexts need not share /tmp (or any artifact directory) with the host.
    profile_container=$(launch_container "$@")
    trap 'if [[ -n "${profile_container:-}" ]]; then docker rm -f "$profile_container" >/dev/null 2>&1 || true; fi' EXIT
    local status=0
    docker start -a "$profile_container" || status=$?
    docker cp "$profile_container:/profiles/." "$profile_root/" || status=1
    docker rm "$profile_container" >/dev/null
    profile_container=""
    return "$status"
  }
  if [[ -d /lib/modules/$(uname -r) ]]; then
    run_container -v /lib/modules:/lib/modules:ro
  else
    run_container
  fi
}

install_container_dependencies() {
  if [[ -n "${PORTABLEFS_PROFILE_DIR:-}" ]]; then
    mkdir -p -- "$PORTABLEFS_PROFILE_DIR"
    chmod 1777 "$PORTABLEFS_PROFILE_DIR"
  fi
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  # xfsprogs: mkfs.xfs and xfs_quota. fuse3: the setuid fusermount3 helper the
  # unprivileged test process needs. sqlite3/git: the real application workload.
  # libcap2-bin: capsh, which is how the tiered suite is handed the archiver's
  # one capability and nothing else. See run_tiered_suite.
  # kmod supplies the tooling used while provisioning the kernel FUSE control
  # surface inherited from the host.
  # dmsetup: the root shared-cell writeback-domain fixture's error segment.
  apt-get install -y -qq --no-install-recommends xfsprogs fuse3 sqlite3 git util-linux libcap2-bin kmod dmsetup >/dev/null
  if [[ ${PORTABLEFS_SOAK_TEST:-} == 1 ]]; then
    apt-get install -y -qq --no-install-recommends nodejs npm >/dev/null
  fi
}

# The FUSE control filesystem is the kernel interface a mount's revocation
# ladder uses to abort its own serving connection, which is what releases every
# request parked in the kernel when the authority is gone. A production host has
# it mounted; a container does not inherit it, and without it the abort step
# silently cannot run - so the mount-owner detach helper waits on a request
# nothing can answer and teardown never completes. Provisioning it here is what
# makes the container the same kernel surface production is.
provision_fuse_control() {
  [[ -d /sys/fs/fuse/connections ]] || fail "/sys/fs/fuse/connections is missing; this kernel has no FUSE control interface" 69
  mountpoint -q /sys/fs/fuse/connections ||
    mount -t fusectl none /sys/fs/fuse/connections ||
    fail "cannot mount the FUSE control filesystem; connection aborts would be unavailable" 69
}

provision_xfs() {
  local image=/var/tmp/portablefs-xfs.img
  [[ -e /dev/fuse ]] || fail "/dev/fuse is missing; the container cannot mount a kernel FUSE filesystem" 69
  [[ -e /dev/loop-control ]] || fail "/dev/loop-control is missing; the container cannot create a loop-backed XFS" 69
  install -d -m 0755 -o 0 -g 0 /srv/portablefs
  rm -f -- "$image"
  truncate -s "$PORTABLEFS_XFS_IMAGE_SIZE" "$image"
  mkfs.xfs -q -f "$image"
  mount -o "loop,prjquota,nodev,nosuid,noexec,noatime" "$image" /srv/portablefs
  local options
  options=$(findmnt -n -r -o OPTIONS -T /srv/portablefs)
  [[ ,$options, == *,prjquota,* ]] || fail "XFS mounted without prjquota (options: $options)"
  [[ $(findmnt -n -r -o FSTYPE -T /srv/portablefs) == xfs ]] || fail "provisioned filesystem is not XFS"
}

provision_volume() {
  # The production provisioner is the single source of truth for project-quota
  # setup. CI exercising a private copy would prove nothing about production.
  bash /work/scripts/provision-xfs-volume.sh \
    /srv/portablefs "$PORTABLEFS_VOLUME_NAME" "$PORTABLEFS_PROJECT_ID" \
    "$PORTABLEFS_SERVICE_UID" "$PORTABLEFS_SERVICE_GID" 512m 200000
}

# The busy-neighbor barrier measurement (a "performance " entry) needs a
# second service-owned project on this volume's XFS filesystem. Provisioning it
# with the production provisioner keeps the neighbor's quota and ownership the
# deployment's.
provision_neighbor_volume() {
  [[ $PORTABLEFS_NEIGHBOR_PROJECT_ID != "$PORTABLEFS_PROJECT_ID" ]] ||
    fail "the latency neighbor needs a project ID distinct from $PORTABLEFS_PROJECT_ID" 70
  bash /work/scripts/provision-xfs-volume.sh \
    /srv/portablefs "$PORTABLEFS_NEIGHBOR_VOLUME_NAME" "$PORTABLEFS_NEIGHBOR_PROJECT_ID" \
    "$PORTABLEFS_SERVICE_UID" "$PORTABLEFS_SERVICE_GID" 128m 10000
}

create_service_identity() {
  groupadd -g "$PORTABLEFS_SERVICE_GID" portablefs
  useradd -u "$PORTABLEFS_SERVICE_UID" -g "$PORTABLEFS_SERVICE_GID" -M -d /home/portablefs -s /bin/bash portablefs
  install -d -m 0700 -o "$PORTABLEFS_SERVICE_UID" -g "$PORTABLEFS_SERVICE_GID" \
    /home/portablefs /home/portablefs/gocache /home/portablefs/gomodcache /home/portablefs/tmp
}

# suite_command emits the fully pinned `go test` invocation, environment and
# all, as one argv. Both suite slices run byte-identically apart from the
# packages they name and the capability they are given.
#
# PORTABLEFS_XFS_TEST_REQUIRED turns every gate skip into a failure so a broken
# provisioner cannot present as a green run. -p 1 keeps the privileged packages
# from opening the one provisioned XFS cell concurrently, which its exclusive
# volume lock forbids.
suite_command() {
  local -a extra_go_test_flags=() soak_env=() performance_env=()
  if [[ ${PORTABLEFS_SOAK_TEST:-} == 1 ]]; then
    soak_env=(GOMAXPROCS=2 GOMEMLIMIT=768MiB)
  fi
  if [[ ${PORTABLEFS_PERFORMANCE_TEST:-} == 1 ]]; then
    performance_env=(
      "PORTABLEFS_XFS_NEIGHBOR_ROOT=/srv/portablefs/${PORTABLEFS_NEIGHBOR_VOLUME_NAME}"
      "PORTABLEFS_XFS_NEIGHBOR_PROJECT=${PORTABLEFS_NEIGHBOR_PROJECT_ID}"
    )
  fi
  if [[ -n ${PORTABLEFS_GO_TEST_FLAGS:-} ]]; then
    read -r -a extra_go_test_flags <<<"$PORTABLEFS_GO_TEST_FLAGS"
  fi
  # Emit rather than execute so the plain and capability-limited slices use
  # the same environment and command line. The 35-minute timeout remains below
  # the CI lane timeout while covering the longer tiered lifecycle.
  printf '%s\0' \
    env -i \
    HOME=/home/portablefs \
    PATH=/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin \
    TMPDIR=/home/portablefs/tmp \
    GOCACHE=/home/portablefs/gocache \
    GOMODCACHE=/home/portablefs/gomodcache \
    GOTOOLCHAIN=local \
    GOFLAGS=-mod=readonly \
    "PORTABLEFS_XFS_TEST_ROOT=/srv/portablefs/${PORTABLEFS_VOLUME_NAME}" \
    "PORTABLEFS_XFS_TEST_PROJECT=${PORTABLEFS_PROJECT_ID}" \
    PORTABLEFS_CELLHOST_XFS_TEST_ROOT=/srv/portablefs \
    "PORTABLEFS_SERVICE_UID=${PORTABLEFS_SERVICE_UID}" \
    "PORTABLEFS_SERVICE_GID=${PORTABLEFS_SERVICE_GID}" \
    PORTABLEFS_XFS_TEST_CELL=/srv/portablefs \
    PORTABLEFS_FUSE_TEST=1 \
    PORTABLEFS_WORKLOAD_TEST=1 \
    PORTABLEFS_XFS_TEST_REQUIRED=1 \
    "PORTABLEFS_FUSE_DEBUG=${PORTABLEFS_FUSE_DEBUG:-}" \
    "PORTABLEFS_PERFORMANCE_TEST=${PORTABLEFS_PERFORMANCE_TEST:-}" \
    "PORTABLEFS_SOAK_TEST=${PORTABLEFS_SOAK_TEST:-}" \
    "${soak_env[@]}" \
    "${performance_env[@]}" \
    "PORTABLEFS_PROFILE_DIR=${PORTABLEFS_PROFILE_DIR:-}" \
    "PORTABLEFS_PROFILE_RUN=${PORTABLEFS_PROFILE_RUN:-}" \
    go -C /work/vcs test -v -count=1 -failfast -p 1 -timeout 35m \
    "${extra_go_test_flags[@]}" "$@"
}

# The bulk of the privileged suite, with no capability at all. The permission
# assertions in it are only meaningful when DAC actually applies, and the
# production data plane never runs as root; CAP_DAC_READ_SEARCH would be just as
# wrong here, because xfsstore proves the restore binding walk by asserting that
# an archived directory refuses to open for reading.
run_plain_suite() {
  local log=$1
  if [[ ${PORTABLEFS_SOAK_TEST:-} == 1 ]]; then
    local -a soak_command=()
    mapfile -d '' -t soak_command < <(suite_command -failfast=false ./test/soak)
    runuser -u portablefs -- "${soak_command[@]}" >>"$log" 2>&1
    return
  fi
  local -a command=()
  mapfile -d '' -t command < <(suite_command ./internal/fusev3/... ./internal/xfsstore/... ./internal/authorityrpc/... ./internal/restoremode/... ./internal/archiver/... ./internal/hydrator/...)
  runuser -u portablefs -- "${command[@]}" >>"$log" 2>&1
}

# The tiered lifecycle, as the volume identity plus exactly one capability.
#
# The suite archives a tree containing inodes whose modes deny their own owner,
# which is a shape a real workspace produces and the archive format promises to
# carry. Reading them is the archiver's job and the archiver unit is the one
# component in the cell granted CAP_DAC_READ_SEARCH, so the test process that
# stands in for it is granted the same thing and nothing else: capsh keeps the
# capability across the drop to the volume identity, raises it into the ambient
# set so the exec'd `go test` inherits it, and leaves the bounding set to supply
# nothing more. The restore half of the suite is unaffected, which is the whole
# point - CAP_DAC_READ_SEARCH bypasses read and search and never write, so
# hydration into a 0444 or 0000 inode still has to come from a descriptor the
# authority's binding walk opened before it began serving.
#
# Root would have made all of it vacuous, and a capability-gated skip made it
# absent; this is what makes RestrictedModesAreCarried a required test.
run_tiered_suite() {
  local log=$1
  local -a command=()
  mapfile -d '' -t command < <(suite_command ./internal/tierede2e/...)
  capsh --keep=1 --user=portablefs \
    --inh=cap_dac_read_search --addamb=cap_dac_read_search \
    -- -c 'exec "$@"' capsh-suite "${command[@]}" >>"$log" 2>&1
}

run_suite() {
  local log=/home/portablefs/tmp/go-test.log
  local status=0
  : >"$log"
  set +e
  run_plain_suite "$log"
  status=$?
  if [[ $status -ne 0 ]]; then
    cat -- "$log"
    fail "go test exited $status" "$status"
  fi
  if [[ ${PORTABLEFS_SOAK_TEST:-} == 1 ]]; then
    cat -- "$log"
    verify_exact_tests "$log" \
      soak:TestSoakPackageTree soak:TestSoakGit soak:TestSoakCompiler soak:TestSoakChaos \
      soak:TestSoakFaults soak:TestSoakNPM soak:TestSoakGitLock
    echo "xfs-fuse-integration: soak inventory passed; standard privileged suites not selected"
    return
  fi
  run_tiered_suite "$log"
  status=$?
  set -e
  cat -- "$log"
  [[ $status -eq 0 ]] || fail "go test exited $status" "$status"
  verify_required_tests "$log"
}

run_root_boundary_suite() {
  local log=/var/tmp/portablefs-root-boundary.log
  local pattern="" entry package status=0
  local -a packages=()
  validate_root_tests
  for entry in "${REQUIRED_ROOT_TESTS[@]}"; do
    pattern="${pattern:+$pattern|}${entry##*:}"
    package="./${entry%%:*}"
    package="./${package#./github.com/steerlabs/portablefs/vcs/}"
    [[ " ${packages[*]-} " == *" ${package} "* ]] || packages+=("$package")
  done
  # Run as root against the same provisioned XFS cell, retaining the production
  # service UID/GID as the ownership the helper must establish. The
  # shared-domain fixture builds its own loop-backed filesystems with the
  # production provisioner.
  [[ -n $pattern && ${#packages[@]} -gt 0 ]] || fail "the root boundary selector is empty" 70
  set +e
  env -i \
    HOME=/root \
    PATH=/usr/local/go/bin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    TMPDIR=/var/tmp \
    GOCACHE=/var/tmp/portablefs-cellhost-gocache \
    GOMODCACHE=/home/portablefs/gomodcache \
    GOTOOLCHAIN=local \
    GOFLAGS=-mod=readonly \
    PORTABLEFS_CELLHOST_XFS_TEST_ROOT=/srv/portablefs \
    PORTABLEFS_XFS_TEST_ROOT="/srv/portablefs/$PORTABLEFS_VOLUME_NAME" \
    PORTABLEFS_XFS_TEST_PROJECT="$PORTABLEFS_PROJECT_ID" \
    PORTABLEFS_SERVICE_UID="$PORTABLEFS_SERVICE_UID" \
    PORTABLEFS_SERVICE_GID="$PORTABLEFS_SERVICE_GID" \
    PORTABLEFS_XFS_DOMAIN_TEST=1 \
    PORTABLEFS_FUSE_TEST=1 \
    PORTABLEFS_TEST_PROVISIONER=/work/scripts/provision-xfs-volume.sh \
    go -C /work/vcs test -v -count=1 -p 1 -timeout 15m \
    -run "^(${pattern})\$" \
    "${packages[@]}" >"$log" 2>&1
  status=$?
  set -e
  cat -- "$log"
  [[ $status -eq 0 ]] || fail "root boundary tests exited $status" "$status"
  verify_exact_tests "$log" "${REQUIRED_ROOT_TESTS[@]}"
  for entry in "${REQUIRED_ROOT_TESTS[@]}"; do
    if grep -Eq -- "--- SKIP: ${entry##*:}(/| \()" "$log"; then
      fail "required root test skipped a subtest: $entry" 70
    fi
  done
  echo "xfs-fuse-integration: all ${#REQUIRED_ROOT_TESTS[@]} required root boundary tests passed"
}

# go test reports a skipped test as "--- SKIP" and a passing one as "--- PASS".
# Matching the exact package/test pairs catches a renamed, deleted, or silently
# skipped privileged test, which a plain exit code cannot.
verify_required_tests() {
  local log=$1
  verify_exact_tests "$log" "${REQUIRED_TESTS[@]}"
  echo "xfs-fuse-integration: all ${#REQUIRED_TESTS[@]} required privileged tests passed"
}

verify_exact_tests() {
  local log=$1 entry package name missing=0
  shift
  for entry in "$@"; do
    package=${entry%%:*}
    name=${entry##*:}
    if ! grep -Fq -- "--- PASS: ${name} (" "$log"; then
      echo "xfs-fuse-integration: required test did not pass: ${package}.${name}" >&2
      missing=1
    fi
  done
  [[ $missing -eq 0 ]] || fail "required privileged tests did not run to a PASS" 70
}

run_container() {
  [[ $EUID -eq 0 ]] || fail "container side must start as root to provision XFS" 77
  load_required_tests
  validate_root_tests
  install_container_dependencies
  create_service_identity
  provision_fuse_control
  provision_xfs
  provision_volume
  if [[ ${PORTABLEFS_PERFORMANCE_TEST:-} == 1 ]]; then
    provision_neighbor_volume
  fi
  run_suite
  if [[ ${PORTABLEFS_SOAK_TEST:-} != 1 ]]; then
    run_root_boundary_suite
  fi
}

case "${1:-}" in
  --in-container) run_container ;;
  "") run_host ;;
  *) fail "usage: $0 [--in-container]" 64 ;;
esac
