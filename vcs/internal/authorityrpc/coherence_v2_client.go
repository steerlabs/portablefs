package authorityrpc

import (
	"bytes"
	"context"
	"errors"
	"math"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"google.golang.org/protobuf/proto"
)

const (
	maximumSubscriptionHorizon = 10 * time.Second
	maximumDelegationBudget    = 5 * time.Second
	coherenceIdentityBytes     = 16
)

// ErrSubscriptionReset requires cold withdrawal before a new incarnation.
var ErrSubscriptionReset = errors.New("authorityrpc: uncertain control result requires cold subscription")

// Subscribe starts a cold volume subscription when snapshotID and
// afterIdentity are empty, or fetches the next page of the frozen delegated
// identity set when both are present. The returned deadline is anchored at the
// local request start. Callers must therefore treat it as a conservative cache
// horizon even when the response spent time in transit.
func (c *Client) Subscribe(ctx context.Context, snapshotID, afterIdentity []byte) (*authoritypb.SubscribeReply, time.Time, error) {
	if !c.linuxSubscriptionProfile() {
		return nil, time.Time{}, syscall.EOPNOTSUPP
	}
	if (len(snapshotID) == 0) != (len(afterIdentity) == 0) {
		return nil, time.Time{}, syscall.EINVAL
	}
	if len(snapshotID) != 0 && (!validCoherenceIdentity(snapshotID) || !validCoherenceIdentity(afterIdentity)) {
		return nil, time.Time{}, syscall.EINVAL
	}
	started := time.Now()
	response, err := c.CallIdempotent(ctx, &authoritypb.Request{Body: &authoritypb.Request_Subscribe{
		Subscribe: &authoritypb.SubscribeRequest{
			SnapshotId:    append([]byte(nil), snapshotID...),
			AfterIdentity: append([]byte(nil), afterIdentity...),
		},
	}})
	if err != nil {
		return nil, time.Time{}, err
	}
	if err := successfulControlResponse(response); err != nil {
		return nil, time.Time{}, err
	}
	reply := response.GetSubscribe()
	if err := validateSubscribeReply(reply); err != nil {
		return nil, time.Time{}, err
	}
	deadline := started.Add(time.Duration(reply.GetHorizonNanos()))
	c.subscriptionMu.Lock()
	if len(snapshotID) == 0 {
		c.subscriptionSnapshot = append(c.subscriptionSnapshot[:0], reply.GetSnapshotId()...)
		c.subscriptionWatermark = reply.GetWatermark()
		c.subscriptionIncarnation = reply.GetIncarnation()
		c.subscriptionHorizonNanos = reply.GetHorizonNanos()
		c.subscriptionDeadline = deadline
	} else if !bytes.Equal(snapshotID, reply.GetSnapshotId()) ||
		!bytes.Equal(snapshotID, c.subscriptionSnapshot) ||
		reply.GetWatermark() != c.subscriptionWatermark ||
		reply.GetIncarnation() != c.subscriptionIncarnation ||
		reply.GetHorizonNanos() != c.subscriptionHorizonNanos ||
		c.subscriptionDeadline.IsZero() {
		c.subscriptionMu.Unlock()
		return nil, time.Time{}, errors.New("authorityrpc: subscribe pagination changed frozen snapshot metadata")
	} else {
		deadline = c.subscriptionDeadline
	}
	c.subscriptionMu.Unlock()
	return proto.Clone(reply).(*authoritypb.SubscribeReply), deadline, nil
}

// RenewSubscription refreshes one exact incarnation. A late reply cannot
// revive an expired subscription because the deadline is measured from the
// request start rather than response receipt.
func (c *Client) RenewSubscription(ctx context.Context, incarnation uint64) (time.Time, error) {
	if incarnation != 0 && incarnation == c.releaseInvalidIncarnation.Load() {
		return time.Time{}, ErrSubscriptionReset
	}
	if !c.linuxSubscriptionProfile() {
		return time.Time{}, syscall.EOPNOTSUPP
	}
	if incarnation == 0 {
		return time.Time{}, syscall.EINVAL
	}
	started := time.Now()
	response, err := c.CallIdempotent(ctx, &authoritypb.Request{Body: &authoritypb.Request_RenewSubscription{
		RenewSubscription: &authoritypb.RenewSubscriptionRequest{Incarnation: incarnation},
	}})
	if err != nil {
		return time.Time{}, err
	}
	if err := successfulControlResponse(response); err != nil {
		return time.Time{}, err
	}
	reply := response.GetRenewSubscription()
	if reply == nil || reply.GetIncarnation() != incarnation || !validHorizon(reply.GetHorizonNanos()) {
		return time.Time{}, errors.New("authorityrpc: subscription renewal returned a malformed result")
	}
	return started.Add(time.Duration(reply.GetHorizonNanos())), nil
}

// NextControlEvent long-polls for exactly the successor of afterSequence.
// Client admission allows only one such poll at a time, while renewal and
// acknowledgment requests retain independent CONTROL capacity.
func (c *Client) NextControlEvent(ctx context.Context, incarnation, afterSequence, completedThrough uint64) (*authoritypb.ControlEvent, error) {
	if incarnation != 0 && incarnation == c.releaseInvalidIncarnation.Load() {
		return nil, ErrSubscriptionReset
	}
	if !c.linuxSubscriptionProfile() {
		return nil, syscall.EOPNOTSUPP
	}
	if incarnation == 0 || afterSequence == math.MaxUint64 {
		return nil, syscall.EINVAL
	}
	response, err := c.CallIdempotent(ctx, &authoritypb.Request{Body: &authoritypb.Request_NextControlEvent{
		NextControlEvent: &authoritypb.NextControlEventRequest{Incarnation: incarnation, AfterSequence: afterSequence, CompletedEventThrough: completedThrough},
	}})
	if err != nil {
		return nil, err
	}
	if err := successfulControlResponse(response); err != nil {
		return nil, err
	}
	event := response.GetControlEvent()
	if err := validateControlEvent(event, incarnation, afterSequence+1); err != nil {
		return nil, err
	}
	return proto.Clone(event).(*authoritypb.ControlEvent), nil
}

// AcknowledgeChanges advances the cumulative withdrawn change prefix. Position
// zero is a legal no-op acknowledgment; incarnation zero is never valid.
func (c *Client) AcknowledgeChanges(ctx context.Context, incarnation, position uint64) error {
	if !c.linuxSubscriptionProfile() {
		return syscall.EOPNOTSUPP
	}
	if incarnation == 0 {
		return syscall.EINVAL
	}
	response, err := c.CallIdempotent(ctx, &authoritypb.Request{Body: &authoritypb.Request_ChangeAck{
		ChangeAck: &authoritypb.ChangeAck{Position: position, Incarnation: incarnation},
	}})
	if err != nil {
		return err
	}
	if err := successfulControlResponse(response); err != nil {
		return err
	}
	if response.GetChangeAck() == nil {
		return errors.New("authorityrpc: change acknowledgment returned no result")
	}
	return nil
}

func (c *Client) AcknowledgeDelegationRecall(ctx context.Context, incarnation, eventSequence uint64, delegation *authoritypb.DelegationRef, appliedSequence uint64) error {
	if err := c.validateDelegationAck(incarnation, eventSequence, delegation); err != nil {
		return err
	}
	response, err := c.CallIdempotent(ctx, &authoritypb.Request{Body: &authoritypb.Request_DelegationRecallAck{
		DelegationRecallAck: &authoritypb.DelegationRecallAck{
			Incarnation: incarnation, EventSequence: eventSequence,
			Delegation: cloneDelegationRef(delegation), AppliedSequence: appliedSequence,
		},
	}})
	if err != nil {
		return err
	}
	if err := successfulControlResponse(response); err != nil {
		return err
	}
	if response.GetDelegationRecallAck() == nil {
		return errors.New("authorityrpc: delegation recall acknowledgment returned no result")
	}
	return nil
}

func (c *Client) AcknowledgeDelegationBreak(ctx context.Context, incarnation, eventSequence uint64, delegation *authoritypb.DelegationRef, appliedSequence uint64) error {
	if err := c.validateDelegationAck(incarnation, eventSequence, delegation); err != nil {
		return err
	}
	response, err := c.CallIdempotent(ctx, &authoritypb.Request{Body: &authoritypb.Request_DelegationBreakAck{
		DelegationBreakAck: &authoritypb.DelegationBreakAck{
			Incarnation: incarnation, EventSequence: eventSequence,
			Delegation: cloneDelegationRef(delegation), AppliedSequence: appliedSequence,
		},
	}})
	if err != nil {
		return err
	}
	if err := successfulControlResponse(response); err != nil {
		return err
	}
	if response.GetDelegationBreakAck() == nil {
		return errors.New("authorityrpc: delegation break acknowledgment returned no result")
	}
	return nil
}

func (c *Client) AcknowledgeDelegationModeChange(ctx context.Context, incarnation, eventSequence uint64, delegation *authoritypb.DelegationRef, appliedSequence uint64) error {
	if err := c.validateDelegationAck(incarnation, eventSequence, delegation); err != nil {
		return err
	}
	response, err := c.CallIdempotent(ctx, &authoritypb.Request{Body: &authoritypb.Request_DelegationModeChangeAck{
		DelegationModeChangeAck: &authoritypb.DelegationModeChangeAck{
			Incarnation: incarnation, EventSequence: eventSequence,
			Delegation: cloneDelegationRef(delegation), AppliedSequence: appliedSequence,
		},
	}})
	if err != nil {
		return err
	}
	if err := successfulControlResponse(response); err != nil {
		return err
	}
	if response.GetDelegationModeChangeAck() == nil {
		return errors.New("authorityrpc: delegation mode-change acknowledgment returned no result")
	}
	return nil
}

// ReleaseDelegations sends an all-or-error sorted batch after the caller has
// stopped admission and flushed each identity's cut.
func (c *Client) ReleaseDelegations(ctx context.Context, incarnation uint64, releases []*authoritypb.DelegationRelease) error {
	if !c.linuxSubscriptionProfile() {
		return syscall.EOPNOTSUPP
	}
	if incarnation == 0 || len(releases) == 0 || len(releases) > maxWireRepeatedElements {
		return syscall.EINVAL
	}
	cloned := make([]*authoritypb.DelegationRelease, len(releases))
	var previous []byte
	for index, release := range releases {
		if release == nil || !validDelegationRef(release.GetDelegation()) {
			return syscall.EINVAL
		}
		id := release.GetDelegation().GetId()
		if index != 0 && bytes.Compare(previous, id) >= 0 {
			return syscall.EINVAL
		}
		previous = id
		cloned[index] = proto.Clone(release).(*authoritypb.DelegationRelease)
	}
	response, err := c.CallIdempotent(ctx, &authoritypb.Request{Body: &authoritypb.Request_DelegationRelease{
		DelegationRelease: &authoritypb.DelegationReleaseRequest{Incarnation: incarnation, Delegations: cloned},
	}})
	if err != nil {
		return err
	}
	if err := successfulControlResponse(response); err != nil {
		return err
	}
	if response.GetDelegationRelease() == nil {
		return errors.New("authorityrpc: delegation release returned no result")
	}
	return nil
}

// Barrier durably covers the already-applied session ticket cut. Barrier is a
// replay-retained DATA mutation, even though its result contains no filesystem
// object, so a transport repair cannot duplicate or lose its exact outcome.
func (c *Client) Barrier(ctx context.Context, cutSequence uint64) (*authoritypb.BarrierReply, error) {
	if !c.linuxSubscriptionProfile() {
		return nil, syscall.EOPNOTSUPP
	}
	response, err := c.CallMutation(ctx, &authoritypb.Request{Body: &authoritypb.Request_Barrier{
		Barrier: &authoritypb.BarrierRequest{CutSequence: cutSequence},
	}})
	if err != nil {
		return nil, err
	}
	if response == nil {
		return nil, errors.New("authorityrpc: barrier returned no response")
	}
	if response.GetErrno() != 0 {
		return nil, syscall.Errno(response.GetErrno())
	}
	reply := response.GetBarrier()
	if reply == nil || reply.GetAppliedSequence() < reply.GetDurableSequence() ||
		reply.GetDurableSequence() < cutSequence {
		return nil, errors.New("authorityrpc: barrier returned an invalid sequence proof")
	}
	return proto.Clone(reply).(*authoritypb.BarrierReply), nil
}

// WaitVisibility joins peer withdrawal through an already-issued application
// ticket. It performs no durability operation and is safe to retry.
func (c *Client) WaitVisibility(ctx context.Context, cutSequence uint64) (*authoritypb.WaitVisibilityReply, error) {
	if !c.linuxSubscriptionProfile() {
		return nil, syscall.EOPNOTSUPP
	}
	if cutSequence == 0 {
		return nil, syscall.EINVAL
	}
	response, err := c.CallIdempotent(ctx, &authoritypb.Request{Body: &authoritypb.Request_WaitVisibility{
		WaitVisibility: &authoritypb.WaitVisibilityRequest{CutSequence: cutSequence},
	}})
	if err != nil {
		return nil, err
	}
	if err := successfulControlResponse(response); err != nil {
		return nil, err
	}
	reply := response.GetWaitVisibility()
	if reply == nil || reply.GetAppliedSequence() < reply.GetVisibleSequence() || reply.GetVisibleSequence() < cutSequence || response.GetVisibleSequence() != reply.GetVisibleSequence() {
		return nil, errors.New("authorityrpc: visibility wait returned an invalid sequence proof")
	}
	return proto.Clone(reply).(*authoritypb.WaitVisibilityReply), nil
}

func (c *Client) linuxSubscriptionProfile() bool {
	return c != nil && c.cfg.FrontendProfile == authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX_LEASES
}

func (c *Client) validateDelegationAck(incarnation, eventSequence uint64, delegation *authoritypb.DelegationRef) error {
	if !c.linuxSubscriptionProfile() {
		return syscall.EOPNOTSUPP
	}
	if incarnation == 0 || eventSequence == 0 || !validDelegationRef(delegation) {
		return syscall.EINVAL
	}
	return nil
}

func successfulControlResponse(response *authoritypb.Response) error {
	if response == nil {
		return errors.New("authorityrpc: control request returned no response")
	}
	if response.GetErrno() != 0 {
		return syscall.Errno(response.GetErrno())
	}
	if response.GetUncertain() {
		return ErrTransportUncertain
	}
	return nil
}

func validateSubscribeReply(reply *authoritypb.SubscribeReply) error {
	if reply == nil || reply.GetIncarnation() == 0 || !validHorizon(reply.GetHorizonNanos()) ||
		!validCoherenceIdentity(reply.GetSnapshotId()) || len(reply.GetDelegatedIdentities()) > maxWireRepeatedElements {
		return errors.New("authorityrpc: subscribe returned malformed snapshot metadata")
	}
	var previous []byte
	for index, identity := range reply.GetDelegatedIdentities() {
		if !validCoherenceIdentity(identity) || (index != 0 && bytes.Compare(previous, identity) >= 0) {
			return errors.New("authorityrpc: subscribe returned unsorted or malformed delegated identities")
		}
		previous = identity
	}
	next := reply.GetNextAfterIdentity()
	if len(next) != 0 && (len(previous) == 0 || !bytes.Equal(next, previous)) {
		return errors.New("authorityrpc: subscribe returned an invalid pagination cursor")
	}
	return nil
}

func validateControlEvent(event *authoritypb.ControlEvent, incarnation, sequence uint64) error {
	if event == nil || event.GetIncarnation() != incarnation || event.GetSequence() != sequence {
		return errors.New("authorityrpc: control poll returned a non-successor event")
	}
	switch body := event.GetEvent().(type) {
	case *authoritypb.ControlEvent_ChangeBatch:
		return validateChangeBatch(body.ChangeBatch, incarnation)
	case *authoritypb.ControlEvent_DelegationRecall:
		return validateDelegationControl(body.DelegationRecall.GetDelegation(), body.DelegationRecall.GetIdentity(), body.DelegationRecall.GetBudgetNanos(), authoritypb.DelegationMode_DELEGATION_MODE_UNSPECIFIED)
	case *authoritypb.ControlEvent_DelegationBreak:
		return validateDelegationControl(body.DelegationBreak.GetDelegation(), body.DelegationBreak.GetIdentity(), body.DelegationBreak.GetBudgetNanos(), authoritypb.DelegationMode_DELEGATION_MODE_UNSPECIFIED)
	case *authoritypb.ControlEvent_DelegationModeChange:
		mode := body.DelegationModeChange.GetMode()
		if mode != authoritypb.DelegationMode_DELEGATION_MODE_FULL &&
			mode != authoritypb.DelegationMode_DELEGATION_MODE_WRITETHROUGH {
			return errors.New("authorityrpc: delegation mode-change target is invalid")
		}
		return validateDelegationControl(body.DelegationModeChange.GetDelegation(), body.DelegationModeChange.GetIdentity(), body.DelegationModeChange.GetBudgetNanos(), mode)
	default:
		return errors.New("authorityrpc: control poll returned no event body")
	}
}

func validateChangeBatch(batch *authoritypb.ChangeBatch, incarnation uint64) error {
	if batch == nil || batch.GetIncarnation() != incarnation || len(batch.GetEntries()) == 0 ||
		len(batch.GetEntries()) > maxWireRepeatedElements {
		return errors.New("authorityrpc: control poll returned a malformed change batch")
	}
	var previous uint64
	for index, entry := range batch.GetEntries() {
		if entry == nil || entry.GetPosition() == 0 || (index != 0 && entry.GetPosition() != previous+1) {
			return errors.New("authorityrpc: change batch positions are not contiguous")
		}
		if err := validateChangeEntry(entry); err != nil {
			return err
		}
		previous = entry.GetPosition()
	}
	return nil
}

func validateChangeEntry(entry *authoritypb.ChangeEntry) error {
	identity := entry.GetIdentity()
	parent := entry.GetParentIdentity()
	name := entry.GetName()
	rangeValue := entry.GetByteRange()
	unusedBinding := len(parent) == 0 && len(name) == 0
	switch entry.GetKind() {
	case authoritypb.ChangeKind_CHANGE_KIND_NAMESPACE_CHANGED:
		if len(identity) != 0 || !validCoherenceIdentity(parent) || !validCoherenceName(name) || rangeValue != nil {
			return errors.New("authorityrpc: namespace change has invalid coordinates")
		}
	case authoritypb.ChangeKind_CHANGE_KIND_ATTRIBUTES_CHANGED,
		authoritypb.ChangeKind_CHANGE_KIND_DELEGATION_GRANTED,
		authoritypb.ChangeKind_CHANGE_KIND_DELEGATION_RELEASED,
		authoritypb.ChangeKind_CHANGE_KIND_DIRECTORY_CHANGED:
		if !validCoherenceIdentity(identity) || !unusedBinding || rangeValue != nil {
			return errors.New("authorityrpc: identity change has invalid coordinates")
		}
	case authoritypb.ChangeKind_CHANGE_KIND_DATA_CHANGED:
		if !validCoherenceIdentity(identity) || !unusedBinding {
			return errors.New("authorityrpc: data change has invalid coordinates")
		}
		if rangeValue != nil && (rangeValue.GetLength() == 0 || rangeValue.GetOffset() > math.MaxUint64-rangeValue.GetLength()) {
			return errors.New("authorityrpc: data change has an invalid byte range")
		}
	default:
		return errors.New("authorityrpc: change entry has an unspecified kind")
	}
	return nil
}

func validateDelegationControl(ref *authoritypb.DelegationRef, identity []byte, budget uint64, mode authoritypb.DelegationMode) error {
	if !validDelegationRef(ref) || !validCoherenceIdentity(identity) || budget == 0 || budget > uint64(maximumDelegationBudget) {
		return errors.New("authorityrpc: delegation control event is malformed")
	}
	if mode != authoritypb.DelegationMode_DELEGATION_MODE_UNSPECIFIED &&
		mode != authoritypb.DelegationMode_DELEGATION_MODE_FULL &&
		mode != authoritypb.DelegationMode_DELEGATION_MODE_WRITETHROUGH {
		return errors.New("authorityrpc: delegation mode-change target is invalid")
	}
	return nil
}

func validHorizon(nanos uint64) bool {
	return nanos != 0 && nanos <= uint64(maximumSubscriptionHorizon)
}

func validCoherenceIdentity(identity []byte) bool {
	if len(identity) != coherenceIdentityBytes {
		return false
	}
	var nonzero byte
	for _, value := range identity {
		nonzero |= value
	}
	return nonzero != 0
}

func validCoherenceName(name []byte) bool {
	if len(name) == 0 || len(name) > 255 || bytes.Equal(name, []byte(".")) || bytes.Equal(name, []byte("..")) {
		return false
	}
	return !bytes.ContainsAny(name, "\x00/")
}

func validDelegationRef(ref *authoritypb.DelegationRef) bool {
	return ref != nil && validCoherenceIdentity(ref.GetId()) && ref.GetGeneration() != 0
}

func cloneDelegationRef(ref *authoritypb.DelegationRef) *authoritypb.DelegationRef {
	if ref == nil {
		return nil
	}
	return &authoritypb.DelegationRef{Id: append([]byte(nil), ref.GetId()...), Generation: ref.GetGeneration()}
}
