package portablefsd

import (
	"context"
	"time"
)

// operationAdmissionBudget is the single absolute bound one frontend operation
// runs under. It sits strictly under the two ceilings above it — the FSKit
// operation ceiling (~60s) and the exact unmount transaction's own budget — so
// reaching it is a DEFINITE outcome (the caller's deadline, surfaced as an
// interrupted operation) rather than an unbounded wait.
//
// A var so failure-shape tests can compress it; production never changes it.
var operationAdmissionBudget = 50 * time.Second

// operationAdmissionBudgetValue publishes that bound to the frontend request
// deadline, so the composition is read from one place.
func operationAdmissionBudgetValue() time.Duration { return operationAdmissionBudget }

// withOperationDeadline installs the operation's single absolute deadline on a
// frontend request context, unless the caller already carries an earlier one.
// It is idempotent: a handler that runs it twice does not extend the
// operation's bound.
func withOperationDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	deadline := time.Now().Add(operationAdmissionBudget)
	if existing, ok := ctx.Deadline(); ok && !existing.After(deadline) {
		return ctx, func() {}
	}
	return context.WithDeadline(ctx, deadline)
}
