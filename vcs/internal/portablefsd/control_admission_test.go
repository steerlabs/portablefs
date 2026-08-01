package portablefsd

// The control plane is a FRONTEND.
//
// It mutates the same namespace the FSKit and FUSE frontends mutate, through the
// same clientcore entry points, so it must obey the same dispatcher-ordering
// contract. It did not: it took the mount-wide EXCLUSIVE namespace gate
// (frontendSerial.Lock + nsMu.Lock) and then called Volume.Create, Volume.Write
// and Volume.Setattr directly with the raw HTTP context — so the delegation
// transition claim was taken and every operand released with the whole namespace
// locked, and none of it was bounded by the operation deadline.
//
// Two consequences, and the second is the serious one:
//
//   - No 50s bound. A control write held the namespace for as long as the uplink
//     took, and the kernel frontends behind it with it.
//   - An INVERTED lock order. Every frontend request holds the mirrors while its
//     handler runs and the pre-lock classifier holds a transition claim across
//     them; a control write holding the mirrors and WAITING for a claim closes
//     that cycle exactly.

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

// TestControlWriteTakesItsAdmissionBeforeTheNamespaceGate proves both halves at
// once: while the control write's pre-lock admission is running, the exclusive
// namespace gate is free, and the context the mutation runs under carries the
// single operation deadline.
func TestControlWriteTakesItsAdmissionBeforeTheNamespaceGate(t *testing.T) {
	authority := serveAuthority(t)
	vol, err := clientcore.Dial(context.Background(), clientcore.Options{Addr: authority, Pool: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer vol.Close()

	a := newAttach("att-control-admission", "key", ensureAttachRequest{
		VolumeID: "vol-control-admission", Branch: "main",
		MountPath: "/Volumes/ControlAdmission", AuthorityURL: authority,
	}, privateTestDir(t))
	a.vol = vol
	a.testExactKernelRefresh = func(context.Context, uint64) error { return nil }

	// The mutation's own context, captured from inside the locked region.
	var mutationDeadline time.Time
	var haveDeadline bool
	namespaceFreeDuringAdmission := make(chan bool, 1)
	sampled := false
	a.testControlAdmissionProbe = func(ctx context.Context) {
		if sampled {
			return
		}
		sampled = true
		// Admission is running. Nothing may be holding the namespace.
		free := a.frontendSerial.TryLock()
		if free {
			a.frontendSerial.Unlock()
		}
		namespaceFreeDuringAdmission <- free
		mutationDeadline, haveDeadline = ctx.Deadline()
	}

	body := []byte(`{"path":"f.txt","dataBase64":"` +
		base64.StdEncoding.EncodeToString([]byte("control")) + `"}`)
	req := httptest.NewRequest(http.MethodPost, "/fs/write", bytes.NewReader(body))
	recorder := httptest.NewRecorder()
	before := time.Now()
	(&Server{}).controlFSWrite(recorder, req, a)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("control write status=%d body=%q", recorder.Code, recorder.Body.String())
	}

	select {
	case free := <-namespaceFreeDuringAdmission:
		if !free {
			t.Fatal("the control write held the exclusive namespace gate while its " +
				"pre-lock admission ran: the transition claim and the operand " +
				"release are taken with the whole namespace locked, which both " +
				"stalls every frontend request and inverts the global lock order " +
				"(a frontend request holds the mirrors and holds a claim across " +
				"them; this holds the mirrors and waits for one)")
		}
	default:
		t.Fatal("the control write never reached pre-lock admission")
	}
	if !haveDeadline {
		t.Fatal("the control write's mutation ran under the raw HTTP context, " +
			"with no operation deadline: it can hold the exclusive namespace " +
			"gate for as long as the uplink takes")
	}
	if got := mutationDeadline.Sub(before); got > clientcore.OperationAdmissionBudget()+time.Second {
		t.Fatalf("control write deadline is %s out, want at most one "+
			"operationAdmissionBudget (%s)",
			got, clientcore.OperationAdmissionBudget())
	}

	// And it actually wrote.
	data, st, err := vol.Client().Read("f.txt", 0, 64)
	if err != nil || st != fsproto.OK {
		t.Fatalf("verify read st=%d err=%v", st, err)
	}
	if string(data) != "control" {
		t.Fatalf("control write content = %q, want %q", string(data), "control")
	}
}
