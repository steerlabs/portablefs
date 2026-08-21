package authoritypb

import (
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestProtocolV6TransportAndActivationSchema(t *testing.T) {
	if TransportRole_TRANSPORT_ROLE_UNSPECIFIED != 0 || TransportRole_TRANSPORT_ROLE_DATA != 1 || TransportRole_TRANSPORT_ROLE_CONTROL != 2 {
		t.Fatalf("transport roles changed: unspecified=%d data=%d control=%d",
			TransportRole_TRANSPORT_ROLE_UNSPECIFIED, TransportRole_TRANSPORT_ROLE_DATA, TransportRole_TRANSPORT_ROLE_CONTROL)
	}
	if SessionState_SESSION_STATE_UNSPECIFIED != 0 || SessionState_SESSION_STATE_PROVISIONAL != 1 ||
		SessionState_SESSION_STATE_ACTIVE != 2 || SessionState_SESSION_STATE_ABORTED != 3 || SessionState_SESSION_STATE_TERMINAL != 4 {
		t.Fatalf("session states changed: unspecified=%d provisional=%d active=%d aborted=%d terminal=%d",
			SessionState_SESSION_STATE_UNSPECIFIED, SessionState_SESSION_STATE_PROVISIONAL,
			SessionState_SESSION_STATE_ACTIVE, SessionState_SESSION_STATE_ABORTED, SessionState_SESSION_STATE_TERMINAL)
	}

	assertProtocolFields(t, (&HelloRequest{}).ProtoReflect().Descriptor(), map[protoreflect.Name]protoreflect.FieldNumber{
		"role": 3, "connection_set_id": 4, "frontend_profile": 10,
	})
	assertProtocolFields(t, (&HelloReply{}).ProtoReflect().Descriptor(), map[protoreflect.Name]protoreflect.FieldNumber{
		"role": 7, "connection_set_id": 8, "frontend_profile": 10, "max_fskit_write_bytes": 11,
	})
	assertProtocolFields(t, (&AttachRequest{}).ProtoReflect().Descriptor(), map[protoreflect.Name]protoreflect.FieldNumber{
		"attach_attempt_id": 10, "purpose": 11, "frontend_profile": 12,
		"fskit_cached_name_capacity": 13, "fskit_repair_budget_millis": 14, "fskit_namespace_repair": 15,
	})
	assertProtocolFields(t, (&AttachReply{}).ProtoReflect().Descriptor(), map[protoreflect.Name]protoreflect.FieldNumber{
		"session_id": 1, "generation": 2, "resume_secret": 3,
		"provisional_deadline_unix_nanos": 10, "data_binding_generation": 11, "control_binding_generation": 12,
	})
	assertProtocolFields(t, (&ResumeReply{}).ProtoReflect().Descriptor(), map[protoreflect.Name]protoreflect.FieldNumber{
		"role": 1, "binding_generation": 2, "state": 3,
	})
	assertProtocolFields(t, (&ActivateRequest{}).ProtoReflect().Descriptor(), map[protoreflect.Name]protoreflect.FieldNumber{
		"attach_attempt_id": 1, "data_binding_generation": 2, "control_binding_generation": 3,
	})
	assertProtocolFields(t, (&ActivateReply{}).ProtoReflect().Descriptor(), map[protoreflect.Name]protoreflect.FieldNumber{
		"root": 1, "features": 2, "session_lease_milliseconds": 3,
		"routes_revision": 5, "authorization_deadline_unix_nanos": 6, "state": 7,
		"lease_cursor": 8, "purpose": 9, "frontend_profile": 10, "fskit_repair_cursor": 11,
	})
	assertProtocolFields(t, (&AbortAttachRequest{}).ProtoReflect().Descriptor(), map[protoreflect.Name]protoreflect.FieldNumber{
		"attach_attempt_id": 1,
	})
	assertProtocolFields(t, (&AbortAttachReply{}).ProtoReflect().Descriptor(), map[protoreflect.Name]protoreflect.FieldNumber{
		"state": 1,
	})

	attach := (&AttachReply{}).ProtoReflect().Descriptor()
	for number := protoreflect.FieldNumber(4); number <= 9; number++ {
		if !attach.ReservedRanges().Has(number) {
			t.Fatalf("AttachReply field %d is not reserved", number)
		}
	}
	for _, name := range []protoreflect.Name{"root", "features", "session_lease_milliseconds", "visibility_cursor", "routes_revision", "authorization_deadline_unix_nanos"} {
		if !attach.ReservedNames().Has(name) {
			t.Fatalf("AttachReply name %q is not reserved", name)
		}
		if attach.Fields().ByName(name) != nil {
			t.Fatalf("active field %q remained on provisional AttachReply", name)
		}
	}

	assertProtocolFields(t, (&Request{}).ProtoReflect().Descriptor(), map[protoreflect.Name]protoreflect.FieldNumber{
		"activate": 52, "abort_attach": 53,
	})
	assertProtocolFields(t, (&Response{}).ProtoReflect().Descriptor(), map[protoreflect.Name]protoreflect.FieldNumber{
		"resume": 12, "activate": 13, "abort_attach": 14,
	})
}

func assertProtocolFields(t *testing.T, message protoreflect.MessageDescriptor, fields map[protoreflect.Name]protoreflect.FieldNumber) {
	t.Helper()
	for name, number := range fields {
		field := message.Fields().ByName(name)
		if field == nil || field.Number() != number {
			got := protoreflect.FieldNumber(0)
			if field != nil {
				got = field.Number()
			}
			t.Fatalf("%s.%s field = %d, want %d", message.FullName(), name, got, number)
		}
	}
}
