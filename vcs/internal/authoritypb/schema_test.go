package authoritypb

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"encoding/json"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// The baseline is the complete accepted grammar, including every surviving tag,
// enum value, oneof and optional presence bit. No historical declarations enter it.
func TestProtocol8SchemaManifest(t *testing.T) {
	file := File_proto_authority_v1_authority_proto
	var checkMessages func(protoreflect.MessageDescriptors)
	checkMessages = func(messages protoreflect.MessageDescriptors) {
		for i := 0; i < messages.Len(); i++ {
			message := messages.Get(i)
			if message.ReservedNames().Len() != 0 || message.ReservedRanges().Len() != 0 {
				t.Fatalf("%s retains reserved history", message.FullName())
			}
			checkMessages(message.Messages())
		}
	}
	checkMessages(file.Messages())
	for i := 0; i < file.Enums().Len(); i++ {
		enum := file.Enums().Get(i)
		if enum.ReservedNames().Len() != 0 || enum.ReservedRanges().Len() != 0 {
			t.Fatalf("%s retains reserved history", enum.FullName())
		}
	}
	got, err := json.MarshalIndent(protodesc.ToFileDescriptorProto(file), "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join("testdata", "protocol8-schema.json")
	if os.Getenv("UPDATE_SCHEMA") == "1" {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, got, 0644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatal("authority grammar differs from protocol8-schema.json")
	}
	if FrontendProfile_FRONTEND_PROFILE_LINUX != 1 || FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE != 2 || FrontendProfile_FRONTEND_PROFILE_CACHELESS_READER != 3 || len(FrontendProfile_name) != 4 {
		t.Fatal("unexpected frontend profiles")
	}
}
