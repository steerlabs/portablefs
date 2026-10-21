package main

import (
	"google.golang.org/protobuf/types/descriptorpb"
	"testing"
)

func TestGeneratorRejectsUnsupportedTypes(t *testing.T) {
	for _, kind := range []descriptorpb.FieldDescriptorProto_Type{descriptorpb.FieldDescriptorProto_TYPE_INT64, descriptorpb.FieldDescriptorProto_TYPE_FIXED32, descriptorpb.FieldDescriptorProto_TYPE_ENUM, descriptorpb.FieldDescriptorProto_TYPE_GROUP} {
		t.Run(kind.String(), func(t *testing.T) {
			if _, err := fieldKind(&descriptorpb.FieldDescriptorProto{Type: &kind}); err == nil {
				t.Fatal("unsupported type mapped to bytes")
			}
		})
	}
}
