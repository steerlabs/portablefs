// Generate the allocation-bound Swift wire table from protoc's descriptor.
package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) != 7 {
		return fmt.Errorf("usage: generate descriptor schema swift-output go-output go-binding swift-binding")
	}
	raw, err := os.ReadFile(os.Args[1])
	if err != nil {
		return fmt.Errorf("workspace generator: %w", err)
	}
	var set descriptorpb.FileDescriptorSet
	if err = proto.Unmarshal(raw, &set); err != nil {
		return fmt.Errorf("workspace generator: %w", err)
	}
	schema, err := os.ReadFile(os.Args[2])
	if err != nil {
		return fmt.Errorf("workspace generator: %w", err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(schema))
	var b strings.Builder
	fmt.Fprintf(&b, "// Code generated from proto/workspace/v8/control.proto. DO NOT EDIT.\nimport Foundation\n\nenum WorkspaceWireSchema {\n    static let messages: [String: [UInt64: WorkspaceWireField]] = [\n")
	for _, file := range set.File {
		for _, m := range file.MessageType {
			fmt.Fprintf(&b, "        %q: [\n", m.GetName())
			for _, f := range m.Field {
				kind, err := fieldKind(f)
				if err != nil {
					return fmt.Errorf("generate %s.%s: %w", m.GetName(), f.GetName(), err)
				}
				fmt.Fprintf(&b, "            %d: .init(kind: %q, repeated: %t, oneof: %t),\n", f.GetNumber(), kind, f.GetLabel() == descriptorpb.FieldDescriptorProto_LABEL_REPEATED, f.OneofIndex != nil)
			}
			if len(m.Field) == 0 {
				b.WriteString("            :\n")
			}
			b.WriteString("        ],\n")
		}
	}
	b.WriteString("    ]\n}\n")
	if err = os.WriteFile(os.Args[3], []byte(b.String()), 0644); err != nil {
		return fmt.Errorf("workspace generator: %w", err)
	}
	var bindingHashes []string
	for _, path := range []string{os.Args[5], os.Args[6]} {
		raw, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("workspace generator: %w", err)
		}
		bindingHashes = append(bindingHashes, fmt.Sprintf("%x", sha256.Sum256(raw)))
	}
	return os.WriteFile(os.Args[4], fmt.Appendf(nil, "// Code generated from proto/workspace/v8/control.proto. DO NOT EDIT.\npackage workspacecontrol\n\nconst SchemaSHA256 = %q\nconst GoBindingSHA256 = %q\nconst SwiftBindingSHA256 = %q\nconst SwiftWireSchemaSHA256 = %q\n", digest, bindingHashes[0], bindingHashes[1], fmt.Sprintf("%x", sha256.Sum256([]byte(b.String())))), 0644)
}

func fieldKind(f *descriptorpb.FieldDescriptorProto) (string, error) {
	switch f.GetType() {
	case descriptorpb.FieldDescriptorProto_TYPE_MESSAGE:
		parts := strings.Split(f.GetTypeName(), ".")
		return parts[len(parts)-1], nil
	case descriptorpb.FieldDescriptorProto_TYPE_STRING, descriptorpb.FieldDescriptorProto_TYPE_BYTES:
		return "$", nil
	case descriptorpb.FieldDescriptorProto_TYPE_UINT32, descriptorpb.FieldDescriptorProto_TYPE_UINT64, descriptorpb.FieldDescriptorProto_TYPE_BOOL:
		return "", nil
	default:
		return "", fmt.Errorf("unsupported field type %s", f.GetType())
	}
}
