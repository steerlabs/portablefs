package authorityrpc

import (
	"fmt"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Protobuf's byte-size bound is not a decoded-memory bound. In particular, a
// small wire stream can contain thousands of empty repeated strings or packed
// scalar values whose Go representation is many times larger. Validate the
// exact schema and cardinality before Unmarshal allocates any of those values.
// Outbound messages pass through the same validator, so this is one protocol
// grammar rather than a receiver-only filter.
const (
	maxWireMessageDepth     = 16
	maxWireDescriptorFields = 64
	// A maximal legal ReadDirReply may contain 4,096 Dirent messages, each
	// carrying both an Item and two fully populated Attr messages. That is about
	// 140K scalar/message fields. Repeated allocations are bounded separately
	// below; these tree-wide ceilings bound parser work and packed values without
	// rejecting that largest legal response.
	maxWireFieldOccurrences = 262144
	maxWireLogicalElements  = 262144
	maxWireRepeatedElements = 4096
	maxWireFeatureElements  = 64
	maxWireSourceTargets    = 16
)

type wireValidationState struct {
	fieldOccurrences uint32
	logicalElements  uint32
}

func validateWireMessage(raw []byte, descriptor protoreflect.MessageDescriptor) error {
	if descriptor == nil {
		return fmt.Errorf("%w: message has no descriptor", ErrFrameEncoding)
	}
	state := wireValidationState{}
	if err := validateWireMessageDepth(raw, descriptor, 0, &state); err != nil {
		return fmt.Errorf("%w: %v", ErrFrameEncoding, err)
	}
	return nil
}

func validateWireMessageDepth(raw []byte, descriptor protoreflect.MessageDescriptor, depth int, state *wireValidationState) error {
	if depth >= maxWireMessageDepth {
		return fmt.Errorf("message nesting exceeds %d", maxWireMessageDepth)
	}
	fields := descriptor.Fields()
	if fields.Len() > maxWireDescriptorFields || descriptor.Oneofs().Len() > maxWireDescriptorFields {
		return fmt.Errorf("schema exceeds validator bounds")
	}
	var occurrences [maxWireDescriptorFields]uint32
	var oneofs [maxWireDescriptorFields]bool
	for len(raw) != 0 {
		number, wireType, tagBytes := protowire.ConsumeTag(raw)
		if tagBytes < 0 {
			return protowire.ParseError(tagBytes)
		}
		raw = raw[tagBytes:]
		field := fields.ByNumber(number)
		if field == nil {
			return fmt.Errorf("%s contains unknown field %d", descriptor.FullName(), number)
		}
		index := field.Index()
		if index < 0 || index >= len(occurrences) {
			return fmt.Errorf("field %s has an invalid descriptor index", field.FullName())
		}
		state.fieldOccurrences++
		if state.fieldOccurrences > maxWireFieldOccurrences {
			return fmt.Errorf("message tree contains more than %d encoded fields", maxWireFieldOccurrences)
		}
		occurrences[index]++
		if !field.IsList() && occurrences[index] != 1 {
			return fmt.Errorf("singular field %s occurs more than once", field.FullName())
		}
		if oneof := field.ContainingOneof(); oneof != nil {
			oneofIndex := oneof.Index()
			if oneofIndex < 0 || oneofIndex >= len(oneofs) {
				return fmt.Errorf("oneof %s has an invalid descriptor index", oneof.FullName())
			}
			if oneofs[oneofIndex] {
				return fmt.Errorf("oneof %s contains more than one encoded value", oneof.FullName())
			}
			oneofs[oneofIndex] = true
		}

		valueBytes, logicalElements, err := consumeWireField(raw, field, wireType, depth, state)
		if err != nil {
			return err
		}
		raw = raw[valueBytes:]
		if logicalElements > maxWireLogicalElements-state.logicalElements {
			return fmt.Errorf("message tree contains more than %d logical elements", maxWireLogicalElements)
		}
		state.logicalElements += logicalElements
		if field.IsList() {
			limit := uint32(maxWireRepeatedElements)
			if field.Name() == "features" && (descriptor.FullName() == "portablefs.authority.v1.HelloRequest" ||
				descriptor.FullName() == "portablefs.authority.v1.HelloReply" ||
				descriptor.FullName() == "portablefs.authority.v1.AttachReply") {
				limit = maxWireFeatureElements
			} else if field.Name() == "targets" && descriptor.FullName() == "portablefs.authority.v1.SourcePublicationGate" {
				limit = maxWireSourceTargets
			}
			// occurrences includes this encoded field once. Replace that one
			// occurrence with the number of logical values it carries (one for
			// unpacked fields, potentially many for a packed scalar field).
			priorElements := occurrences[index] - 1
			if priorElements > limit || logicalElements > limit-priorElements {
				return fmt.Errorf("repeated field %s exceeds %d elements", field.FullName(), limit)
			}
			occurrences[index] = priorElements + logicalElements
		}
	}
	return nil
}

func consumeWireField(raw []byte, field protoreflect.FieldDescriptor, wireType protowire.Type, depth int, state *wireValidationState) (consumed int, logicalElements uint32, err error) {
	natural, packable, err := wireTypeForKind(field.Kind())
	if err != nil {
		return 0, 0, err
	}
	if field.IsMap() {
		return 0, 0, fmt.Errorf("map field %s is not part of the authority protocol", field.FullName())
	}
	if field.IsList() && packable && wireType == protowire.BytesType {
		packed, n := protowire.ConsumeBytes(raw)
		if n < 0 {
			return 0, 0, protowire.ParseError(n)
		}
		count, countErr := countPackedValues(packed, natural)
		return n, count, countErr
	}
	if wireType != natural {
		return 0, 0, fmt.Errorf("field %s has wire type %d, want %d", field.FullName(), wireType, natural)
	}
	if wireType == protowire.BytesType {
		value, n := protowire.ConsumeBytes(raw)
		if n < 0 {
			return 0, 0, protowire.ParseError(n)
		}
		if field.Kind() == protoreflect.MessageKind {
			if err := validateWireMessageDepth(value, field.Message(), depth+1, state); err != nil {
				return 0, 0, err
			}
		}
		return n, 1, nil
	}
	n := protowire.ConsumeFieldValue(field.Number(), wireType, raw)
	if n < 0 {
		return 0, 0, protowire.ParseError(n)
	}
	return n, 1, nil
}

func wireTypeForKind(kind protoreflect.Kind) (protowire.Type, bool, error) {
	switch kind {
	case protoreflect.BoolKind, protoreflect.EnumKind,
		protoreflect.Int32Kind, protoreflect.Int64Kind,
		protoreflect.Uint32Kind, protoreflect.Uint64Kind,
		protoreflect.Sint32Kind, protoreflect.Sint64Kind:
		return protowire.VarintType, true, nil
	case protoreflect.Fixed32Kind, protoreflect.Sfixed32Kind, protoreflect.FloatKind:
		return protowire.Fixed32Type, true, nil
	case protoreflect.Fixed64Kind, protoreflect.Sfixed64Kind, protoreflect.DoubleKind:
		return protowire.Fixed64Type, true, nil
	case protoreflect.StringKind, protoreflect.BytesKind, protoreflect.MessageKind:
		return protowire.BytesType, false, nil
	default:
		return 0, false, fmt.Errorf("unsupported protobuf kind %s", kind)
	}
}

func countPackedValues(raw []byte, wireType protowire.Type) (uint32, error) {
	var count uint32
	for len(raw) != 0 {
		var n int
		switch wireType {
		case protowire.VarintType:
			_, n = protowire.ConsumeVarint(raw)
		case protowire.Fixed32Type:
			_, n = protowire.ConsumeFixed32(raw)
		case protowire.Fixed64Type:
			_, n = protowire.ConsumeFixed64(raw)
		default:
			return 0, fmt.Errorf("wire type %d cannot be packed", wireType)
		}
		if n < 0 {
			return 0, protowire.ParseError(n)
		}
		raw = raw[n:]
		count++
		if count > maxWireRepeatedElements {
			return 0, fmt.Errorf("packed field exceeds %d elements", maxWireRepeatedElements)
		}
	}
	return count, nil
}
