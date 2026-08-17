package readonlyfs

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
)

const (
	maxNameBytes = 255
	maxPathBytes = 4096
)

// EncodePath turns raw PortableFS name components into the opaque path key
// used by read-only services. The root is the empty key.
func EncodePath(components [][]byte) (string, error) {
	if err := validateComponents(components); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes.Join(components, []byte{0})), nil
}

// DecodePath validates and decodes one opaque path key. Components stay as
// bytes because a Linux filename is not required to be UTF-8.
func DecodePath(key string) ([][]byte, error) {
	if key == "" {
		return nil, nil
	}
	if len(key) > base64.RawURLEncoding.EncodedLen(maxPathBytes) {
		return nil, errors.New("readonlyfs: path key is too long")
	}
	raw, err := base64.RawURLEncoding.DecodeString(key)
	if err != nil {
		return nil, errors.New("readonlyfs: path key is not canonical base64url")
	}
	components := bytes.Split(raw, []byte{0})
	if err := validateComponents(components); err != nil {
		return nil, err
	}
	if encoded, err := EncodePath(components); err != nil || encoded != key {
		return nil, errors.New("readonlyfs: path key is not canonical")
	}
	return components, nil
}

func AppendPath(parent string, name []byte) (string, error) {
	components, err := DecodePath(parent)
	if err != nil {
		return "", err
	}
	components = append(components, append([]byte(nil), name...))
	return EncodePath(components)
}

func validateComponents(components [][]byte) error {
	total := 0
	for _, component := range components {
		if len(component) == 0 || len(component) > maxNameBytes || bytes.IndexByte(component, 0) >= 0 || bytes.IndexByte(component, '/') >= 0 || bytes.Equal(component, []byte(".")) || bytes.Equal(component, []byte("..")) {
			return fmt.Errorf("readonlyfs: invalid path component")
		}
		total += len(component)
		if total > maxPathBytes {
			return errors.New("readonlyfs: path is too long")
		}
	}
	if len(components) > 1 {
		total += len(components) - 1
	}
	if total > maxPathBytes {
		return errors.New("readonlyfs: path is too long")
	}
	return nil
}
