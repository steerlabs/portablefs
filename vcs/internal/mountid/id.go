// Package mountid creates and validates stable random identities persisted
// before mount/attach side effects.
package mountid

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
)

func NewMountInstance() (string, error) { return newID("mnt_") }
func NewAttachRef() (string, error)     { return newID("att_") }

func ValidMountInstance(value string) bool { return valid(value, "mnt_") }
func ValidAttachRef(value string) bool     { return valid(value, "att_") }

func newID(prefix string) (string, error) {
	var entropy [16]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", err
	}
	return prefix + base64.RawURLEncoding.EncodeToString(entropy[:]), nil
}

func valid(value, prefix string) bool {
	if !strings.HasPrefix(value, prefix) || len(value) != len(prefix)+22 {
		return false
	}
	for _, char := range value[len(prefix):] {
		if !(char >= 'a' && char <= 'z') && !(char >= 'A' && char <= 'Z') &&
			!(char >= '0' && char <= '9') && char != '-' && char != '_' {
			return false
		}
	}
	return true
}
